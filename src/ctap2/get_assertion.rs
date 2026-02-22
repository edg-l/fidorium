use ciborium::value::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use super::authenticator_data::{build_get_assertion_auth_data, encode_der_ecdsa};
use super::types::{Ctap2Error, GetAssertionRequest};
use crate::store::{CredentialRecord, CredentialStore};
use crate::tpm::{self, TpmContext};

fn select_credential(
    store: &CredentialStore,
    rp_id_hash: &[u8; 32],
    allow_list: &[Vec<u8>],
) -> Option<CredentialRecord> {
    let found = if !allow_list.is_empty() {
        allow_list.iter().find_map(|id| {
            store
                .get_by_id(id)
                .filter(|c| c.rp_id_hash.as_slice() == rp_id_hash.as_slice())
        })
    } else {
        store
            .get_by_rp_hash(rp_id_hash)
            .into_iter()
            .find(|c| c.discoverable)
    };

    found.cloned()
}

pub(crate) async fn handle_get_assertion(
    req: GetAssertionRequest,
    tpm: &TpmContext,
    store: &Arc<Mutex<CredentialStore>>,
    nv_index: u32,
    pinentry_bin: &str,
    cid: u32,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<u8>, Ctap2Error> {
    let rp_id_hash: [u8; 32] = Sha256::digest(req.rp_id.as_bytes()).into();

    // Find credential
    let cred = {
        let guard = store.lock().unwrap();
        match select_credential(&guard, &rp_id_hash, &req.allow_list) {
            Some(c) => c,
            None => return Err(Ctap2Error::NoCredentials),
        }
    };

    // User presence
    let prompt = crate::up::get_assertion_prompt(
        &req.rp_id,
        cred.user_display.as_deref(),
        cred.user_name.as_deref(),
    );
    let proof =
        crate::up::require_user_presence(&prompt, pinentry_bin, outgoing_tx, cid, cancel).await?;
    tracing::info!(cid = format!("{cid:#010x}"), "User presence confirmed");

    // TPM operations
    let tpm2 = tpm.clone();
    let rp_id_hash2 = rp_id_hash;
    let cdh2 = req.client_data_hash.clone();
    let key_private = cred.key_private.clone();
    let key_public = cred.key_public.clone();
    let cred_id = cred.credential_id.clone();

    let (auth_data, der_sig) = tokio::task::spawn_blocking(move || {
        tpm2.with_ctx(|ctx, primary| {
            let counter = tpm::counter::increment_and_read(ctx, nv_index)?;
            tracing::info!(count = counter, "Counter incremented");
            let auth_data = build_get_assertion_auth_data(&rp_id_hash2, counter as u32);
            let mut to_sign = auth_data.clone();
            to_sign.extend_from_slice(&cdh2);
            let handle = tpm::keys::load_key(ctx, primary, &key_private, &key_public)?;
            let raw_sig = tpm::keys::sign(ctx, handle, &to_sign, &proof)?;
            tpm::keys::flush(ctx, handle)?;
            let der_sig = encode_der_ecdsa(&raw_sig);
            Ok((auth_data, der_sig))
        })
    })
    .await
    .map_err(|e| Ctap2Error::Tpm(tpm::TpmError::Other(e.to_string())))??;

    // Build response
    let mut entries = vec![
        (
            Value::Integer(1i64.into()),
            Value::Map(vec![
                (
                    Value::Text("type".to_string()),
                    Value::Text("public-key".to_string()),
                ),
                (Value::Text("id".to_string()), Value::Bytes(cred_id)),
            ]),
        ),
        (Value::Integer(2i64.into()), Value::Bytes(auth_data)),
        (Value::Integer(3i64.into()), Value::Bytes(der_sig)),
    ];

    // Key 0x04: user entity — required by spec for resident/discoverable credentials
    if cred.discoverable {
        let mut user_map = vec![(
            Value::Text("id".to_string()),
            Value::Bytes(cred.user_id.clone()),
        )];
        if let Some(name) = &cred.user_name {
            user_map.push((Value::Text("name".to_string()), Value::Text(name.clone())));
        }
        if let Some(display) = &cred.user_display {
            user_map.push((
                Value::Text("displayName".to_string()),
                Value::Text(display.clone()),
            ));
        }
        entries.push((Value::Integer(4i64.into()), Value::Map(user_map)));
    }

    let map = Value::Map(entries);

    let mut buf = vec![0x00u8];
    ciborium::into_writer(&map, &mut buf).map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_record(
        cred_byte: u8,
        rp_hash: [u8; 32],
        discoverable: bool,
        created_at: u64,
    ) -> CredentialRecord {
        CredentialRecord {
            version: 1,
            credential_id: vec![cred_byte; 32],
            rp_id: "example.com".to_string(),
            rp_id_hash: rp_hash.to_vec(),
            rp_name: Some("Example".to_string()),
            user_id: vec![1, 2, 3],
            user_name: Some(format!("user-{cred_byte}")),
            user_display: Some(format!("User {cred_byte}")),
            public_key_x: vec![0u8; 32],
            public_key_y: vec![0u8; 32],
            key_private: vec![0xAA],
            key_public: vec![0xBB],
            created_at,
            discoverable,
        }
    }

    fn make_store() -> (CredentialStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = CredentialStore::load([0u8; 32], tmp.path().to_path_buf()).unwrap();
        (store, tmp)
    }

    #[test]
    fn test_select_credential_skips_non_discoverable_without_allow_list() {
        let rp_hash = [0x11u8; 32];
        let (mut store, _tmp) = make_store();

        // Newer non-discoverable credential should not be returned in discoverable flow.
        store.add(make_record(1, rp_hash, false, 200)).unwrap();
        store.add(make_record(2, rp_hash, true, 100)).unwrap();

        let selected =
            select_credential(&store, &rp_hash, &[]).expect("must select discoverable credential");
        assert_eq!(selected.credential_id, vec![2u8; 32]);
        assert!(selected.discoverable);
    }

    #[test]
    fn test_select_credential_allows_non_discoverable_with_allow_list() {
        let rp_hash = [0x22u8; 32];
        let (mut store, _tmp) = make_store();
        let record = make_record(7, rp_hash, false, 123);
        let cred_id = record.credential_id.clone();
        store.add(record).unwrap();

        let selected = select_credential(&store, &rp_hash, std::slice::from_ref(&cred_id))
            .expect("allowList should match non-discoverable credential");
        assert_eq!(selected.credential_id, cred_id);
        assert!(!selected.discoverable);
    }
}
