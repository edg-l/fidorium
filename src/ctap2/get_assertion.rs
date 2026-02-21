use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use tokio::sync::mpsc;
use sha2::{Sha256, Digest};
use ciborium::value::Value;

use crate::tpm::{self, TpmContext};
use crate::store::CredentialStore;
use super::types::{GetAssertionRequest, Ctap2Error};
use super::authenticator_data::{build_get_assertion_auth_data, encode_der_ecdsa};

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
        let found = if !req.allow_list.is_empty() {
            req.allow_list.iter().find_map(|id| {
                guard.get_by_id(id)
                    .filter(|c| c.rp_id_hash.as_slice() == rp_id_hash.as_slice())
            })
        } else {
            guard.get_by_rp_hash(&rp_id_hash).into_iter().next()
        };
        match found {
            Some(c) => c.clone(),
            None => return Err(Ctap2Error::NoCredentials),
        }
    };

    // User presence
    let prompt = crate::up::get_assertion_prompt(
        &req.rp_id,
        cred.user_display.as_deref(),
    );
    let proof = crate::up::require_user_presence(
        &prompt, pinentry_bin, outgoing_tx, cid, cancel,
    ).await?;
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
    .map_err(|e| Ctap2Error::Tpm(tpm::TpmError::Other(e.to_string())))?
    ?;

    // Build response
    let mut entries = vec![
        (Value::Integer(1i64.into()), Value::Map(vec![
            (Value::Text("type".to_string()), Value::Text("public-key".to_string())),
            (Value::Text("id".to_string()), Value::Bytes(cred_id)),
        ])),
        (Value::Integer(2i64.into()), Value::Bytes(auth_data)),
        (Value::Integer(3i64.into()), Value::Bytes(der_sig)),
    ];

    // Key 0x04: user entity — required by spec for resident/discoverable credentials
    if cred.discoverable {
        let mut user_map = vec![
            (Value::Text("id".to_string()), Value::Bytes(cred.user_id.clone())),
        ];
        if let Some(name) = &cred.user_name {
            user_map.push((Value::Text("name".to_string()), Value::Text(name.clone())));
        }
        if let Some(display) = &cred.user_display {
            user_map.push((Value::Text("displayName".to_string()), Value::Text(display.clone())));
        }
        entries.push((Value::Integer(4i64.into()), Value::Map(user_map)));
    }

    let map = Value::Map(entries);

    let mut buf = vec![0x00u8];
    ciborium::into_writer(&map, &mut buf)
        .map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    Ok(buf)
}
