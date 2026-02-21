use std::convert::TryFrom;
use rand::RngCore;
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::structures::KeyedHashScheme;
use tss_esapi::structures::Private;
use tss_esapi::structures::Public;
use tss_esapi::structures::PublicBuilder;
use tss_esapi::structures::PublicKeyedHashParameters;
use tss_esapi::structures::SensitiveData;
use tss_esapi::traits::Marshall;
use tss_esapi::traits::UnMarshall;
use super::TpmError;

/// Create a sealed object wrapping a random 32-byte key.
/// Returns (private_blob, public_blob, key_plaintext).
pub fn create_seal(
    ctx: &mut Context,
    primary: KeyHandle,
) -> Result<(Vec<u8>, Vec<u8>, [u8; 32]), TpmError> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    let sensitive = SensitiveData::try_from(key.to_vec())
        .map_err(|e| TpmError::Seal(e.to_string()))?;

    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .build()
        .map_err(|e| TpmError::Seal(e.to_string()))?;

    let seal_params = PublicKeyedHashParameters::new(KeyedHashScheme::Null);

    let pub_template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_keyed_hash_parameters(seal_params)
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .map_err(|e| TpmError::Seal(e.to_string()))?;

    let result = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create(primary, pub_template, None, Some(sensitive), None, None)
        })
        .map_err(|e: tss_esapi::Error| TpmError::Seal(e.to_string()))?;

    let private_bytes = result.out_private.value().to_vec();
    let public_bytes = result
        .out_public
        .marshall()
        .map_err(|e| TpmError::Seal(e.to_string()))?;

    Ok((private_bytes, public_bytes, key))
}

/// Load sealed object and unseal to recover the 32-byte key.
pub fn unseal(
    ctx: &mut Context,
    primary: KeyHandle,
    private_bytes: &[u8],
    public_bytes: &[u8],
) -> Result<[u8; 32], TpmError> {
    let private = Private::try_from(private_bytes.to_vec())
        .map_err(|e| TpmError::Seal(e.to_string()))?;
    let public = Public::unmarshall(public_bytes)
        .map_err(|e| TpmError::Seal(e.to_string()))?;

    let sealed_handle = ctx
        .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
        .map_err(|e: tss_esapi::Error| TpmError::Seal(e.to_string()))?;

    let sensitive = ctx
        .execute_with_nullauth_session(|ctx| ctx.unseal(ObjectHandle::from(sealed_handle)))
        .map_err(|e: tss_esapi::Error| {
            let _ = ctx.flush_context(ObjectHandle::from(sealed_handle));
            TpmError::Seal(e.to_string())
        })?;

    ctx.flush_context(ObjectHandle::from(sealed_handle))
        .map_err(|e| TpmError::Seal(e.to_string()))?;

    let bytes = sensitive.value();
    if bytes.len() != 32 {
        return Err(TpmError::Seal(format!(
            "expected 32-byte key, got {}",
            bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Ok(key)
}
