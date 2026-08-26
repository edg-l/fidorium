use super::TpmError;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::return_code::TpmFormatOneError;
use tss_esapi::handles::KeyHandle;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::structures::Auth;
use tss_esapi::structures::KeyedHashScheme;
use tss_esapi::structures::Private;
use tss_esapi::structures::Public;
use tss_esapi::structures::PublicBuilder;
use tss_esapi::structures::PublicKeyedHashParameters;
use tss_esapi::structures::SensitiveData;
use tss_esapi::traits::Marshall;
use tss_esapi::traits::UnMarshall;

/// Create a sealed object wrapping a random 32-byte key.
/// Returns (private_blob, public_blob, key_plaintext).
pub type SealCreation = (Vec<u8>, Vec<u8>, [u8; 32]);

pub fn create_seal(ctx: &mut Context, primary: KeyHandle) -> Result<SealCreation, TpmError> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    let sensitive =
        SensitiveData::try_from(key.to_vec()).map_err(|e| TpmError::Seal(e.to_string()))?;

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

    let private_bytes = result.out_private.as_bytes().to_vec();
    let public_bytes = result
        .out_public
        .marshall()
        .map_err(|e| TpmError::Seal(e.to_string()))?;

    Ok((private_bytes, public_bytes, key))
}

/// Create a sealed object whose authValue is derived from `passphrase`.
///
/// The sealed payload is deliberately meaningless — the object exists only so
/// that a successful `TPM2_Unseal` proves the caller knows the passphrase. This
/// is what backs the `uv` (user verification) bit we report in GetInfo.
///
/// Dictionary-attack protection is left **enabled** (`no_da` clear, unlike
/// [`create_seal`]) so the TPM rate-limits guessing in hardware. A run of wrong
/// passphrases will eventually trip the TPM's lockout; that is the point.
pub fn create_uv_verifier(
    ctx: &mut Context,
    primary: KeyHandle,
    passphrase: &str,
) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
    let sensitive = SensitiveData::try_from(b"fidorium-uv".to_vec())
        .map_err(|e| TpmError::Seal(e.to_string()))?;

    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
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

    let auth = passphrase_auth(passphrase)?;

    let result = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create(
                primary,
                pub_template,
                Some(auth),
                Some(sensitive),
                None,
                None,
            )
        })
        .map_err(|e: tss_esapi::Error| TpmError::Seal(e.to_string()))?;

    let private_bytes = result.out_private.as_bytes().to_vec();
    let public_bytes = result
        .out_public
        .marshall()
        .map_err(|e| TpmError::Seal(e.to_string()))?;

    Ok((private_bytes, public_bytes))
}

/// Check `passphrase` against a verifier created by [`create_uv_verifier`].
///
/// `Ok(false)` means the passphrase was rejected by the TPM. `Err` means the
/// TPM operation itself failed (including lockout), which the caller should
/// surface rather than report as a simple mismatch.
pub fn verify_passphrase(
    ctx: &mut Context,
    primary: KeyHandle,
    private_bytes: &[u8],
    public_bytes: &[u8],
    passphrase: &str,
) -> Result<bool, TpmError> {
    let private =
        Private::try_from(private_bytes.to_vec()).map_err(|e| TpmError::Seal(e.to_string()))?;
    let public = Public::unmarshall(public_bytes).map_err(|e| TpmError::Seal(e.to_string()))?;

    let handle = ctx
        .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
        .map_err(|e: tss_esapi::Error| TpmError::Seal(e.to_string()))?;

    let auth = passphrase_auth(passphrase)?;
    if let Err(e) = ctx.tr_set_auth(ObjectHandle::from(handle), auth) {
        let _ = ctx.flush_context(ObjectHandle::from(handle));
        return Err(TpmError::Seal(e.to_string()));
    }

    let result = ctx.execute_with_nullauth_session(|ctx| ctx.unseal(ObjectHandle::from(handle)));
    let _ = ctx.flush_context(ObjectHandle::from(handle));

    match result {
        Ok(_) => Ok(true),
        Err(e) if is_auth_failure(&e) => Ok(false),
        Err(e) => Err(TpmError::Seal(e.to_string())),
    }
}

/// TPM auth values are capped at the name-algorithm digest size, so hash the
/// passphrase rather than truncating it and silently weakening long ones.
fn passphrase_auth(passphrase: &str) -> Result<Auth, TpmError> {
    let digest: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
    Auth::try_from(digest.to_vec()).map_err(|e| TpmError::Seal(e.to_string()))
}

/// Distinguish "wrong passphrase" from a genuine TPM failure such as lockout.
///
/// `AuthFail` is a failed auth that increments the dictionary-attack counter;
/// `BadAuth` is a failed auth that does not. Both mean the passphrase was wrong.
/// Anything else — notably `TPM2_RC_LOCKOUT` — is a real error the caller must
/// surface, so it is never silently reported as a mismatch.
fn is_auth_failure(e: &tss_esapi::Error) -> bool {
    use tss_esapi::error::{ReturnCode, TpmResponseCode};

    let code = match e {
        tss_esapi::Error::TssError(code) => code,
        _ => return false,
    };
    // Errors reach us through the resource manager (/dev/tpmrm0) as well as
    // directly from the TPM layer, so accept either.
    let tpm_code = match code {
        ReturnCode::Tpm(c) | ReturnCode::TpmResourceManager(c) => c,
        _ => return false,
    };
    match tpm_code {
        TpmResponseCode::FormatOne(f) => matches!(
            f.error_number(),
            TpmFormatOneError::AuthFail | TpmFormatOneError::BadAuth
        ),
        TpmResponseCode::FormatZero(_) => false,
    }
}

/// Load sealed object and unseal to recover the 32-byte key.
pub fn unseal(
    ctx: &mut Context,
    primary: KeyHandle,
    private_bytes: &[u8],
    public_bytes: &[u8],
) -> Result<[u8; 32], TpmError> {
    let private =
        Private::try_from(private_bytes.to_vec()).map_err(|e| TpmError::Seal(e.to_string()))?;
    let public = Public::unmarshall(public_bytes).map_err(|e| TpmError::Seal(e.to_string()))?;

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

    let bytes = sensitive.as_bytes();
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
