use super::TpmError;
use sha2::Digest as ShaDigest;
use sha2::Sha256;
use std::convert::TryFrom;
use std::convert::TryInto;
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::tss::TPM2_RH_NULL;
use tss_esapi::constants::tss::TPM2_ST_HASHCHECK;
use tss_esapi::handles::KeyHandle;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::Digest;
use tss_esapi::structures::EccPoint;
use tss_esapi::structures::EccScheme;
use tss_esapi::structures::HashScheme;
use tss_esapi::structures::HashcheckTicket;
use tss_esapi::structures::Private;
use tss_esapi::structures::Public;
use tss_esapi::structures::PublicBuilder;
use tss_esapi::structures::PublicEccParametersBuilder;
use tss_esapi::structures::Signature;
use tss_esapi::structures::SignatureScheme;
use tss_esapi::structures::SymmetricDefinitionObject;
use tss_esapi::traits::Marshall;
use tss_esapi::traits::UnMarshall;
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;

pub fn create_primary(ctx: &mut Context) -> Result<KeyHandle, TpmError> {
    let ecc_params = PublicEccParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        EccCurve::NistP256,
    )
    .build()
    .map_err(|e| TpmError::Key(e.to_string()))?;

    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| TpmError::Key(e.to_string()))?;

    let pub_template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| TpmError::Key(e.to_string()))?;

    let result = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, pub_template, None, None, None, None)
        })
        .map_err(|e: tss_esapi::Error| TpmError::Key(e.to_string()))?;

    Ok(result.key_handle)
}

pub fn create_child_key(
    ctx: &mut Context,
    primary: KeyHandle,
) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
    let scheme = EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256));
    let ecc_params =
        PublicEccParametersBuilder::new_unrestricted_signing_key(scheme, EccCurve::NistP256)
            .build()
            .map_err(|e| TpmError::Key(e.to_string()))?;

    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_no_da(true)
        .build()
        .map_err(|e| TpmError::Key(e.to_string()))?;

    let pub_template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| TpmError::Key(e.to_string()))?;

    let result = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create(primary, pub_template, None, None, None, None)
        })
        .map_err(|e: tss_esapi::Error| TpmError::Key(e.to_string()))?;

    let private_bytes = result.out_private.as_bytes().to_vec();
    let public_bytes = result
        .out_public
        .marshall()
        .map_err(|e| TpmError::Key(e.to_string()))?;

    Ok((private_bytes, public_bytes))
}

pub fn load_key(
    ctx: &mut Context,
    primary: KeyHandle,
    private_bytes: &[u8],
    public_bytes: &[u8],
) -> Result<KeyHandle, TpmError> {
    let private =
        Private::try_from(private_bytes.to_vec()).map_err(|e| TpmError::Key(e.to_string()))?;
    let public = Public::unmarshall(public_bytes).map_err(|e| TpmError::Key(e.to_string()))?;

    ctx.execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
        .map_err(|e: tss_esapi::Error| TpmError::Key(e.to_string()))
}

/// Sign `data` with the loaded key.
/// Returns raw (r, s) concatenated — 64 bytes, each component zero-padded to 32 bytes.
/// The `_up` parameter is a user presence proof token, ensuring this function
/// is only callable after user presence has been confirmed.
pub fn sign(
    ctx: &mut Context,
    key: KeyHandle,
    data: &[u8],
    _up: &crate::up::UserPresenceProof,
) -> Result<[u8; 64], TpmError> {
    let hash_bytes: [u8; 32] = Sha256::digest(data).into();
    let digest = Digest::try_from(hash_bytes.to_vec()).map_err(|e| TpmError::Key(e.to_string()))?;

    let raw_ticket = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    };
    let validation: HashcheckTicket = raw_ticket
        .try_into()
        .map_err(|e: tss_esapi::Error| TpmError::Key(e.to_string()))?;

    let scheme = SignatureScheme::Null;

    let signature = ctx
        .execute_with_nullauth_session(|ctx| ctx.sign(key, digest, scheme, validation))
        .map_err(|e: tss_esapi::Error| TpmError::Key(e.to_string()))?;

    match signature {
        Signature::EcDsa(ecc_sig) => {
            let r = ecc_sig.signature_r().as_bytes();
            let s = ecc_sig.signature_s().as_bytes();
            let mut result = [0u8; 64];
            let r_len = r.len().min(32);
            let s_len = s.len().min(32);
            result[32 - r_len..32].copy_from_slice(&r[r.len() - r_len..]);
            result[64 - s_len..].copy_from_slice(&s[s.len() - s_len..]);
            Ok(result)
        }
        _ => Err(TpmError::Key("Expected ECDSA signature".into())),
    }
}

pub fn flush(ctx: &mut Context, handle: KeyHandle) -> Result<(), TpmError> {
    ctx.flush_context(ObjectHandle::from(handle))
        .map_err(|e| TpmError::Key(e.to_string()))
}

/// Extract (x, y) coordinates from a marshalled TPM2B_PUBLIC blob.
pub fn ecc_public_coords(public_bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), TpmError> {
    let public = Public::unmarshall(public_bytes).map_err(|e| TpmError::Key(e.to_string()))?;

    match public {
        Public::Ecc { unique, .. } => {
            let x_bytes = unique.x().as_bytes();
            let y_bytes = unique.y().as_bytes();
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            let x_len = x_bytes.len().min(32);
            let y_len = y_bytes.len().min(32);
            x[32 - x_len..].copy_from_slice(&x_bytes[x_bytes.len() - x_len..]);
            y[32 - y_len..].copy_from_slice(&y_bytes[y_bytes.len() - y_len..]);
            Ok((x, y))
        }
        _ => Err(TpmError::Key("Not an ECC key".into())),
    }
}
