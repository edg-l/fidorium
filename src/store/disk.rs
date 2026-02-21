use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use std::path::Path;

use super::{CredentialRecord, StoreError};

/// Encrypt + write credential to `dir/{credential_id_hex}.bin`.
pub(crate) fn write_credential(
    aes_key: &[u8; 32],
    dir: &Path,
    record: &CredentialRecord,
) -> Result<(), StoreError> {
    let mut buf = Vec::new();
    ciborium::into_writer(record, &mut buf)
        .map_err(|e| StoreError::Serialization(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| StoreError::Encryption(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), buf.as_slice())
        .map_err(|e| StoreError::Encryption(e.to_string()))?;

    let hex: String = record.credential_id.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(format!("{hex}.bin"));

    let mut file_bytes = Vec::with_capacity(12 + ciphertext.len());
    file_bytes.extend_from_slice(&nonce_bytes);
    file_bytes.extend_from_slice(&ciphertext);

    std::fs::write(path, file_bytes)?;
    Ok(())
}

/// Read + decrypt + deserialize credential from `path`.
pub(crate) fn read_credential(
    aes_key: &[u8; 32],
    path: &Path,
) -> Result<CredentialRecord, StoreError> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 12 {
        return Err(StoreError::Corrupt("file too short".into()));
    }
    let (nonce_bytes, ciphertext) = bytes.split_at(12);

    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| StoreError::Encryption(e.to_string()))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| StoreError::Encryption(e.to_string()))?;

    let record: CredentialRecord = ciborium::from_reader(plaintext.as_slice())
        .map_err(|e| StoreError::Serialization(e.to_string()))?;

    Ok(record)
}

/// Delete credential file for `credential_id`.
pub(crate) fn delete_credential(dir: &Path, credential_id: &[u8]) -> Result<(), StoreError> {
    let hex: String = credential_id.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(format!("{hex}.bin"));
    std::fs::remove_file(path)?;
    Ok(())
}

/// Load all valid credential files from `dir`. Logs and skips corrupt files.
pub(crate) fn load_all(
    aes_key: &[u8; 32],
    dir: &Path,
) -> Result<Vec<CredentialRecord>, StoreError> {
    let mut records = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        match read_credential(aes_key, &path) {
            Ok(record) => records.push(record),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Skipping corrupt credential file");
            }
        }
    }
    Ok(records)
}
