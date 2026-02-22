use std::collections::HashMap;
use std::path::PathBuf;

use super::{StoreError, credential::CredentialRecord, disk};

pub struct CredentialStore {
    aes_key: [u8; 32],
    creds_dir: PathBuf,
    by_id: HashMap<[u8; 32], CredentialRecord>,
    by_rp: HashMap<[u8; 32], Vec<[u8; 32]>>,
}

impl CredentialStore {
    /// Load all credentials from disk into memory.
    pub fn load(aes_key: [u8; 32], creds_dir: PathBuf) -> Result<Self, StoreError> {
        let records = disk::load_all(&aes_key, &creds_dir)?;
        let mut by_id = HashMap::new();
        let mut by_rp: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
        for record in records {
            let id: [u8; 32] = record
                .credential_id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("credential_id not 32 bytes".into()))?;
            let rp: [u8; 32] = record
                .rp_id_hash
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("rp_id_hash not 32 bytes".into()))?;
            by_rp.entry(rp).or_default().push(id);
            by_id.insert(id, record);
        }
        Ok(Self {
            aes_key,
            creds_dir,
            by_id,
            by_rp,
        })
    }

    /// Add new credential: write to disk and index in memory.
    pub fn add(&mut self, record: CredentialRecord) -> Result<(), StoreError> {
        disk::write_credential(&self.aes_key, &self.creds_dir, &record)?;
        let id: [u8; 32] = record
            .credential_id
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupt("credential_id not 32 bytes".into()))?;
        let rp: [u8; 32] = record
            .rp_id_hash
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corrupt("rp_id_hash not 32 bytes".into()))?;
        self.by_rp.entry(rp).or_default().push(id);
        self.by_id.insert(id, record);
        Ok(())
    }

    /// Look up by credential_id (for allowList-based GetAssertion).
    pub fn get_by_id(&self, id: &[u8]) -> Option<&CredentialRecord> {
        let id: [u8; 32] = id.try_into().ok()?;
        self.by_id.get(&id)
    }

    /// Look up all credentials for an rpIdHash (for discoverable/passkey flow).
    /// Returns records sorted by created_at descending (most recent first).
    pub fn get_by_rp_hash(&self, rp_id_hash: &[u8]) -> Vec<&CredentialRecord> {
        let rp: [u8; 32] = match rp_id_hash.try_into() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let ids = match self.by_rp.get(&rp) {
            Some(ids) => ids,
            None => return Vec::new(),
        };
        let mut records: Vec<&CredentialRecord> =
            ids.iter().filter_map(|id| self.by_id.get(id)).collect();
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        records
    }

    /// Remove a credential by id; deletes from disk and memory index.
    pub fn remove(&mut self, id: &[u8]) -> Result<bool, StoreError> {
        let id: [u8; 32] = match id.try_into() {
            Ok(i) => i,
            Err(_) => return Ok(false),
        };
        if let Some(record) = self.by_id.remove(&id) {
            disk::delete_credential(&self.creds_dir, &record.credential_id)?;
            let rp: [u8; 32] = record
                .rp_id_hash
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corrupt("rp_id_hash not 32 bytes".into()))?;
            if let Some(ids) = self.by_rp.get_mut(&rp) {
                ids.retain(|i| i != &id);
                if ids.is_empty() {
                    self.by_rp.remove(&rp);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn credential_count(&self) -> usize {
        self.by_id.len()
    }
}
