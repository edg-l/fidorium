use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub version:      u8,
    pub credential_id: Vec<u8>,     // 32 bytes random
    pub rp_id:        String,
    pub rp_id_hash:   Vec<u8>,      // SHA-256(rp_id), 32 bytes
    pub rp_name:      Option<String>,
    pub user_id:      Vec<u8>,
    pub user_name:    Option<String>,
    pub user_display: Option<String>,
    pub public_key_x: Vec<u8>,      // ECC P-256 x, 32 bytes
    pub public_key_y: Vec<u8>,      // ECC P-256 y, 32 bytes
    pub key_private:  Vec<u8>,      // TPM2B_PRIVATE marshaled
    pub key_public:   Vec<u8>,      // TPM2B_PUBLIC marshaled
    pub created_at:   u64,          // Unix timestamp
    pub discoverable: bool,
}
