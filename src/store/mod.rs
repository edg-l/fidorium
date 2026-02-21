pub mod credential;
pub mod disk;
pub mod index;

pub use credential::CredentialRecord;
pub use index::CredentialStore;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialize: {0}")]
    Serialization(String),
    #[error("Encrypt: {0}")]
    Encryption(String),
    #[error("Corrupt: {0}")]
    Corrupt(String),
    #[error("Not found")]
    NotFound,
}
