pub mod context;
pub mod counter;
pub mod keys;
pub mod seal;

pub use context::TpmContext;

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("TPM context error: {0}")]
    Context(String),
    #[error("TPM key error: {0}")]
    Key(String),
    #[error("TPM counter error: {0}")]
    Counter(String),
    #[error("TPM seal error: {0}")]
    Seal(String),
    #[error("TPM error: {0}")]
    Other(String),
}

impl From<tss_esapi::Error> for TpmError {
    fn from(e: tss_esapi::Error) -> Self {
        TpmError::Other(e.to_string())
    }
}
