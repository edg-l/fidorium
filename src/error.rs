#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HID: {0}")]
    Hid(#[from] crate::hid::HidError),
    #[error("CTAPHID: {0}")]
    CtapHid(#[from] crate::ctaphid::CtapHidError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("TPM: {0}")]
    Tpm(#[from] crate::tpm::TpmError),
    #[error("Store: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("{0}")]
    Internal(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
