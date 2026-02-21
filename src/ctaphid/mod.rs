pub mod channel;
pub mod dispatch;
pub mod packet;
pub mod types;

pub use dispatch::run_ctaphid_loop;

#[derive(Debug, thiserror::Error)]
pub enum CtapHidError {
    #[error("Channel busy")]
    ChannelBusy,
    #[error("Invalid channel: {0:#x}")]
    InvalidChannel(u32),
    #[error("Unexpected continuation packet")]
    UnexpectedCont,
    #[error("Bad sequence number: {0}")]
    InvalidSeq(u8),
    #[error("Assembly timeout")]
    Timeout,
}
