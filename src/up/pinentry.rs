use super::prompt::UpPrompt;
use crate::ctap2::types::Ctap2Error;
use crate::ctaphid::packet::encode_response;
use crate::ctaphid::types::CMD_KEEPALIVE;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

pub struct UserPresenceProof {
    pub(crate) _private: (),
}

fn encode_keepalive(cid: u32, status: u8) -> [u8; 64] {
    encode_response(cid, CMD_KEEPALIVE, &[status])[0]
}

pub(crate) async fn require_user_presence(
    prompt: &UpPrompt,
    pinentry_bin: &str,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cid: u32,
    cancel: &Arc<AtomicBool>,
) -> Result<UserPresenceProof, Ctap2Error> {
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let tx_keepalive = outgoing_tx.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tx_keepalive.send(encode_keepalive(cid, 0x02)).await.ok();
                }
                _ = &mut stop_rx => break,
            }
        }
    });

    let title = prompt.title.clone();
    let description = prompt.description.clone();
    let bin = pinentry_bin.to_string();

    let join = tokio::task::spawn_blocking(move || {
        let input = pinentry::PassphraseInput::with_binary(&bin);
        match input {
            None => Err(pinentry::Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "pinentry binary not found",
            ))),
            Some(mut input) => input
                .with_title(&title)
                .with_description(&description)
                .with_ok("Confirm")
                .with_cancel("Deny")
                .interact(),
        }
    });

    let result = tokio::time::timeout(std::time::Duration::from_secs(30), join).await;

    let _ = stop_tx.send(());

    if cancel.load(Ordering::Relaxed) {
        return Err(Ctap2Error::KeepaliveCancel);
    }

    match result {
        Err(_) => Err(Ctap2Error::UserActionTimeout),
        Ok(Err(_)) => Err(Ctap2Error::OperationDenied),
        Ok(Ok(Ok(_))) => Ok(UserPresenceProof { _private: () }),
        Ok(Ok(Err(_))) => Err(Ctap2Error::OperationDenied),
    }
}

impl UserPresenceProof {
    /// Construct a proof for use in tests only.
    /// Do not use in production code — this bypasses user presence verification.
    #[doc(hidden)]
    pub fn test_only() -> Self {
        Self { _private: () }
    }
}
