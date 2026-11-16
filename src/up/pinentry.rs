use super::prompt::UpPrompt;
use crate::ctap2::types::Ctap2Error;
use crate::ctaphid::packet::encode_response;
use crate::ctaphid::types::CMD_KEEPALIVE;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use tokio::sync::mpsc;

const KEEPALIVE_PROCESSING: u8 = 0x01;
const KEEPALIVE_UPNEEDED: u8 = 0x02;

pub struct UserPresenceProof {
    pub(crate) _private: (),
    // Keeps the KEEPALIVE task alive until the command (including the TPM
    // operations that follow user presence) has finished. Hosts such as
    // Firefox abort a CTAP2 request if they receive no KEEPALIVE while the
    // authenticator is processing.
    _keepalive: Option<KeepaliveGuard>,
}

struct KeepaliveGuard {
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for KeepaliveGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
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
    let status = Arc::new(AtomicU8::new(KEEPALIVE_UPNEEDED));
    let status2 = Arc::clone(&status);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let s = status2.load(Ordering::Relaxed);
                    tx_keepalive.send(encode_keepalive(cid, s)).await.ok();
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

    if cancel.load(Ordering::Relaxed) {
        return Err(Ctap2Error::KeepaliveCancel);
    }

    match result {
        Err(_) => Err(Ctap2Error::UserActionTimeout),
        Ok(Err(_)) => Err(Ctap2Error::OperationDenied),
        Ok(Ok(Ok(_))) => {
            // User presence is confirmed. Keep sending KEEPALIVE while the
            // caller performs the remaining (potentially slow) TPM work.
            status.store(KEEPALIVE_PROCESSING, Ordering::Relaxed);
            Ok(UserPresenceProof {
                _private: (),
                _keepalive: Some(KeepaliveGuard {
                    stop_tx: Some(stop_tx),
                }),
            })
        }
        Ok(Ok(Err(_))) => Err(Ctap2Error::OperationDenied),
    }
}

impl UserPresenceProof {
    /// Construct a proof for use in tests only.
    /// Do not use in production code — this bypasses user presence verification.
    #[doc(hidden)]
    pub fn test_only() -> Self {
        Self {
            _private: (),
            _keepalive: None,
        }
    }
}
