use super::prompt::UpPrompt;
use crate::ctap2::types::Ctap2Error;
use crate::ctaphid::packet::encode_response;
use crate::ctaphid::types::CMD_KEEPALIVE;
use crate::tpm::TpmContext;
use secrecy::ExposeSecret;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

/// Evidence that the user was verified through pinentry for this operation.
///
/// Only [`UserVerifier::require`] constructs one outside of tests, so the
/// signing path cannot be reached without a passphrase the TPM accepted.
pub struct UserPresenceProof {
    pub(crate) _private: (),
}

/// Authorization to reach the TPM signing path.
///
/// Signing is gated on this enum rather than on a bare flag so that producing a
/// user-present assertion without a verified prompt is not expressible.
pub enum SignAuth {
    /// The user was verified through pinentry. The assertion may set UP and UV.
    UserPresent(UserPresenceProof),
    /// A CTAP silent probe (`options.up = false`), used by clients to discover
    /// which credentials exist without disturbing the user.
    ///
    /// The resulting assertion MUST have the UP flag clear. WebAuthn requires
    /// relying parties to reject an assertion with UP=0, so a silent signature
    /// cannot stand in for a real authentication.
    Silent,
}

/// Prompts for the user's passphrase and checks it against a TPM-sealed
/// verifier object, which is what entitles us to report `uv: true` in GetInfo.
///
/// The passphrase is the authValue of a sealed TPM object, so the check happens
/// inside the TPM: a wrong passphrase fails `TPM2_Unseal` and increments the
/// TPM's dictionary-attack counter. Nothing derived from the passphrase is
/// stored on disk.
pub struct UserVerifier {
    pinentry_bin: String,
    blob_path: PathBuf,
}

fn encode_keepalive(cid: u32, status: u8) -> [u8; 64] {
    encode_response(cid, CMD_KEEPALIVE, &[status])[0]
}

/// `(private, public)` blobs, length-prefixed so they round-trip through one file.
fn encode_blob(private: &[u8], public: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + private.len() + public.len());
    out.extend_from_slice(&(private.len() as u32).to_be_bytes());
    out.extend_from_slice(private);
    out.extend_from_slice(public);
    out
}

fn decode_blob(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Ctap2Error> {
    if bytes.len() < 4 {
        return Err(Ctap2Error::Other("uv_verifier.blob is truncated".into()));
    }
    let private_len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if bytes.len() < 4 + private_len {
        return Err(Ctap2Error::Other(
            "uv_verifier.blob private section truncated".into(),
        ));
    }
    Ok((
        bytes[4..4 + private_len].to_vec(),
        bytes[4 + private_len..].to_vec(),
    ))
}

impl UserVerifier {
    pub fn new(pinentry_bin: String, blob_path: PathBuf) -> Self {
        Self {
            pinentry_bin,
            blob_path,
        }
    }

    /// True once a passphrase has been enrolled.
    pub fn is_enrolled(&self) -> bool {
        self.blob_path.exists()
    }

    /// Prompt, verify, and on success return proof that signing may proceed.
    ///
    /// On first use this enrolls a passphrase instead, since there is nothing
    /// to check against yet. Enrollment is deliberately lazy rather than done
    /// at startup: the daemon may start at boot with no session to prompt in.
    pub(crate) async fn require(
        &self,
        prompt: &UpPrompt,
        tpm: &TpmContext,
        outgoing_tx: &mpsc::Sender<[u8; 64]>,
        cid: u32,
        cancel: &Arc<AtomicBool>,
    ) -> Result<UserPresenceProof, Ctap2Error> {
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let tx_keepalive = outgoing_tx.clone();

        // Hold the client open across both the dialog and the TPM check.
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

        let result = self.prompt_and_verify(prompt, tpm, cancel).await;
        let _ = stop_tx.send(());
        result
    }

    async fn prompt_and_verify(
        &self,
        prompt: &UpPrompt,
        tpm: &TpmContext,
        cancel: &Arc<AtomicBool>,
    ) -> Result<UserPresenceProof, Ctap2Error> {
        let enrolling = !self.is_enrolled();

        let title = prompt.title.clone();
        let description = if enrolling {
            format!(
                "{}\n\nNo passphrase is set yet. Choose one now — it will be \
                 required to approve future passkey operations.",
                prompt.description
            )
        } else {
            prompt.description.clone()
        };
        let bin = self.pinentry_bin.clone();

        let join = tokio::task::spawn_blocking(move || {
            let Some(mut input) = pinentry::PassphraseInput::with_binary(&bin) else {
                return Err(pinentry::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "pinentry binary not found",
                )));
            };
            input
                .with_title(&title)
                .with_description(&description)
                .with_prompt("Passphrase:")
                .required("A passphrase is required")
                .with_ok("Confirm")
                .with_cancel("Deny");
            if enrolling {
                input.with_confirmation("Confirm passphrase:", "Passphrases do not match");
            }
            input.interact()
        });

        let result = tokio::time::timeout(std::time::Duration::from_secs(30), join).await;

        if cancel.load(Ordering::Relaxed) {
            return Err(Ctap2Error::KeepaliveCancel);
        }

        let passphrase = match result {
            Err(_) => return Err(Ctap2Error::UserActionTimeout),
            Ok(Err(_)) => return Err(Ctap2Error::OperationDenied),
            Ok(Ok(Err(_))) => return Err(Ctap2Error::OperationDenied),
            Ok(Ok(Ok(secret))) => secret,
        };
        let passphrase = passphrase.expose_secret().to_string();

        if enrolling {
            self.enroll(tpm, passphrase).await?;
            tracing::info!("Enrolled user verification passphrase");
            return Ok(UserPresenceProof { _private: () });
        }

        let (private_blob, public_blob) = decode_blob(&std::fs::read(&self.blob_path)?)?;
        let tpm2 = tpm.clone();
        let verified = tokio::task::spawn_blocking(move || {
            tpm2.with_ctx(|ctx, primary| {
                crate::tpm::seal::verify_passphrase(
                    ctx,
                    primary,
                    &private_blob,
                    &public_blob,
                    &passphrase,
                )
            })
        })
        .await
        .map_err(|e| Ctap2Error::Tpm(crate::tpm::TpmError::Other(e.to_string())))??;

        if !verified {
            tracing::warn!("User verification failed: passphrase rejected by TPM");
            return Err(Ctap2Error::UvInvalid);
        }
        Ok(UserPresenceProof { _private: () })
    }

    async fn enroll(&self, tpm: &TpmContext, passphrase: String) -> Result<(), Ctap2Error> {
        let tpm2 = tpm.clone();
        let (private_blob, public_blob) = tokio::task::spawn_blocking(move || {
            tpm2.with_ctx(|ctx, primary| {
                crate::tpm::seal::create_uv_verifier(ctx, primary, &passphrase)
            })
        })
        .await
        .map_err(|e| Ctap2Error::Tpm(crate::tpm::TpmError::Other(e.to_string())))??;

        write_private(&self.blob_path, &encode_blob(&private_blob, &public_blob))?;
        Ok(())
    }
}

/// Write owner-only. The blob is not secret on its own — the passphrase is
/// never derivable from it — but it gates user verification, so it should not
/// be world-readable or replaceable by another user.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

impl UserPresenceProof {
    /// Construct a proof for use in tests only.
    /// Do not use in production code — this bypasses user verification.
    #[doc(hidden)]
    pub fn test_only() -> Self {
        Self { _private: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_roundtrip() {
        let encoded = encode_blob(&[1, 2, 3], &[4, 5, 6, 7]);
        let (private, public) = decode_blob(&encoded).unwrap();
        assert_eq!(private, vec![1, 2, 3]);
        assert_eq!(public, vec![4, 5, 6, 7]);
    }

    #[test]
    fn test_decode_blob_rejects_truncated() {
        assert!(
            decode_blob(&[0, 0]).is_err(),
            "short header must be rejected"
        );
        // Claims a 99-byte private section but supplies far less.
        assert!(
            decode_blob(&[0, 0, 0, 99, 1, 2]).is_err(),
            "truncated private section must be rejected"
        );
    }

    #[test]
    fn test_not_enrolled_when_blob_absent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let v = UserVerifier::new("pinentry".into(), tmp.path().join("uv_verifier.blob"));
        assert!(!v.is_enrolled());
    }
}
