pub(crate) mod attestation;
pub(crate) mod authenticator_data;
pub(crate) mod get_assertion;
pub(crate) mod get_info;
pub(crate) mod make_credential;
pub(crate) mod types;

pub(crate) use types::Ctap2Error;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::ctaphid::channel::Message;
use crate::store::CredentialStore;
use crate::tpm::TpmContext;
use types::{
    CTAP2_CMD_GET_ASSERTION, CTAP2_CMD_GET_INFO, CTAP2_CMD_MAKE_CREDENTIAL, GetAssertionRequest,
    MakeCredentialRequest,
};

pub(crate) async fn dispatch_cbor(
    msg: Message,
    tpm: &TpmContext,
    store: &Arc<Mutex<CredentialStore>>,
    nv_index: u32,
    pinentry_bin: &str,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cancel: &Arc<AtomicBool>,
) -> Vec<u8> {
    match dispatch_inner(msg, tpm, store, nv_index, pinentry_bin, outgoing_tx, cancel).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("CTAP2 error: {e}");
            vec![e.status_byte()]
        }
    }
}

async fn dispatch_inner(
    msg: Message,
    tpm: &TpmContext,
    store: &Arc<Mutex<CredentialStore>>,
    nv_index: u32,
    pinentry_bin: &str,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<u8>, Ctap2Error> {
    if msg.payload.is_empty() {
        return Err(Ctap2Error::MissingParameter);
    }
    let cmd_byte = msg.payload[0];
    let cbor_body = &msg.payload[1..];
    let cid = msg.cid;

    match cmd_byte {
        CTAP2_CMD_GET_INFO => Ok(get_info::handle_get_info()),
        CTAP2_CMD_MAKE_CREDENTIAL => {
            let req = MakeCredentialRequest::try_from(cbor_body)?;
            make_credential::handle_make_credential(
                req,
                tpm,
                store,
                nv_index,
                pinentry_bin,
                cid,
                outgoing_tx,
                cancel,
            )
            .await
        }
        CTAP2_CMD_GET_ASSERTION => {
            let req = GetAssertionRequest::try_from(cbor_body)?;
            get_assertion::handle_get_assertion(
                req,
                tpm,
                store,
                nv_index,
                pinentry_bin,
                cid,
                outgoing_tx,
                cancel,
            )
            .await
        }
        _ => Err(Ctap2Error::Cbor(format!("unknown cmd {cmd_byte:#04x}"))),
    }
}
