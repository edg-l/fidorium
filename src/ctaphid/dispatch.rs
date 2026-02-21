use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use super::{
    CtapHidError,
    channel::{ChannelManager, Message},
    packet::{parse_packet, encode_response, encode_error, Packet},
    types::*,
};
use crate::config::MAX_CHANNELS;
use crate::ctap2;
use crate::store::CredentialStore;
use crate::tpm::TpmContext;

enum DispatchResult {
    Response(Vec<[u8; 64]>),
    Cbor(Message),
}

pub async fn run_ctaphid_loop(
    mut incoming_rx: mpsc::Receiver<[u8; 64]>,
    outgoing_tx: mpsc::Sender<[u8; 64]>,
    tpm: TpmContext,
    store: Arc<Mutex<CredentialStore>>,
    nv_index: u32,
    pinentry_bin: String,
) {
    let mut manager = ChannelManager::new(MAX_CHANNELS);
    let cancel = Arc::new(AtomicBool::new(false));
    let cbor_busy = Arc::new(AtomicBool::new(false));
    tracing::info!("CTAPHID loop running");

    while let Some(report) = incoming_rx.recv().await {
        match process_report(&mut manager, &report, &cancel) {
            DispatchResult::Response(pkts) => {
                let n = pkts.len();
                for pkt in pkts {
                    if outgoing_tx.send(pkt).await.is_err() {
                        tracing::error!("Outgoing channel closed");
                        return;
                    }
                }
                if n > 0 {
                    tracing::trace!(packets = n, "sent response");
                }
            }
            DispatchResult::Cbor(msg) => {
                if cbor_busy.swap(true, Ordering::Relaxed) {
                    outgoing_tx.send(encode_error(msg.cid, ERR_CHANNEL_BUSY)).await.ok();
                } else {
                    cancel.store(false, Ordering::Relaxed);
                    let tx = outgoing_tx.clone();
                    let tpm2 = tpm.clone();
                    let store2 = Arc::clone(&store);
                    let cancel2 = Arc::clone(&cancel);
                    let busy2 = Arc::clone(&cbor_busy);
                    let pin_bin = pinentry_bin.clone();
                    let cid = msg.cid;
                    tokio::spawn(async move {
                        let response = ctap2::dispatch_cbor(
                            msg, &tpm2, &store2, nv_index, &pin_bin, &tx, &cancel2,
                        ).await;
                        for pkt in encode_response(cid, CMD_CBOR, &response) {
                            tx.send(pkt).await.ok();
                        }
                        busy2.store(false, Ordering::Relaxed);
                    });
                }
            }
        }
    }
    tracing::info!("CTAPHID loop exiting (incoming channel closed)");
}

fn process_report(
    manager: &mut ChannelManager,
    report: &[u8; 64],
    cancel: &Arc<AtomicBool>,
) -> DispatchResult {
    let packet = match parse_packet(report) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Failed to parse packet: {e}");
            return DispatchResult::Response(vec![]);
        }
    };

    match packet {
        Packet::Init(init) => {
            tracing::debug!(
                cid = format!("{:#010x}", init.cid),
                cmd = format!("{:#04x}", init.cmd),
                bcnt = init.bcnt,
                "INIT packet"
            );

            if init.cid == RESERVED_CID {
                tracing::warn!("Rejected reserved CID");
                return DispatchResult::Response(vec![encode_error(BROADCAST_CID, ERR_INVALID_CHANNEL)]);
            }
            if init.cid != BROADCAST_CID && manager.get(init.cid).is_none() {
                tracing::warn!(cid = format!("{:#010x}", init.cid), "Unknown CID");
                return DispatchResult::Response(vec![encode_error(init.cid, ERR_INVALID_CHANNEL)]);
            }

            match manager.feed_init(init.cid, init.cmd, init.bcnt, init.data) {
                Ok(Some(msg)) => dispatch_message(manager, msg, cancel),
                Ok(None) => DispatchResult::Response(vec![]),
                Err(e) => {
                    tracing::warn!(cid = format!("{:#010x}", init.cid), "feed_init error: {e}");
                    let err_code = ctaphid_error_code(&e);
                    DispatchResult::Response(vec![encode_error(init.cid, err_code)])
                }
            }
        }
        Packet::Cont(cont) => {
            tracing::debug!(
                cid = format!("{:#010x}", cont.cid),
                seq = cont.seq,
                "CONT packet"
            );

            if cont.cid == BROADCAST_CID || cont.cid == RESERVED_CID {
                tracing::warn!(cid = format!("{:#010x}", cont.cid), "CONT on invalid CID");
                return DispatchResult::Response(vec![encode_error(cont.cid, ERR_INVALID_CHANNEL)]);
            }
            match manager.feed_cont(cont.cid, cont.seq, cont.data) {
                Ok(Some(msg)) => dispatch_message(manager, msg, cancel),
                Ok(None) => DispatchResult::Response(vec![]),
                Err(e) => {
                    tracing::warn!(cid = format!("{:#010x}", cont.cid), "feed_cont error: {e}");
                    let err_code = ctaphid_error_code(&e);
                    DispatchResult::Response(vec![encode_error(cont.cid, err_code)])
                }
            }
        }
    }
}

fn cmd_name(cmd: u8) -> &'static str {
    match cmd {
        CMD_PING      => "PING",
        CMD_MSG       => "MSG",
        CMD_INIT      => "INIT",
        CMD_WINK      => "WINK",
        CMD_CBOR      => "CBOR",
        CMD_CANCEL    => "CANCEL",
        CMD_KEEPALIVE => "KEEPALIVE",
        CMD_ERROR     => "ERROR",
        _             => "UNKNOWN",
    }
}

fn dispatch_message(
    manager: &mut ChannelManager,
    msg: Message,
    cancel: &Arc<AtomicBool>,
) -> DispatchResult {
    tracing::debug!(
        cid  = format!("{:#010x}", msg.cid),
        cmd  = cmd_name(msg.cmd),
        len  = msg.payload.len(),
        "dispatch"
    );
    match msg.cmd {
        CMD_INIT   => DispatchResult::Response(handle_init(manager, msg)),
        CMD_PING   => DispatchResult::Response(handle_ping(msg)),
        CMD_CANCEL => {
            tracing::debug!(cid = format!("{:#010x}", msg.cid), "CANCEL received");
            cancel.store(true, Ordering::Relaxed);
            DispatchResult::Response(vec![])
        }
        CMD_CBOR => DispatchResult::Cbor(msg),
        CMD_MSG => {
            tracing::debug!(cid = format!("{:#010x}", msg.cid), "MSG (U2F) -> SW_INS_NOT_SUPPORTED");
            DispatchResult::Response(encode_response(msg.cid, CMD_MSG, &[0x6D, 0x00]))
        }
        cmd => {
            tracing::warn!(
                cid  = format!("{:#010x}", msg.cid),
                cmd  = cmd_name(cmd),
                raw  = format!("{:#04x}", cmd),
                "Unimplemented command"
            );
            DispatchResult::Response(vec![encode_error(msg.cid, ERR_INVALID_CMD)])
        }
    }
}

fn handle_init(manager: &mut ChannelManager, msg: Message) -> Vec<[u8; 64]> {
    if msg.payload.len() < INIT_NONCE_SIZE {
        tracing::warn!("INIT payload too short: {} bytes", msg.payload.len());
        return vec![encode_error(msg.cid, ERR_INVALID_LEN)];
    }

    let new_cid = match manager.allocate_cid() {
        Ok(cid) => cid,
        Err(_) => {
            tracing::warn!("All channels busy, rejecting INIT");
            return vec![encode_error(msg.cid, ERR_CHANNEL_BUSY)];
        }
    };

    let nonce_hex: String = msg.payload[..8].iter().map(|b| format!("{b:02x}")).collect();
    tracing::info!(
        cid   = format!("{:#010x}", new_cid),
        nonce = nonce_hex,
        "Allocated new channel"
    );

    let mut response = [0u8; INIT_RESPONSE_SIZE];
    response[0..8].copy_from_slice(&msg.payload[0..8]);
    response[8..12].copy_from_slice(&new_cid.to_be_bytes());
    response[12] = CTAPHID_PROTOCOL_VERSION;
    response[13] = DEVICE_VERSION_MAJOR;
    response[14] = DEVICE_VERSION_MINOR;
    response[15] = DEVICE_VERSION_BUILD;
    response[16] = FIDORIUM_CAPABILITIES;

    encode_response(msg.cid, CMD_INIT, &response)
}

fn handle_ping(msg: Message) -> Vec<[u8; 64]> {
    tracing::debug!(
        cid = format!("{:#010x}", msg.cid),
        len = msg.payload.len(),
        "PING"
    );
    encode_response(msg.cid, CMD_PING, &msg.payload)
}

fn ctaphid_error_code(e: &CtapHidError) -> u8 {
    match e {
        CtapHidError::ChannelBusy => ERR_CHANNEL_BUSY,
        CtapHidError::InvalidChannel(_) => ERR_INVALID_CHANNEL,
        CtapHidError::UnexpectedCont => ERR_INVALID_CMD,
        CtapHidError::InvalidSeq(_) => ERR_INVALID_PAR,
        CtapHidError::Timeout => ERR_OTHER,
    }
}
