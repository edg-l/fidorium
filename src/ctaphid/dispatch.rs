use tokio::sync::mpsc;
use super::{
    CtapHidError,
    channel::{ChannelManager, Message},
    packet::{parse_packet, encode_response, encode_error, Packet},
    types::*,
};
use crate::config::MAX_CHANNELS;

pub async fn run_ctaphid_loop(
    mut incoming_rx: mpsc::Receiver<[u8; 64]>,
    outgoing_tx: mpsc::Sender<[u8; 64]>,
) {
    let mut manager = ChannelManager::new(MAX_CHANNELS);
    tracing::info!("CTAPHID loop running");

    while let Some(report) = incoming_rx.recv().await {
        let packets = process_report(&mut manager, &report);
        for pkt in packets {
            if outgoing_tx.send(pkt).await.is_err() {
                tracing::error!("Outgoing channel closed");
                return;
            }
        }
    }
    tracing::info!("CTAPHID loop exiting (incoming channel closed)");
}

fn process_report(manager: &mut ChannelManager, report: &[u8; 64]) -> Vec<[u8; 64]> {
    let packet = match parse_packet(report) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Failed to parse packet: {e}");
            return vec![];
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
                return vec![encode_error(BROADCAST_CID, ERR_INVALID_CHANNEL)];
            }
            if init.cid != BROADCAST_CID && manager.get(init.cid).is_none() {
                tracing::warn!(cid = format!("{:#010x}", init.cid), "Unknown CID");
                return vec![encode_error(init.cid, ERR_INVALID_CHANNEL)];
            }

            match manager.feed_init(init.cid, init.cmd, init.bcnt, init.data) {
                Ok(Some(msg)) => dispatch_message(manager, msg),
                Ok(None) => vec![],
                Err(e) => {
                    tracing::warn!(cid = format!("{:#010x}", init.cid), "feed_init error: {e}");
                    let err_code = ctaphid_error_code(&e);
                    vec![encode_error(init.cid, err_code)]
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
                return vec![encode_error(cont.cid, ERR_INVALID_CHANNEL)];
            }
            match manager.feed_cont(cont.cid, cont.seq, cont.data) {
                Ok(Some(msg)) => dispatch_message(manager, msg),
                Ok(None) => vec![],
                Err(e) => {
                    tracing::warn!(cid = format!("{:#010x}", cont.cid), "feed_cont error: {e}");
                    let err_code = ctaphid_error_code(&e);
                    vec![encode_error(cont.cid, err_code)]
                }
            }
        }
    }
}

fn dispatch_message(manager: &mut ChannelManager, msg: Message) -> Vec<[u8; 64]> {
    match msg.cmd {
        CMD_INIT => handle_init(manager, msg),
        CMD_PING => handle_ping(msg),
        CMD_CANCEL => {
            tracing::debug!(cid = format!("{:#010x}", msg.cid), "CANCEL (no-op in Phase 1)");
            vec![]
        }
        cmd => {
            tracing::warn!(
                cid = format!("{:#010x}", msg.cid),
                cmd = format!("{:#04x}", cmd),
                "Unknown command"
            );
            vec![encode_error(msg.cid, ERR_INVALID_CMD)]
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

    tracing::info!(cid = format!("{:#010x}", new_cid), "Allocated new channel");

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
