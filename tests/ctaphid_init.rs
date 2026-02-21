use fidorium::ctaphid::{run_ctaphid_loop, types::*};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

fn make_init_packet(cid: u32, cmd: u8, payload: &[u8]) -> [u8; 64] {
    let mut pkt = [0u8; 64];
    pkt[0..4].copy_from_slice(&cid.to_be_bytes());
    pkt[4] = cmd | 0x80;
    let bcnt = payload.len() as u16;
    pkt[5] = (bcnt >> 8) as u8;
    pkt[6] = (bcnt & 0xFF) as u8;
    let len = payload.len().min(57);
    pkt[7..7 + len].copy_from_slice(&payload[..len]);
    pkt
}

#[tokio::test]
async fn test_ctaphid_init_returns_cid() {
    let (incoming_tx, incoming_rx) = mpsc::channel::<[u8; 64]>(16);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<[u8; 64]>(16);

    tokio::spawn(run_ctaphid_loop(incoming_rx, outgoing_tx));

    let nonce = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let pkt = make_init_packet(BROADCAST_CID, CMD_INIT, &nonce);
    incoming_tx.send(pkt).await.unwrap();

    let response = timeout(Duration::from_secs(1), outgoing_rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    // CID in response header should be BROADCAST_CID
    let resp_cid = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    assert_eq!(resp_cid, BROADCAST_CID, "Response CID must be broadcast");

    // CMD byte: INIT | 0x80
    assert_eq!(response[4], CMD_INIT | 0x80, "Response CMD must be INIT");

    // BCNT = 17
    let bcnt = u16::from_be_bytes([response[5], response[6]]);
    assert_eq!(bcnt, 17, "INIT response must be 17 bytes");

    // Nonce echoed at [7..15]
    assert_eq!(&response[7..15], &nonce, "Nonce must be echoed");

    // Allocated CID at [15..19]
    let new_cid = u32::from_be_bytes([response[15], response[16], response[17], response[18]]);
    assert_ne!(new_cid, 0, "Allocated CID must not be zero");
    assert_ne!(new_cid, BROADCAST_CID, "Allocated CID must not be broadcast");

    // Protocol version
    assert_eq!(response[19], CTAPHID_PROTOCOL_VERSION, "Protocol version must be 2");

    // Capabilities
    assert_eq!(response[23], FIDORIUM_CAPABILITIES, "Capabilities must be 0x0C");

    drop(incoming_tx);
}

#[tokio::test]
async fn test_ctaphid_ping_echo() {
    let (incoming_tx, incoming_rx) = mpsc::channel::<[u8; 64]>(16);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<[u8; 64]>(16);

    tokio::spawn(run_ctaphid_loop(incoming_rx, outgoing_tx));

    // First: INIT to get a valid CID
    let nonce = [0xAAu8; 8];
    let init_pkt = make_init_packet(BROADCAST_CID, CMD_INIT, &nonce);
    incoming_tx.send(init_pkt).await.unwrap();

    let init_resp = timeout(Duration::from_secs(1), outgoing_rx.recv())
        .await
        .expect("timeout waiting for INIT response")
        .expect("channel closed");

    let cid = u32::from_be_bytes([init_resp[15], init_resp[16], init_resp[17], init_resp[18]]);

    // PING with payload
    let ping_data = b"hello fidorium";
    let ping_pkt = make_init_packet(cid, CMD_PING, ping_data);
    incoming_tx.send(ping_pkt).await.unwrap();

    let pong = timeout(Duration::from_secs(1), outgoing_rx.recv())
        .await
        .expect("timeout waiting for PING response")
        .expect("channel closed");

    let resp_cid = u32::from_be_bytes([pong[0], pong[1], pong[2], pong[3]]);
    assert_eq!(resp_cid, cid, "PONG CID must match PING CID");
    assert_eq!(pong[4], CMD_PING | 0x80, "PONG CMD must be PING");

    let bcnt = u16::from_be_bytes([pong[5], pong[6]]) as usize;
    assert_eq!(bcnt, ping_data.len(), "PONG bcnt must match payload length");
    assert_eq!(&pong[7..7 + bcnt], ping_data, "PONG payload must echo exactly");

    drop(incoming_tx);
}

#[tokio::test]
async fn test_ctaphid_invalid_cmd_returns_error() {
    let (incoming_tx, incoming_rx) = mpsc::channel::<[u8; 64]>(16);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<[u8; 64]>(16);

    tokio::spawn(run_ctaphid_loop(incoming_rx, outgoing_tx));

    // INIT first
    let nonce = [0xBBu8; 8];
    let init_pkt = make_init_packet(BROADCAST_CID, CMD_INIT, &nonce);
    incoming_tx.send(init_pkt).await.unwrap();

    let init_resp = timeout(Duration::from_secs(1), outgoing_rx.recv())
        .await
        .expect("timeout")
        .unwrap();
    let cid = u32::from_be_bytes([init_resp[15], init_resp[16], init_resp[17], init_resp[18]]);

    // Send unknown command 0x7E
    let bad_pkt = make_init_packet(cid, 0x7E, &[]);
    incoming_tx.send(bad_pkt).await.unwrap();

    let err_resp = timeout(Duration::from_secs(1), outgoing_rx.recv())
        .await
        .expect("timeout waiting for error response")
        .unwrap();

    // CMD = ERROR | 0x80
    assert_eq!(err_resp[4], CMD_ERROR | 0x80, "Must respond with ERROR command");
    // payload[0] = ERR_INVALID_CMD
    assert_eq!(err_resp[7], ERR_INVALID_CMD, "Error code must be ERR_INVALID_CMD");

    drop(incoming_tx);
}
