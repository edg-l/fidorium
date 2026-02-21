use ciborium::value::Value;
use fidorium::ctaphid::{run_ctaphid_loop, types::*};
use fidorium::store::CredentialStore;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

fn try_make_tpm() -> Option<fidorium::tpm::TpmContext> {
    let tcti = std::env::var("FIDORIUM_TEST_TCTI")
        .unwrap_or_else(|_| "device:/dev/tpmrm0".into());
    fidorium::tpm::TpmContext::new(tcti.trim_start_matches("device:")).ok()
}

fn make_init_packet(cid: u32, cmd: u8, payload: &[u8]) -> [u8; 64] {
    let mut pkt = [0u8; 64];
    pkt[0..4].copy_from_slice(&cid.to_be_bytes());
    pkt[4] = cmd | 0x80;
    let bcnt = payload.len() as u16;
    pkt[5] = (bcnt >> 8) as u8;
    pkt[6] = (bcnt & 0xFF) as u8;
    let copy = payload.len().min(57);
    pkt[7..7 + copy].copy_from_slice(&payload[..copy]);
    pkt
}

fn cbor_map_get<'a>(map: &'a [(Value, Value)], key: i64) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| {
        if let Value::Integer(i) = k {
            if i128::from(*i) == key as i128 { return Some(v); }
        }
        None
    })
}

async fn run_loop_and_get_response(
    tpm: fidorium::tpm::TpmContext,
    payload: &[u8],
) -> Vec<u8> {
    let tmp = TempDir::new().unwrap();
    let store = Arc::new(Mutex::new(
        CredentialStore::load([0u8; 32], tmp.path().to_path_buf()).unwrap(),
    ));

    let (incoming_tx, incoming_rx) = mpsc::channel::<[u8; 64]>(16);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<[u8; 64]>(16);

    tokio::spawn(run_ctaphid_loop(
        incoming_rx,
        outgoing_tx,
        tpm,
        store,
        0x01800100,
        "pinentry".to_string(),
    ));

    // Allocate a channel with INIT
    incoming_tx
        .send(make_init_packet(BROADCAST_CID, CMD_INIT, &[1, 2, 3, 4, 5, 6, 7, 8]))
        .await
        .unwrap();
    let init_resp = timeout(Duration::from_secs(2), outgoing_rx.recv())
        .await
        .expect("INIT timeout")
        .unwrap();
    let cid = u32::from_be_bytes([init_resp[15], init_resp[16], init_resp[17], init_resp[18]]);

    // Send CBOR command
    incoming_tx
        .send(make_init_packet(cid, CMD_CBOR, payload))
        .await
        .unwrap();

    // Collect all response packets (may be multiple for large payloads)
    let first = timeout(Duration::from_secs(2), outgoing_rx.recv())
        .await
        .expect("CBOR response timeout")
        .unwrap();

    let bcnt = u16::from_be_bytes([first[5], first[6]]) as usize;
    let mut body: Vec<u8> = first[7..7 + bcnt.min(57)].to_vec();

    // Read continuation packets if needed
    let mut seq = 0u8;
    while body.len() < bcnt {
        let cont = timeout(Duration::from_millis(500), outgoing_rx.recv())
            .await
            .expect("continuation timeout")
            .unwrap();
        assert_eq!(cont[4], seq, "continuation sequence mismatch");
        let remaining = bcnt - body.len();
        let chunk = remaining.min(59);
        body.extend_from_slice(&cont[5..5 + chunk]);
        seq += 1;
    }

    drop(incoming_tx);
    body
}

#[tokio::test]
async fn test_get_info_status_ok() {
    let Some(tpm) = try_make_tpm() else {
        println!("SKIP: TPM not available");
        return;
    };

    let body = run_loop_and_get_response(tpm, &[0x04]).await;

    assert_eq!(body[0], 0x00, "GetInfo must return CTAP2_OK (0x00)");
}

#[tokio::test]
async fn test_get_info_versions() {
    let Some(tpm) = try_make_tpm() else {
        println!("SKIP: TPM not available");
        return;
    };

    let body = run_loop_and_get_response(tpm, &[0x04]).await;
    assert_eq!(body[0], 0x00);

    let val: Value = ciborium::from_reader(&body[1..]).unwrap();
    let Value::Map(map) = val else { panic!("GetInfo response is not a CBOR map") };

    // 0x01: versions array must contain "FIDO_2_0"
    let versions = cbor_map_get(&map, 0x01).expect("key 0x01 (versions) missing");
    let Value::Array(arr) = versions else { panic!("versions is not an array") };
    let has_fido2 = arr.iter().any(|v| matches!(v, Value::Text(s) if s == "FIDO_2_0"));
    assert!(has_fido2, "versions must contain FIDO_2_0");
}

#[tokio::test]
async fn test_get_info_aaguid() {
    let Some(tpm) = try_make_tpm() else {
        println!("SKIP: TPM not available");
        return;
    };

    let body = run_loop_and_get_response(tpm, &[0x04]).await;
    assert_eq!(body[0], 0x00);

    let val: Value = ciborium::from_reader(&body[1..]).unwrap();
    let Value::Map(map) = val else { panic!("not a map") };

    // 0x03: aaguid must be 16 bytes and match config::AAGUID
    let aaguid_val = cbor_map_get(&map, 0x03).expect("key 0x03 (aaguid) missing");
    let Value::Bytes(aaguid) = aaguid_val else { panic!("aaguid is not bytes") };
    assert_eq!(aaguid.len(), 16, "AAGUID must be 16 bytes");
    assert_eq!(aaguid.as_slice(), &fidorium::config::AAGUID, "AAGUID must match config");
}

#[tokio::test]
async fn test_get_info_options() {
    let Some(tpm) = try_make_tpm() else {
        println!("SKIP: TPM not available");
        return;
    };

    let body = run_loop_and_get_response(tpm, &[0x04]).await;
    assert_eq!(body[0], 0x00);

    let val: Value = ciborium::from_reader(&body[1..]).unwrap();
    let Value::Map(map) = val else { panic!("not a map") };

    // 0x04: options map — rk=true, up=true, uv=false
    let opts_val = cbor_map_get(&map, 0x04).expect("key 0x04 (options) missing");
    let Value::Map(opts) = opts_val else { panic!("options is not a map") };

    let get_bool = |key: &str| -> Option<bool> {
        opts.iter().find_map(|(k, v)| {
            if let (Value::Text(k), Value::Bool(b)) = (k, v) {
                if k == key { return Some(*b); }
            }
            None
        })
    };

    assert_eq!(get_bool("rk"), Some(true), "rk must be true");
    assert_eq!(get_bool("up"), Some(true), "up must be true");
    assert_eq!(get_bool("uv"), Some(false), "uv must be false");
}

#[tokio::test]
async fn test_unknown_ctap2_cmd_returns_error() {
    let Some(tpm) = try_make_tpm() else {
        println!("SKIP: TPM not available");
        return;
    };

    // Command 0x7F is not a valid CTAP2 command
    let body = run_loop_and_get_response(tpm, &[0x7F]).await;
    assert_ne!(body[0], 0x00, "Unknown command must not return CTAP2_OK");
}
