use super::{CtapHidError, types::*};

pub enum Packet {
    Init(InitPacket),
    Cont(ContPacket),
}

pub struct InitPacket {
    pub cid: u32,
    pub cmd: u8,
    pub bcnt: u16,
    pub data: Vec<u8>,
}

pub struct ContPacket {
    pub cid: u32,
    pub seq: u8,
    pub data: Vec<u8>,
}

/// Distinguish init vs cont by bit 7 of byte 4.
pub fn parse_packet(report: &[u8; 64]) -> Result<Packet, CtapHidError> {
    let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
    let byte4 = report[4];

    if byte4 & 0x80 != 0 {
        // Init packet: bit 7 set
        let cmd = byte4 & 0x7F;
        let bcnt = u16::from_be_bytes([report[5], report[6]]);
        let take = (bcnt as usize).min(INIT_DATA_SIZE);
        let data = report[7..7 + take].to_vec();
        Ok(Packet::Init(InitPacket {
            cid,
            cmd,
            bcnt,
            data,
        }))
    } else {
        // Cont packet: bit 7 clear
        let seq = byte4;
        let data = report[5..5 + CONT_DATA_SIZE].to_vec();
        Ok(Packet::Cont(ContPacket { cid, seq, data }))
    }
}

/// Encode response message into >=1 HID reports.
pub fn encode_response(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; 64]> {
    let mut packets = Vec::new();
    let bcnt = payload.len() as u16;
    let cid_bytes = cid.to_be_bytes();

    // Init packet
    let mut pkt = [0u8; 64];
    pkt[0..4].copy_from_slice(&cid_bytes);
    pkt[4] = cmd | 0x80;
    pkt[5] = (bcnt >> 8) as u8;
    pkt[6] = (bcnt & 0xFF) as u8;
    let first_chunk = payload.len().min(INIT_DATA_SIZE);
    pkt[7..7 + first_chunk].copy_from_slice(&payload[..first_chunk]);
    packets.push(pkt);

    // Continuation packets
    let mut offset = first_chunk;
    let mut seq: u8 = 0;
    while offset < payload.len() {
        let mut cpkt = [0u8; 64];
        cpkt[0..4].copy_from_slice(&cid_bytes);
        cpkt[4] = seq;
        let chunk = (payload.len() - offset).min(CONT_DATA_SIZE);
        cpkt[5..5 + chunk].copy_from_slice(&payload[offset..offset + chunk]);
        packets.push(cpkt);
        offset += chunk;
        seq = seq.wrapping_add(1);
    }

    packets
}

/// Single-packet ERROR response.
pub fn encode_error(cid: u32, error_code: u8) -> [u8; 64] {
    let packets = encode_response(cid, CMD_ERROR, &[error_code]);
    packets[0]
}
