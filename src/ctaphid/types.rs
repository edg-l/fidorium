pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;
pub const RESERVED_CID: u32 = 0x0000_0000;

pub const CMD_PING: u8 = 0x01;
pub const CMD_INIT: u8 = 0x06;
pub const CMD_WINK: u8 = 0x08;
pub const CMD_CBOR: u8 = 0x10;
pub const CMD_CANCEL: u8 = 0x11;
pub const CMD_KEEPALIVE: u8 = 0x3B;
pub const CMD_ERROR: u8 = 0x3F;

pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_LOCK_REQUIRED: u8 = 0x0A;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const ERR_OTHER: u8 = 0x7F;

pub const CAP_WINK: u8 = 0x01;
pub const CAP_CBOR: u8 = 0x04;
pub const CAP_NMSG: u8 = 0x08;
pub const FIDORIUM_CAPABILITIES: u8 = CAP_CBOR | CAP_NMSG;

pub const INIT_DATA_SIZE: usize = 57;
pub const CONT_DATA_SIZE: usize = 59;
pub const PACKET_SIZE: usize = 64;
pub const INIT_NONCE_SIZE: usize = 8;
pub const INIT_RESPONSE_SIZE: usize = 17;
pub const CTAPHID_PROTOCOL_VERSION: u8 = 2;
pub const DEVICE_VERSION_MAJOR: u8 = 0;
pub const DEVICE_VERSION_MINOR: u8 = 1;
pub const DEVICE_VERSION_BUILD: u8 = 0;
