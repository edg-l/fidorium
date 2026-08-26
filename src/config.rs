pub const AAGUID: [u8; 16] = [
    0xf1, 0xd0, 0x6b, 0x4e, 0x3a, 0x17, 0x4c, 0x80, 0xb1, 0xd2, 0x9e, 0x3f, 0x00, 0x00, 0x00, 0x01,
];
pub const MAX_CHANNELS: usize = 8;
pub const CHANNEL_TIMEOUT_SECS: u64 = 30;

#[derive(clap::Parser, Debug, Clone)]
pub struct Config {
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    #[arg(long, default_value = "/dev/tpmrm0")]
    pub tpm_device: String,
    #[arg(long, default_value = "0x01800100")]
    pub nv_index: String,
    #[arg(long, default_value = "pinentry")]
    pub pinentry: String,
    /// Seconds a successful passphrase check stays valid. Within this window
    /// operations only ask for confirmation, not the passphrase again. Set to 0
    /// to require the passphrase every time.
    #[arg(long, default_value_t = 300)]
    pub uv_cache_secs: u64,
    /// Delete all stored credentials and reset the TPM NV counter, then exit.
    #[arg(long)]
    pub wipe: bool,
}
