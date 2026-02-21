use std::io;

pub mod device;
pub mod report;
pub mod transport;

pub use transport::{HidTransport, start_hid_transport};

#[derive(Debug, thiserror::Error)]
pub enum HidError {
    #[error("Failed to create UHID device: {0}")]
    Create(io::Error),
    #[error("HID read error: {0}")]
    Read(String),
    #[error("HID write error: {0}")]
    Write(io::Error),
    #[error("Bad report size: {0} (expected 64)")]
    BadReportSize(usize),
}
