use std::fs::{File, OpenOptions};
use std::io::Write;
use uhid_virt::{Bus, CreateParams, InputEvent, UHID_EVENT_SIZE};
use super::{HidError, report::FIDO_HID_REPORT_DESCRIPTOR};

/// Open /dev/uhid in blocking mode and register the FIDO HID device.
/// Returns the raw File so the caller controls the I/O mode.
pub fn create_uhid_device() -> Result<File, HidError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/uhid")
        .map_err(HidError::Create)?;

    let params = CreateParams {
        name: String::from("fidorium FIDO2 HID"),
        phys: String::new(),
        uniq: String::new(),
        bus: Bus::USB,
        vendor: 0x1209,
        product: 0xF1D0,
        version: 0,
        country: 0,
        rd_data: FIDO_HID_REPORT_DESCRIPTOR.to_vec(),
    };

    let event: [u8; UHID_EVENT_SIZE] = InputEvent::Create(params).into();
    file.write_all(&event).map_err(HidError::Create)?;
    Ok(file)
}
