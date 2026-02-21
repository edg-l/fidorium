use std::io::{Read, Write};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use uhid_virt::{InputEvent, OutputEvent, UHID_EVENT_SIZE};
use super::{HidError, report::HID_REPORT_SIZE, device::create_uhid_device};

pub struct HidTransport {
    pub incoming_rx: mpsc::Receiver<[u8; HID_REPORT_SIZE]>,
    pub outgoing_tx: mpsc::Sender<[u8; HID_REPORT_SIZE]>,
    pub task: JoinHandle<Result<(), HidError>>,
}

pub fn start_hid_transport() -> Result<HidTransport, HidError> {
    let (incoming_tx, incoming_rx) = mpsc::channel::<[u8; HID_REPORT_SIZE]>(64);
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<[u8; HID_REPORT_SIZE]>(64);

    let task = tokio::task::spawn_blocking(move || {
        let mut file = create_uhid_device()?;
        tracing::info!("UHID device created, waiting for events");

        // Dedicated writer thread: sends responses as soon as they are ready,
        // without waiting for the next inbound HID event.  This avoids a
        // deadlock where the reader blocks on read_exact while Firefox blocks
        // waiting for our response.
        let mut write_file = file.try_clone().map_err(HidError::Create)?;
        std::thread::spawn(move || {
            while let Some(report) = outgoing_rx.blocking_recv() {
                let event: [u8; UHID_EVENT_SIZE] = InputEvent::Input { data: &report }.into();
                if let Err(e) = write_file.write_all(&event) {
                    tracing::error!("HID write error: {e}");
                    break;
                }
                tracing::trace!("HID tx 64 bytes");
            }
            tracing::debug!("HID writer thread exiting");
        });

        let mut buf = [0u8; UHID_EVENT_SIZE];
        loop {
            file.read_exact(&mut buf)
                .map_err(|e| HidError::Read(e.to_string()))?;

            let event = match OutputEvent::try_from(buf) {
                Ok(e) => e,
                Err(uhid_virt::StreamError::UnknownEventType(t)) => {
                    tracing::debug!("HID unknown event type {t}, ignoring");
                    continue;
                }
                Err(uhid_virt::StreamError::Io(e)) => {
                    return Err(HidError::Read(e.to_string()));
                }
            };

            match event {
                OutputEvent::Output { data } => {
                    // Linux hidraw always prepends a report-ID byte (0x00 when no
                    // explicit report IDs are declared).  Strip it so CTAPHID sees
                    // a clean 64-byte frame starting at the CID.
                    let stripped = data.len() == HID_REPORT_SIZE + 1 && data[0] == 0;
                    let payload: &[u8] = if stripped {
                        &data[1..]
                    } else {
                        &data[..data.len().min(HID_REPORT_SIZE)]
                    };
                    tracing::trace!(
                        raw_len = data.len(),
                        stripped_report_id = stripped,
                        "HID rx"
                    );
                    let mut report = [0u8; HID_REPORT_SIZE];
                    let len = payload.len().min(HID_REPORT_SIZE);
                    report[..len].copy_from_slice(&payload[..len]);
                    if incoming_tx.blocking_send(report).is_err() {
                        break;
                    }
                }
                OutputEvent::Open => tracing::info!("HID device opened by host"),
                OutputEvent::Close => tracing::info!("HID device closed by host"),
                OutputEvent::Start { dev_flags: _ } => tracing::debug!("HID device started"),
                OutputEvent::Stop => {
                    tracing::info!("HID device stopped");
                    break;
                }
                OutputEvent::GetReport { .. } => tracing::debug!("HID GetReport (ignored)"),
                OutputEvent::SetReport { .. } => tracing::debug!("HID SetReport (ignored)"),
            }
        }
        Ok(())
    });

    Ok(HidTransport { incoming_rx, outgoing_tx, task })
}
