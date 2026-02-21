use crate::config::Config;

pub fn check(cfg: &Config) -> anyhow::Result<()> {
    let mut errors: Vec<String> = Vec::new();

    // Check 1: /dev/uhid writable
    match std::fs::OpenOptions::new().write(true).open("/dev/uhid") {
        Ok(_) => {}
        Err(e) => errors.push(format!(
            "cannot open /dev/uhid: {e}\n  \
             → add yourself to the 'input' group: sudo usermod -aG input $USER\n  \
             → or install the udev rule: dist/99-fidorium.rules"
        )),
    }

    // Check 2: TPM device readable
    match std::fs::OpenOptions::new().read(true).open(&cfg.tpm_device) {
        Ok(_) => {}
        Err(e) => errors.push(format!(
            "cannot open {}: {e}\n  \
             → add yourself to the 'tss' group: sudo usermod -aG tss $USER",
            cfg.tpm_device
        )),
    }

    // Check 3: pinentry binary found
    match std::process::Command::new(&cfg.pinentry)
        .arg("--version")
        .output()
    {
        Ok(_) => {}
        Err(e) => errors.push(format!(
            "pinentry binary not found: '{}': {e}\n  \
             → install pinentry: emerge app-crypt/pinentry",
            cfg.pinentry
        )),
    }

    if errors.is_empty() {
        return Ok(());
    }

    for err in &errors {
        eprintln!("ERROR: {err}");
    }
    anyhow::bail!("{} preflight check(s) failed", errors.len());
}
