# fidorium

A FIDO2/CTAP2 authenticator daemon for Linux. It presents as a virtual USB HID authenticator via `/dev/uhid`, backed by TPM 2.0 for key storage. Supports passkey registration (MakeCredential) and authentication (GetAssertion). User presence is confirmed via a pinentry popup.

## Requirements

- Linux
- TPM 2.0 accessible at `/dev/tpmrm0` (resource manager device)
- `/dev/uhid` for virtual HID device creation
- `pinentry` binary in PATH (e.g. `pinentry-qt6`, `pinentry-gnome3`, `pinentry-curses`)
- `libtss2-esys` / `tpm2-tss` system library (Gentoo: `app-crypt/tpm2-tss`)
- Rust toolchain

## Permissions

**TPM device** — add your user to the `tss` group:

```bash
sudo usermod -aG tss $USER
```

**UHID device** — add your user to the `input` group, or add a udev rule:

```
KERNEL=="uhid", GROUP="input", MODE="0660"
```

Log out and back in after group changes.

## Build

```bash
cargo build
# or for a release build:
cargo build --release
```

## Run

```bash
# Basic run
cargo run

# With GUI pinentry and debug logging
cargo run -- -vv --pinentry pinentry-qt6

# Wipe all stored credentials and reset the TPM NV counter, then exit
cargo run -- --wipe
```

The daemon runs in the foreground. Kill it with Ctrl-C to stop.

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-v`, `--verbose` | off | Increase log verbosity; use `-vv` for debug output |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path |
| `--nv-index` | `0x01800100` | TPM NV counter index (hex) |
| `--pinentry` | `pinentry` | pinentry binary name or path |
| `--wipe` | — | Delete all credentials and reset NV counter, then exit |

## Data Storage

| Path | Contents |
|------|----------|
| `~/.local/share/fidorium/credentials/` | Encrypted credential blobs |
| `~/.local/share/fidorium/seal_key.blob` | TPM-sealed AES encryption key |

Credential files are AES-256-GCM encrypted with a key sealed to the TPM. They are useless without access to the same TPM.

## How It Works

1. At startup, fidorium creates a virtual FIDO2 HID device via `/dev/uhid`.
2. **Registration (MakeCredential):** Generates a P-256 key under the TPM owner hierarchy, encrypts the key blob with a TPM-sealed AES key, stores it to disk, and shows a pinentry confirmation dialog for user presence.
3. **Authentication (GetAssertion):** Loads the credential blob, increments the monotonic TPM NV counter, signs the assertion inside the TPM, and shows a pinentry confirmation dialog for user presence.

Security properties:

- Key material never leaves the TPM unencrypted.
- The monotonic NV counter in TPM storage prevents cloning-detection rollback.
- User presence confirmation is enforced at the type level (`UserPresenceProof`) — the signing path cannot be reached without pinentry approval.
- No PIN or UV — user presence only (pinentry serves as the "tap to confirm" equivalent).

## Testing

```bash
# Run all tests (TPM tests skip automatically if no TPM is available)
cargo test

# Run TPM tests against a real device
FIDORIUM_TEST_TCTI=device:/dev/tpmrm0 cargo test
```

Test coverage:

- `tests/store_roundtrip.rs` — credential store read/write/remove
- `tests/tpm_smoke.rs` — TPM key creation, signing, NV counter, seal/unseal
- `tests/ctaphid_init.rs` — CTAPHID INIT/PING/error handling
