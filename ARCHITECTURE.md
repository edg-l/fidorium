# Fidorium Architecture

FIDO2/CTAP2 authenticator daemon for Linux, backed by TPM2 hardware.

---

## Table of Contents

1. [Module Tree](#1-module-tree)
2. [TPM2 Key Hierarchy](#2-tpm2-key-hierarchy)
3. [CTAPHID State Machine](#3-ctaphid-state-machine)
4. [CTAP2 Command Flows](#4-ctap2-command-flows)
5. [Credential Storage Layout](#5-credential-storage-layout)
6. [User Presence Flow](#6-user-presence-flow)
7. [Dependencies](#7-dependencies)
8. [Security Considerations](#8-security-considerations)
9. [Risks and Open Questions](#9-risks-and-open-questions)

---

## 1. Module Tree

```
src/
  main.rs                  -- Entrypoint: tokio runtime, CLI args, daemon lifecycle
  config.rs                -- Configuration (XDG paths, TPM device, pinentry binary)
  error.rs                 -- Unified error types (thiserror)

  hid/
    mod.rs                 -- Re-exports
    device.rs              -- UHIDDevice wrapper: create virtual FIDO HID device
    report.rs              -- HID report descriptor constant (usage page 0xF1D0)
    transport.rs           -- Read/write loop: raw 64-byte report I/O on /dev/uhid

  ctaphid/
    mod.rs                 -- Re-exports
    packet.rs              -- Init/Continuation packet parsing and assembly
    channel.rs             -- CID allocation table, channel state, timeouts
    dispatch.rs            -- CTAPHID command router (INIT, CBOR, PING, CANCEL, ERROR, KEEPALIVE)
    types.rs               -- CTAPHID command/error code constants

  ctap2/
    mod.rs                 -- Re-exports, top-level CTAP2 command dispatcher
    make_credential.rs     -- authenticatorMakeCredential (0x01)
    get_assertion.rs       -- authenticatorGetAssertion (0x02)
    get_info.rs            -- authenticatorGetInfo (0x04)
    types.rs               -- CBOR request/response structs (serde + ciborium)
    authenticator_data.rs  -- AuthenticatorData builder (rpIdHash, flags, counter, attCredData)
    attestation.rs         -- Self-attestation (packed format, self-signed)

  tpm/
    mod.rs                 -- Re-exports
    context.rs             -- TpmContext: create/own tss_esapi::Context, Mutex wrapper
    keys.rs                -- Primary key creation, per-credential child key creation, signing
    counter.rs             -- NV counter: define, increment, read
    seal.rs                -- Seal/unseal blobs to TPM key hierarchy (credential store encryption)

  store/
    mod.rs                 -- Re-exports
    credential.rs          -- CredentialRecord: the in-memory type for one credential
    disk.rs                -- Read/write/list/delete credential files on disk
    index.rs               -- In-memory index: rpIdHash -> Vec<CredentialRecord>

  up/
    mod.rs                 -- Re-exports
    pinentry.rs            -- Spawn pinentry, Assuan protocol, confirm/cancel
    prompt.rs              -- Build prompt strings (operation type, RP ID, user name)
```

Total: 23 source files across 6 modules plus root.


## 2. TPM2 Key Hierarchy

### Hierarchy Choice: Owner (Storage)

The Owner hierarchy is correct for user-owned credentials. Endorsement is
manufacturer-locked (unsuitable for creating child keys). Platform is
firmware-only.

### Object Tree

```
Owner Hierarchy (SH)
  |
  +-- Primary Key (ECC P-256, fixedTPM, fixedParent, sensitiveDataOrigin)
  |     Template: deterministic (same template always recreates same primary)
  |     Auth: owner password (empty by default on most Linux TPMs)
  |     NOT persisted to a handle -- recreated on startup from fixed template
  |     Purpose: parent for all credential keys + seal/unseal operations
  |
  +---+-- Child Key: credential_A (ECC P-256, ECDSA-SHA256, sign-only)
  |   |     Created via TPM2_Create under primary
  |   |     Returns: (TPM2B_PRIVATE, TPM2B_PUBLIC) -- the "key blob"
  |   |     Key blob stored on disk inside credential file (encrypted)
  |   |     Loaded into TPM via TPM2_Load when needed for signing
  |   |     Unloaded after use (transient handle)
  |   |
  |   +-- Child Key: credential_B ...
  |   +-- Child Key: credential_C ...
  |
  +-- Seal Object (symmetric, for encrypting credential metadata files)
        Created once, blob stored at ~/.local/share/fidorium/seal_key.blob
        Used to seal/unseal the AES-256-GCM key that encrypts credential files
        Bound to PCR policy (optional, configurable PCR selection)

NV Storage (Owner-authorized):
  +-- NV Index 0x01800100: Global signature counter (NV_Counter type)
        Attributes: AUTHWRITE | AUTHREAD | NT=COUNTER
        Size: 8 bytes (monotonic, TPM2_NV_Increment)
        Single counter for all credentials (not per-credential)
```

### Why a Single Global Counter (Not Per-Credential)

TPM2 NV storage is limited (typically ~1500-2000 bytes total on most TPMs,
with a handful of available NV indices). Allocating one NV counter per
credential would exhaust NV space after approximately 10-20 credentials.

**Design**: One global NV counter. Each GetAssertion call:
1. Calls `TPM2_NV_Increment` on the global counter
2. Reads the new counter value via `TPM2_NV_Read`
3. Embeds the value in the authenticator data's 4-byte signCount field

This is monotonically increasing across all credentials, which is what
relying parties need to detect cloning. The spec requires only that the
counter "is incremented for every assertion generated" -- it need not be
per-credential.

### Key Blob vs. Persistent Handle

We use **key blobs on disk** (the TPM2B_PRIVATE + TPM2B_PUBLIC pair returned
by TPM2_Create), not persistent handles. Reasons:

- Persistent handle slots are limited (~7 on many TPMs)
- Key blobs are encrypted by the TPM's storage hierarchy -- they are useless
  without access to the same TPM
- Blobs can be loaded transiently when needed and flushed immediately after
- This allows unlimited credentials

### Primary Key Recreation

The primary key uses a **deterministic template** (fixed parameters, no
random unique field). This means `TPM2_CreatePrimary` with the same template
always produces the same key on the same TPM. We recreate it on every daemon
startup rather than persisting it, saving a persistent handle slot.

Template parameters:
- Algorithm: `TPM2_ALG_ECC`
- Curve: `TPM2_ECC_NIST_P256`
- Scheme: `TPM2_ALG_NULL` (parent does not sign; children do)
- Attributes: `fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | decrypt`
- Auth value: empty (or configurable)
- Unique field: zero-filled (deterministic)


## 3. CTAPHID State Machine

### HID Report Descriptor

64-byte reports, FIDO usage page:

```
0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance, 0xF1D0)
0x09, 0x01,         // Usage (CTAP HID)
0xA1, 0x01,         // Collection (Application)
0x09, 0x20,         //   Usage (Data In)
0x15, 0x00,         //   Logical Minimum (0)
0x26, 0xFF, 0x00,   //   Logical Maximum (255)
0x75, 0x08,         //   Report Size (8 bits)
0x95, 0x40,         //   Report Count (64)
0x81, 0x02,         //   Input (Data, Variable, Absolute)
0x09, 0x21,         //   Usage (Data Out)
0x15, 0x00,         //   Logical Minimum (0)
0x26, 0xFF, 0x00,   //   Logical Maximum (255)
0x75, 0x08,         //   Report Size (8 bits)
0x95, 0x40,         //   Report Count (64)
0x91, 0x02,         //   Output (Data, Variable, Absolute)
0xC0,               // End Collection
```

### Packet Format

**Initialization packet** (first packet of a message):
```
Offset  Size  Field
0       4     CID (Channel ID)
4       1     CMD (command byte, bit 7 = 1)
5       2     BCNT (payload length, big-endian)
7       57    DATA (first chunk of payload, zero-padded to 57)
---
Total: 64 bytes
```

**Continuation packet** (subsequent packets):
```
Offset  Size  Field
0       4     CID (same as init packet)
4       1     SEQ (sequence number 0..127, bit 7 = 0)
5       59    DATA (next chunk of payload, zero-padded to 59)
---
Total: 64 bytes
```

### Channel State Machine

```
                      +-----------+
              INIT    |           |   timeout
     +--------------->|   IDLE    |<----------+
     |   (broadcast)  |           |           |
     |                +-----+-----+           |
     |                      |                 |
     |               INIT pkt (CMD)           |
     |                      |                 |
     |                      v                 |
     |                +-----+-----+           |
     |                |           |  CANCEL   |
     |                |  BUSY     +---------->+
     |                | (assembling|          |
     |                |  message)  |          |
     |                +-----+-----+          |
     |                      |                |
     |               all CONT pkts           |
     |               received                |
     |                      |                |
     |                      v                |
     |                +-----+-----+          |
     |                | PROCESSING|  CANCEL  |
     |                | (CTAP2 cmd+--------->+
     |                |  running) |          |
     |                +-----+-----+          |
     |                      |                |
     |               response ready          |
     |                      |                |
     |                      v                |
     |                +-----+-----+          |
     |                | RESPONDING|          |
     |                | (sending  |          |
     +<---------------+  packets) |          |
          done        +-----------+          |
                                             |
          30s inactivity on any state -------+
```

### CID Allocation

- Broadcast CID: `0xFFFFFFFF` -- used only for `CTAPHID_INIT`
- On receiving `CTAPHID_INIT` on broadcast, allocate a random non-zero,
  non-broadcast 4-byte CID
- Store in `HashMap<u32, ChannelState>`
- Maximum concurrent channels: 8 (reject with `ERR_CHANNEL_BUSY` after)
- Channel timeout: 30 seconds of inactivity -- reclaim the CID

### CTAPHID Command Dispatch

| Command          | Code | Direction     | Description                        |
|------------------|------|---------------|------------------------------------|
| CTAPHID_PING     | 0x01 | Host <-> Auth | Echo: return same data             |
| CTAPHID_MSG      | 0x03 | Host -> Auth  | U2F/CTAP1 (NOT IMPLEMENTED in MVP) |
| CTAPHID_LOCK     | 0x04 | Host -> Auth  | NOT IMPLEMENTED in MVP             |
| CTAPHID_INIT     | 0x06 | Host <-> Auth | Channel allocation                 |
| CTAPHID_WINK     | 0x08 | Host -> Auth  | No-op (respond OK)                 |
| CTAPHID_CBOR     | 0x10 | Host <-> Auth | CTAP2 CBOR command                 |
| CTAPHID_CANCEL   | 0x11 | Host -> Auth  | Cancel pending operation            |
| CTAPHID_KEEPALIVE| 0x3B | Auth -> Host  | Status during UP wait              |
| CTAPHID_ERROR    | 0x3F | Auth -> Host  | Error notification                 |

CTAPHID_INIT response (17 bytes):
```
Offset  Size  Field
0       8     Nonce (echoed from request)
8       4     Allocated CID
12      1     Protocol version (= 2 for CTAP2)
13      1     Device major version
14      1     Device minor version
15      1     Device build version
16      1     Capabilities flags:
                bit 0: WINK
                bit 2: CBOR (= 1)
                bit 3: NMSG (= 1, no CTAP1 MSG support)
```

### Concurrency Model

The daemon runs a single-threaded event loop for HID I/O. CTAP2 command
processing is dispatched to a `tokio::spawn_blocking` task (because TPM
operations are blocking). During processing:

1. The HID read loop continues running
2. KEEPALIVE packets (status = `PROCESSING` or `UPNEEDED`) are sent every
   100ms on the active channel while a command is in progress
3. CANCEL on the active channel sets an `AtomicBool` cancellation flag that
   the command task checks
4. Messages on other channels are queued (up to 1 pending message per channel)


## 4. CTAP2 Command Flows

### authenticatorMakeCredential (0x01)

```
Input CBOR map:
  0x01: clientDataHash    [32 bytes, required]
  0x02: rp                {id: String, name: Option<String>}
  0x03: user              {id: Bytes, name: Option<String>, displayName: Option<String>}
  0x04: pubKeyCredParams  [{alg: i64, type: "public-key"}, ...]
  0x05: excludeList       [Option<Vec<{type, id}>>]
  0x06: extensions        [Option<Map>]
  0x07: options           [Option<{rk: bool, uv: bool}>]

Flow:
  1. PARSE input CBOR into MakeCredentialRequest struct
     - Reject if any required field missing -> CTAP2_ERR_MISSING_PARAMETER

  2. VALIDATE pubKeyCredParams
     - Scan list for alg = -7 (ES256 / ECDSA-SHA256-P256)
     - If ES256 not found -> CTAP2_ERR_UNSUPPORTED_ALGORITHM

  3. CHECK excludeList
     - For each descriptor in excludeList:
       - Look up credential by ID in store
       - If found and rpId matches:
         - Request UP (user must confirm "you already have a credential for X")
         - Return CTAP2_ERR_CREDENTIAL_EXCLUDED

  4. ENFORCE USER PRESENCE *** CRITICAL SECURITY ***
     - Spawn pinentry with prompt:
       "Register new credential for: {rp.name} ({rp.id})"
     - Start sending KEEPALIVE(status=UPNEEDED) packets every 100ms
     - Block until user confirms or:
       - User cancels in pinentry -> CTAP2_ERR_OPERATION_DENIED
       - CTAPHID_CANCEL received -> CTAP2_ERR_KEEPALIVE_CANCEL
       - Timeout (30 seconds) -> CTAP2_ERR_USER_ACTION_TIMEOUT
     - Stop KEEPALIVE packets
     - Set UP=1 flag

  5. CREATE KEY ON TPM
     - TPM2_Create under primary key:
       - Type: ECC NIST P-256, scheme ECDSA-SHA256
       - Attributes: fixedTPM | fixedParent | sensitiveDataOrigin |
                     userWithAuth | sign | noDA
     - Receive: (tpm2b_private, tpm2b_public)
     - Load key: TPM2_Load -> get transient handle
     - Read public key point (x, y) from tpm2b_public
     - Flush transient handle

  6. GENERATE CREDENTIAL ID
     - credential_id = random 32 bytes (from /dev/urandom via rand crate)
     - This is an opaque identifier; the key blob is stored on disk,
       NOT embedded in the credential ID

  7. STORE CREDENTIAL (if rk=true OR always for passkey support)
     - Build CredentialRecord (see Section 5)
     - Encrypt and write to disk
     - Index by rpIdHash for later lookup

  8. BUILD AUTHENTICATOR DATA
     - rpIdHash:    SHA-256(rp.id)                              [32 bytes]
     - flags:       UP=1, AT=1, UV=0, BE=0, BS=0, ED=0         [1 byte = 0x41]
     - signCount:   0 (new credential, counter starts at 0)     [4 bytes, big-endian]
     - aaguid:      fidorium's AAGUID                           [16 bytes]
     - credIdLen:   length of credential_id                     [2 bytes, big-endian]
     - credId:      credential_id                               [32 bytes]
     - credPubKey:  COSE_Key (EC2, P-256, x, y)                [~77 bytes CBOR]

  9. BUILD ATTESTATION OBJECT
     - fmt:     "packed"
     - attStmt: self-attestation:
       - alg: -7 (ES256)
       - sig: ECDSA signature over (authData || clientDataHash)
              signed by the credential key itself (self-attestation)
     - authData: the bytes from step 8

  10. ENCODE response CBOR map:
      0x01: fmt       (String)
      0x02: authData  (Bytes)
      0x03: attStmt   (Map)

  11. RETURN via CTAPHID_CBOR response
      - Status byte: 0x00 (CTAP2_OK) prepended to CBOR
```

### authenticatorGetAssertion (0x02)

```
Input CBOR map:
  0x01: rpId              [String, required]
  0x02: clientDataHash    [32 bytes, required]
  0x03: allowList         [Option<Vec<{type, id}>>]
  0x04: extensions        [Option<Map>]
  0x05: options           [Option<{up: bool, uv: bool}>]

Flow:
  1. PARSE input CBOR into GetAssertionRequest struct
     - Reject if any required field missing -> CTAP2_ERR_MISSING_PARAMETER

  2. LOCATE CREDENTIALS
     - Compute rpIdHash = SHA-256(rpId)
     - If allowList is present and non-empty:
       - For each descriptor in allowList:
         - Look up credential by credential_id in store
         - If found and rpIdHash matches, add to candidates
       - If no candidates -> CTAP2_ERR_NO_CREDENTIALS
     - Else (discoverable/resident key flow):
       - Look up all credentials where stored rpIdHash == computed rpIdHash
       - If none -> CTAP2_ERR_NO_CREDENTIALS

  3. SELECT CREDENTIAL
     - If exactly 1 candidate: use it
     - If multiple candidates:
       - For MVP: use the most recently created one
       - (Future: authenticatorGetNextAssertion support)
       - Set numberOfCredentials in response

  4. ENFORCE USER PRESENCE *** CRITICAL SECURITY ***
     - Spawn pinentry with prompt:
       "Sign in to: {rpId}\nCredential: {user.name or user.displayName}"
     - Start sending KEEPALIVE(status=UPNEEDED) packets every 100ms
     - Block until user confirms or:
       - User cancels -> CTAP2_ERR_OPERATION_DENIED
       - CTAPHID_CANCEL -> CTAP2_ERR_KEEPALIVE_CANCEL
       - Timeout (30s) -> CTAP2_ERR_USER_ACTION_TIMEOUT
     - Stop KEEPALIVE
     - Set UP=1 flag

  5. INCREMENT COUNTER (TPM NV)
     - TPM2_NV_Increment on global counter NV index
     - TPM2_NV_Read to get new value
     - Truncate to u32 for authenticator data (lower 4 bytes)

  6. LOAD KEY AND SIGN
     - Load credential's key blob: TPM2_Load(primary, private, public)
     - Build authenticator data:
       - rpIdHash                              [32 bytes]
       - flags: UP=1, UV=0                     [1 byte = 0x01]
       - signCount: counter value              [4 bytes, big-endian]
     - Compute signData = authData || clientDataHash
     - TPM2_Sign(key_handle, SHA-256(signData), scheme=ECDSA-SHA256)
     - Convert TPM signature (r, s) to DER-encoded ECDSA signature
     - Flush transient key handle

  7. ENCODE response CBOR map:
     0x01: credential    {type: "public-key", id: credential_id}
     0x02: authData      (Bytes)
     0x03: signature     (Bytes, DER-encoded)
     0x04: user          {id, name, displayName} (only if resident key)
     0x05: numberOfCredentials (only if > 1 candidate)

  8. RETURN via CTAPHID_CBOR response
     - Status byte: 0x00 (CTAP2_OK) prepended to CBOR
```

### authenticatorGetInfo (0x04)

```
No input parameters.

Static response CBOR map:
  0x01: versions         ["FIDO_2_0"]
  0x02: extensions       []  (none for MVP)
  0x03: aaguid           <16-byte fidorium AAGUID>
  0x04: options          {
                           "rk": true,      // resident key support
                           "up": true,      // user presence enforced
                           "uv": false,     // no user verification (no PIN)
                           "plat": false,   // not a platform authenticator
                         }
  0x05: maxMsgSize       1200
  0x06: pinProtocols     []  (no PIN protocol for MVP)
```


## 5. Credential Storage Layout

### Location

```
~/.local/share/fidorium/
  seal_key.blob              -- TPM-sealed AES-256 key material (TPM2B_PRIVATE + TPM2B_PUBLIC)
  counter_initialized        -- Marker file (empty); signals NV counter is defined
  credentials/
    {credential_id_hex}.bin  -- One file per credential, encrypted
```

### Credential File Format

Each `.bin` file is an encrypted blob. The plaintext (before encryption) is
CBOR-encoded with the following schema:

```
CBOR Map {
  "version":        1,                      // u8, schema version
  "credential_id":  Bytes(32),              // the credential ID
  "rp_id":          String,                 // e.g., "github.com"
  "rp_id_hash":     Bytes(32),             // SHA-256(rp_id), precomputed for lookup
  "rp_name":        Option<String>,         // display name, e.g., "GitHub"
  "user_id":        Bytes,                  // opaque user handle from RP
  "user_name":      Option<String>,         // e.g., "alice@example.com"
  "user_display":   Option<String>,         // e.g., "Alice"
  "public_key_x":   Bytes(32),             // EC P-256 public key X coordinate
  "public_key_y":   Bytes(32),             // EC P-256 public key Y coordinate
  "key_private":    Bytes,                 // TPM2B_PRIVATE marshaled
  "key_public":     Bytes,                 // TPM2B_PUBLIC marshaled
  "created_at":     u64,                   // Unix timestamp
  "discoverable":   bool,                  // true if created with rk=true
}
```

### Encryption Scheme

**Method**: AES-256-GCM (via `aes-gcm` crate, software crypto).

**Key derivation**:
1. On first run, create a random 32-byte AES key
2. Seal it to the TPM primary key via `TPM2_Create` with:
   - Type: KEYEDHASH (HMAC key used as opaque sealed data)
   - Attributes: fixedTPM | fixedParent
   - Optional: PCR policy (seal to specific PCR values)
3. Store the sealed blob (TPM2B_PRIVATE + TPM2B_PUBLIC) as `seal_key.blob`
4. On startup, unseal: `TPM2_Load` + `TPM2_Unseal` -> recover 32-byte AES key
5. Hold AES key in memory for the daemon's lifetime

**Per-file encryption**:
- Generate random 12-byte nonce per credential file
- Prepend nonce to ciphertext: `[nonce (12 bytes)][ciphertext][tag (16 bytes)]`
- File = `nonce || AES-256-GCM(key, nonce, plaintext_cbor)`

### Index

On startup, read all `.bin` files in `credentials/`, decrypt, deserialize
the CBOR, and build an in-memory `HashMap<[u8; 32], Vec<CredentialRecord>>`
keyed by `rp_id_hash`. This allows O(1) lookup for both:
- allowList-based lookup (by credential_id via a second `HashMap<[u8; 32], CredentialRecord>`)
- Discoverable credential lookup (by rp_id_hash)


## 6. User Presence Flow

### Pinentry Integration

The `pinentry` crate (v0.8.0) wraps the Assuan protocol. The standard
`pinentry-gtk-2`, `pinentry-qt`, or `pinentry-curses` binary is spawned.

```
Sequence:

  Daemon                          pinentry
    |                                |
    |--- spawn pinentry binary ----->|
    |                                |
    |<-- "OK Pleased to meet you" --|  (Assuan greeting)
    |                                |
    |-- SETTITLE fidorium ---------->|
    |<-- OK -------------------------|
    |                                |
    |-- SETDESC {prompt_text} ------>|
    |<-- OK -------------------------|
    |                                |
    |-- SETPROMPT Confirm ---------->|
    |<-- OK -------------------------|
    |                                |
    |-- CONFIRM -------------------->|
    |                                |  (dialog appears, user sees prompt)
    |         ... waiting ...        |
    |<-- OK -------------------------|  (user clicked OK)
    |   or                           |
    |<-- ERR 83886179 Not confirmed -|  (user clicked Cancel)
    |                                |
    |-- BYE ----------------------->|
    |                                |  (pinentry exits)
```

### Prompt Text

For MakeCredential:
```
Register new passkey

Site: {rp_name} ({rp_id})
Account: {user_display_name}

Press OK to create a credential, or Cancel to deny.
```

For GetAssertion:
```
Sign in with passkey

Site: {rp_id}
Account: {user_name or user_display_name}

Press OK to sign in, or Cancel to deny.
```

### Timeout and KEEPALIVE

While waiting for pinentry:

1. A `tokio::spawn` task sends KEEPALIVE packets every 100ms on the
   active CTAPHID channel with status byte:
   - `0x02` = UPNEEDED (user presence needed)

2. The pinentry wait has a 30-second timeout. If the user does not
   respond within 30 seconds, the pinentry process is killed and
   CTAP2_ERR_USER_ACTION_TIMEOUT is returned.

3. If CTAPHID_CANCEL is received during the wait, the daemon:
   - Kills the pinentry process
   - Returns CTAP2_ERR_KEEPALIVE_CANCEL

4. The UP enforcement is unconditional. There is no code path that
   skips pinentry. The `options.up` field from the client is checked,
   but per CTAP2 spec, UP is always enforced for MakeCredential and
   for GetAssertion when up is not explicitly false (and even then,
   the authenticator MAY enforce it -- we always do).


## 7. Dependencies

```toml
[dependencies]
# TPM2 interface
tss-esapi = "7.6"                    # latest stable: 7.6.0 (8.0.0-alpha.1 exists, skip)

# Virtual HID device
uhid-virt = "0.0.8"                  # latest stable: 0.0.8

# CBOR
ciborium = "0.2"                     # latest stable: 0.2.2
serde = { version = "1", features = ["derive"] }  # latest stable: 1.0.228

# Async runtime
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time", "signal", "io-util"] }  # latest stable: 1.49.0

# User presence (pinentry/Assuan)
pinentry = "0.8"                     # latest stable: 0.8.0

# Crypto (software, for non-TPM operations)
sha2 = "0.10"                        # latest stable: 0.10.9 (0.11.0-rc.5 not yet stable)
rand = "0.8"                         # pinned to 0.8 for RustCrypto ecosystem compat:
                                     # p256 0.13 and aes-gcm 0.10 depend on rand_core 0.6.x
                                     # (rand 0.8's ecosystem). rand 0.9+ bumps rand_core to
                                     # 0.9.x, causing duplicate rand_core versions.
                                     # NOTE: rand 0.10.0 is now stable (Feb 2026); upgrade
                                     # all three (rand/p256/aes-gcm) together when
                                     # RustCrypto 0.14 stabilises.
aes-gcm = "0.10"                     # latest stable: 0.10.3

# ECDSA signature encoding (DER conversion from TPM raw r,s)
p256 = "0.13"                        # latest stable: 0.13.2 (0.14.0-rc.7 not yet stable)
ecdsa = { version = "0.16", features = ["der"] }  # latest stable: 0.16.9

# COSE key encoding
coset = "0.4"                        # latest stable: 0.4.1 (was "0.3" in original draft — UPDATED)

# Error handling
thiserror = "2.0"                    # latest stable: 2.0.18
anyhow = "1"                         # latest stable: 1.0.102

# Logging
tracing = "0.1"                      # latest stable: 0.1.44
tracing-subscriber = { version = "0.3", features = ["env-filter"] }  # latest stable: 0.3.22

# CLI
clap = { version = "4", features = ["derive"] }  # latest stable: 4.5.60

# XDG directories
directories = "6"                    # latest stable: 6.0.0
```

### Dependency Rationale

- **tss-esapi 7.6**: Latest stable (7.6.0). 8.0.0-alpha.1 exists but is
  pre-release; do not use. Requires system `tpm2-tss` libraries (ESAPI,
  TCTI). On Gentoo: `app-crypt/tpm2-tss`.
- **uhid-virt**: Synchronous API. We wrap it in `spawn_blocking`. No async
  uhid crate is mature enough.
- **ciborium over serde_cbor**: serde_cbor is unmaintained. ciborium is the
  maintained successor with proper CTAP2 CBOR canonical encoding support.
- **sha2 0.10 (not 0.11-rc)**: Stable release (0.10.9). 0.11.0-rc.5 is
  not yet stable. We only need SHA-256 for rpIdHash.
- **rand 0.8** (pinned): `rand 0.10.0` is now stable (released Feb 2026),
  but the RustCrypto crates we use (`p256 0.13`, `aes-gcm 0.10`) depend on
  `rand_core 0.6.x` (rand 0.8's ecosystem). Upgrading rand to 0.9+ without
  also upgrading those crates adds a duplicate `rand_core` in the dep tree.
  Upgrade all three together once `p256 0.14` and `aes-gcm 0.11` stabilise.
- **coset 0.4**: COSE_Key encoding (updated from 0.3 to latest stable 0.4.1).
  We could hand-encode CBOR, but coset provides correct COSE key structure
  encoding. Check for API changes at the 0.3→0.4 boundary before using.
- **p256 + ecdsa**: Only for converting TPM's raw (r, s) signature into
  DER-encoded ECDSA-SHA256 format that WebAuthn expects. We do NOT use
  these for key generation or signing -- the TPM does that.
- **pinentry 0.8**: Latest stable (0.8.0). Wraps the Assuan protocol.
  Handles spawning the system pinentry binary, sending commands, and
  parsing responses.
- **directories**: XDG base directory support for
  `~/.local/share/fidorium/`.


## 8. Security Considerations

### TPM Context Thread Safety

`tss_esapi::Context` requires `&mut self` for all operations, so it is
not `Send` or `Sync` by default. Our design:

```
struct TpmContext {
    ctx: Mutex<tss_esapi::Context>,
}
```

All TPM operations go through `tokio::task::spawn_blocking` with the mutex:
```rust
let tpm = tpm_ctx.clone();
tokio::task::spawn_blocking(move || {
    let mut ctx = tpm.ctx.lock().unwrap();
    ctx.create(...)?;
    // ...
}).await?
```

This serializes all TPM access, which is correct: the TPM2 resource manager
(`/dev/tpmrm0`) handles multiplexing at the kernel level, but the ESAPI
context itself is not thread-safe.

### Credential ID Format

The credential ID is an opaque random 32-byte value. It does NOT contain:
- Key material
- RP ID
- Any information about the key

This is a deliberate security choice. In tpm-fido, the credential ID
contained the key handle (TPM2B_PRIVATE + TPM2B_PUBLIC concatenated), which
meant the key blob was sent to the relying party and stored in the clear.
Our design stores key blobs locally, encrypted.

The credential ID is used only as a lookup key into the local credential
store. If the store is deleted, credentials are unrecoverable (by design --
the key blobs are encrypted and sealed to this TPM).

### allowList Handling

For GetAssertion:
1. If `allowList` is present: iterate the list, look up each credential_id
   in the local store. Return matches for this rpId.
2. If `allowList` is absent: this is a discoverable credential (passkey)
   flow. Look up all credentials for the given rpIdHash.

An attacker cannot use allowList to probe for credentials on other rpIds
because we verify rpIdHash matches before considering a credential as a
candidate.

### AAGUID

We generate a fixed AAGUID for fidorium. This is a 16-byte identifier
that is the same for all instances of this authenticator software. It is
NOT a secret.

Proposed AAGUID: Generate once using `uuidgen` and hardcode.

```
// Example (replace with actual generated value before release):
const AAGUID: [u8; 16] = [
    0xf1, 0xd0, 0x21, 0x01,  // "fido" + version hint
    0x00, 0x00,               // reserved
    0x40, 0x00,               // UUID version 4 marker
    0x80, 0x00,               // UUID variant marker
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01  // serial
];
```

### User Presence Enforcement (tpm-fido Fix 1)

The critical bug in tpm-fido was that UP could be silently skipped.
Our mitigation is architectural:

- The `user_presence()` function is the ONLY path to set `flags.UP = 1`
- `user_presence()` ALWAYS spawns pinentry and blocks for user input
- There is no boolean flag, no config option, no code path that sets UP
  without going through pinentry
- MakeCredential and GetAssertion both call the same `user_presence()`
  function before any signing occurs
- The signing functions (`tpm::keys::sign`) require a `UserPresenceProof`
  token type that can only be constructed by `user_presence()` -- this
  is a compile-time guarantee via Rust's type system

```rust
/// Proof that user presence was verified. Cannot be constructed
/// outside the `up` module.
pub struct UserPresenceProof {
    _private: (),  // prevents construction outside this module
}

/// The ONLY way to obtain a UserPresenceProof.
pub async fn require_user_presence(
    prompt: &UpPrompt,
    keepalive_tx: &Sender<KeepaliveStatus>,
    cancel: &AtomicBool,
) -> Result<UserPresenceProof, Ctap2Error> {
    // ... pinentry logic, NO bypass possible ...
    Ok(UserPresenceProof { _private: () })
}

/// Signing requires proof of UP.
pub fn sign(
    ctx: &mut tss_esapi::Context,
    key: &LoadedKey,
    data: &[u8],
    _up: &UserPresenceProof,  // must be provided, cannot be faked
) -> Result<Vec<u8>, TpmError> {
    // ...
}
```

### Monotonic Counters (tpm-fido Fix 2)

tpm-fido used a software counter (a file on disk), which could be rolled
back by restoring the file from a backup. Our counter lives in TPM2 NV
storage, which:

- Cannot be decremented (hardware enforced)
- Survives reboots (non-volatile)
- Cannot be rolled back without physical TPM reset

NV counter setup (first run):
```
TPM2_NV_DefineSpace(
    auth_handle: OWNER,
    auth: empty,
    nv_public: {
        nv_index:    0x01800100,
        name_alg:    SHA256,
        attributes:  AUTHWRITE | AUTHREAD | NT_COUNTER,
        auth_policy: empty,
        data_size:   8,
    }
)
```

### Resident Key Support (tpm-fido Fix 3)

tpm-fido did not support resident keys / passkeys. Our credential store
(Section 5) supports discoverable credentials by storing full credential
metadata on disk, indexed by rpIdHash. When a GetAssertion arrives with
an empty allowList, we perform a resident key lookup.


## 9. Risks and Open Questions

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| TPM NV space exhaustion (counter allocation fails on a TPM with full NV) | High | Check available NV space on startup; clear error message if unavailable |
| /dev/uhid requires root or specific permissions | High | Document udev rule: `KERNEL=="uhid", GROUP="plugdev", MODE="0660"` |
| tss-esapi 7.6 API instability (8.0.0-alpha exists) | Medium | Pin to 7.6; do not upgrade to 8.x until stable |
| pinentry not installed or not in PATH | Medium | Check on startup, exit with clear error |
| Browser does not detect UHID device | Medium | Test with Chrome and Firefox; may need specific HID report descriptor tuning |
| Large credential store (1000+ passkeys) slows startup | Low | Lazy loading or memory-mapped index in future; unlikely for personal use |
| Concurrent daemon instances corrupt credential store | Medium | PID file or flock() on data directory |

### Open Questions

1. **PCR binding policy**: Which PCRs to bind the seal key to? PCR7
   (SecureBoot state) is common, but changes on kernel updates. Should
   this be configurable? **Recommendation**: default to no PCR binding,
   with a `--pcr-bind=7` CLI flag for users who want it.

2. **CTAP2.1+ features**: Should we plan for authenticatorGetNextAssertion
   (for multiple credentials per RP)? **Recommendation**: yes, structure
   GetAssertion to return a "pending assertions" list internally, but only
   implement GetNextAssertion in a future phase.

3. **U2F/CTAP1 backward compatibility**: Some sites still send CTAP1
   commands via CTAPHID_MSG. Should we implement a minimal CTAP1 shim?
   **Recommendation**: defer. Return CTAPHID_ERROR with ERR_INVALID_CMD
   for CTAPHID_MSG. Revisit if real-world breakage is observed.

4. **Attestation format**: Self-attestation ("packed" with self-signed)
   is the simplest. Some RPs may want "none" attestation. Should we
   support both? **Recommendation**: default to "packed" self-attestation.
   Add "none" support (trivial: just omit attStmt fields) if requested.

5. **Multiple TPM devices**: Should we support selecting a TPM device
   other than `/dev/tpmrm0`? **Recommendation**: yes, via `--tpm-device`
   CLI flag, defaulting to `/dev/tpmrm0`.

6. **Daemon lifecycle**: systemd user service? Background process?
   **Recommendation**: run in foreground, provide a systemd user service
   unit file. No daemonization logic in the binary itself.

7. **NV index collision**: The hardcoded NV index `0x01800100` could
   conflict with other applications. **Recommendation**: make it
   configurable via `--nv-index`, default to `0x01800100` which is in
   the owner-defined range (`0x01800000-0x01BFFFFF`).

---

## Implementation Phases

### Phase 1: Skeleton + HID (Complexity: Medium)
- [ ] Project structure, all module files with stub types
- [ ] HID report descriptor + UHID device creation
- [ ] CTAPHID packet parser (init/cont) + channel allocator
- [ ] CTAPHID_INIT, PING, ERROR handling
- [ ] Integration test: send INIT from host, get CID back

### Phase 2: TPM Foundation (Complexity: High)
- [ ] TpmContext wrapper with Mutex
- [ ] Primary key creation (deterministic template under Owner)
- [ ] Child ECC key creation + signing
- [ ] NV counter: define, increment, read
- [ ] Seal/unseal for credential store key
- [ ] Unit tests with swtpm (software TPM emulator)

### Phase 3: Credential Store (Complexity: Medium)
- [ ] CredentialRecord type + CBOR serialization
- [ ] AES-256-GCM encryption/decryption with TPM-sealed key
- [ ] Disk I/O: write, read, list, delete credential files
- [ ] In-memory index (rpIdHash + credential_id lookups)

### Phase 4: CTAP2 Commands (Complexity: High)
- [ ] authenticatorGetInfo (static response)
- [ ] authenticatorMakeCredential (full flow with UP)
- [ ] authenticatorGetAssertion (full flow with counter)
- [ ] User presence via pinentry (with timeout, cancel, KEEPALIVE)
- [ ] UserPresenceProof type-safety pattern
- [ ] CBOR encoding/decoding for all request/response types

### Phase 5: Integration + Hardening (Complexity: Medium)
- [ ] End-to-end test with Chrome and Firefox
- [ ] PID file / flock for single-instance enforcement
- [ ] CLI (clap): --tpm-device, --nv-index, --pcr-bind, --pinentry-binary
- [ ] systemd user service unit file
- [ ] udev rule documentation
- [ ] Startup diagnostics (TPM accessible? UHID accessible? pinentry found?)
