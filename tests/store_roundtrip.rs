use fidorium::store::{CredentialRecord, CredentialStore};

fn make_record(
    rp_id: &str,
    user_id: &[u8],
    credential_id: &[u8; 32],
    created_at: u64,
) -> CredentialRecord {
    use sha2::{Digest, Sha256};
    let rp_id_hash = Sha256::digest(rp_id.as_bytes()).to_vec();
    CredentialRecord {
        version: 1,
        credential_id: credential_id.to_vec(),
        rp_id: rp_id.to_string(),
        rp_id_hash,
        rp_name: Some(format!("{rp_id} name")),
        user_id: user_id.to_vec(),
        user_name: Some("alice".into()),
        user_display: Some("Alice".into()),
        public_key_x: vec![0u8; 32],
        public_key_y: vec![1u8; 32],
        key_private: vec![2u8; 64],
        key_public: vec![3u8; 64],
        created_at,
        discoverable: true,
    }
}

#[test]
fn test_store_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let key = [0xabu8; 32];
    let cred_id = [0x01u8; 32];

    let record = make_record("example.com", b"user1", &cred_id, 1_700_000_000);

    {
        let mut store = CredentialStore::load(key, dir.path().to_path_buf()).unwrap();
        store.add(record.clone()).unwrap();
    }

    // Reload from disk
    let store = CredentialStore::load(key, dir.path().to_path_buf()).unwrap();
    assert_eq!(store.credential_count(), 1);

    let loaded = store.get_by_id(&cred_id).expect("credential not found");
    assert_eq!(loaded.rp_id, "example.com");
    assert_eq!(loaded.user_id, b"user1");
    assert_eq!(loaded.credential_id, cred_id);
    assert_eq!(loaded.created_at, 1_700_000_000);
    assert!(loaded.discoverable);
}

#[test]
fn test_store_index() {
    let dir = tempfile::tempdir().unwrap();
    let key = [0xcd_u8; 32];

    let cred_id1 = [0x11u8; 32];
    let cred_id2 = [0x22u8; 32];

    let record1 = make_record("rp.example", b"user1", &cred_id1, 1_700_000_000);
    let record2 = make_record("rp.example", b"user2", &cred_id2, 1_700_001_000);

    let mut store = CredentialStore::load(key, dir.path().to_path_buf()).unwrap();
    store.add(record1).unwrap();
    store.add(record2).unwrap();
    assert_eq!(store.credential_count(), 2);

    use sha2::{Digest, Sha256};
    let rp_hash = Sha256::digest("rp.example".as_bytes()).to_vec();
    let results = store.get_by_rp_hash(&rp_hash);
    assert_eq!(results.len(), 2);
    // Most recent first
    assert_eq!(results[0].created_at, 1_700_001_000);
    assert_eq!(results[1].created_at, 1_700_000_000);
}

#[test]
fn test_store_remove() {
    let dir = tempfile::tempdir().unwrap();
    let key = [0xef_u8; 32];
    let cred_id = [0x42u8; 32];

    let record = make_record("remove.example", b"user", &cred_id, 1_000);

    let mut store = CredentialStore::load(key, dir.path().to_path_buf()).unwrap();
    store.add(record).unwrap();
    assert_eq!(store.credential_count(), 1);

    let removed = store.remove(&cred_id).unwrap();
    assert!(removed);
    assert_eq!(store.credential_count(), 0);
    assert!(store.get_by_id(&cred_id).is_none());

    // Removing again returns false
    let removed2 = store.remove(&cred_id).unwrap();
    assert!(!removed2);

    // Disk file should be gone
    let store2 = CredentialStore::load(key, dir.path().to_path_buf()).unwrap();
    assert_eq!(store2.credential_count(), 0);
}

#[test]
fn test_store_wrong_key_skips_file() {
    // Write with key A, reload with key B — AES-GCM auth tag fails so file is skipped.
    let dir = tempfile::tempdir().unwrap();
    let key_a = [0x11u8; 32];
    let key_b = [0x22u8; 32];
    let cred_id = [0x55u8; 32];

    let mut store = CredentialStore::load(key_a, dir.path().to_path_buf()).unwrap();
    store
        .add(make_record("wrong-key.example", b"user", &cred_id, 1_000))
        .unwrap();
    drop(store);

    // Reload with wrong key — corrupt file should be silently skipped
    let store2 = CredentialStore::load(key_b, dir.path().to_path_buf()).unwrap();
    assert_eq!(
        store2.credential_count(),
        0,
        "corrupt (wrong-key) file must be skipped"
    );
}

#[test]
fn test_store_skips_truncated_bin_file() {
    // A .bin file shorter than the 12-byte nonce prefix should be skipped.
    let dir = tempfile::tempdir().unwrap();
    let key = [0xAAu8; 32];

    // Write a too-short .bin file directly
    let short_path = dir.path().join("deadbeef.bin");
    std::fs::write(&short_path, b"short").unwrap();

    let store = CredentialStore::load(key, dir.path().to_path_buf()).unwrap();
    assert_eq!(
        store.credential_count(),
        0,
        "truncated .bin file must be skipped"
    );
}

#[test]
fn test_store_skips_non_bin_files() {
    // Non-.bin files in the credentials directory must be ignored.
    let dir = tempfile::tempdir().unwrap();
    let key = [0xBBu8; 32];

    std::fs::write(dir.path().join("notes.txt"), b"ignore me").unwrap();
    std::fs::write(dir.path().join("backup.json"), b"{}").unwrap();

    let store = CredentialStore::load(key, dir.path().to_path_buf()).unwrap();
    assert_eq!(
        store.credential_count(),
        0,
        "non-.bin files must be ignored"
    );
}

#[test]
fn test_store_corrupt_bin_file_does_not_affect_valid_ones() {
    // A corrupt file is skipped but valid credentials in the same directory still load.
    let dir = tempfile::tempdir().unwrap();
    let key = [0xCCu8; 32];
    let cred_id = [0x77u8; 32];

    let mut store = CredentialStore::load(key, dir.path().to_path_buf()).unwrap();
    store
        .add(make_record("good.example", b"user", &cred_id, 2_000))
        .unwrap();
    drop(store);

    // Drop a garbage .bin file alongside the valid one
    std::fs::write(dir.path().join("garbage.bin"), b"not encrypted").unwrap();

    let store2 = CredentialStore::load(key, dir.path().to_path_buf()).unwrap();
    assert_eq!(
        store2.credential_count(),
        1,
        "valid credential must still load despite corrupt neighbour"
    );
    assert!(store2.get_by_id(&cred_id).is_some());
}
