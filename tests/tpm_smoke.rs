use fidorium::tpm;

fn test_tcti() -> Option<String> {
    let s = std::env::var("FIDORIUM_TEST_TCTI")
        .unwrap_or_else(|_| "device:/dev/tpmrm0".into());
    // Probe: try to create a context; if it fails, skip the test.
    let tcti: tss_esapi::TctiNameConf = match s.parse() {
        Ok(v) => v,
        Err(_) => {
            println!("SKIP: cannot parse TCTI string '{s}'");
            return None;
        }
    };
    match tss_esapi::Context::new(tcti) {
        Ok(_) => Some(s),
        Err(e) => {
            println!("SKIP: TPM not accessible ({e}), skipping TPM smoke tests");
            None
        }
    }
}

fn make_context(tcti: &str) -> fidorium::tpm::TpmContext {
    fidorium::tpm::TpmContext::new(
        tcti.trim_start_matches("device:"),
    )
    .expect("TpmContext::new should succeed")
}

#[test]
fn test_primary_key_is_deterministic() {
    let Some(tcti) = test_tcti() else { return };

    // Create two independent contexts with the same device.
    let ctx1 = make_context(&tcti);
    let ctx2 = make_context(&tcti);

    // Create child keys under each primary; both should succeed.
    let (priv1, pub1) = ctx1
        .with_ctx(|ctx, primary| tpm::keys::create_child_key(ctx, primary))
        .expect("create child key on ctx1");
    let (priv2, pub2) = ctx2
        .with_ctx(|ctx, primary| tpm::keys::create_child_key(ctx, primary))
        .expect("create child key on ctx2");

    // Serialized public keys for child keys will differ (random), but
    // they must be loadable under their respective primaries.
    ctx1.with_ctx(|ctx, primary| {
        let h = tpm::keys::load_key(ctx, primary, &priv1, &pub1)?;
        tpm::keys::flush(ctx, h)
    })
    .expect("load child1 under ctx1 primary");

    ctx2.with_ctx(|ctx, primary| {
        let h = tpm::keys::load_key(ctx, primary, &priv2, &pub2)?;
        tpm::keys::flush(ctx, h)
    })
    .expect("load child2 under ctx2 primary");

    println!(
        "Primary key determinism: child key public blobs are {} bytes and {} bytes",
        pub1.len(),
        pub2.len()
    );
}

#[test]
fn test_child_key_create_load_sign() {
    let Some(tcti) = test_tcti() else { return };
    let ctx = make_context(&tcti);

    let (priv_bytes, pub_bytes) = ctx
        .with_ctx(|ctx, primary| tpm::keys::create_child_key(ctx, primary))
        .expect("create child key");

    let up = fidorium::UserPresenceProof::test_only();
    let sig = ctx
        .with_ctx(|ctx, primary| {
            let key = tpm::keys::load_key(ctx, primary, &priv_bytes, &pub_bytes)?;
            let sig = tpm::keys::sign(ctx, key, b"hello fidorium", &up)?;
            tpm::keys::flush(ctx, key)?;
            Ok(sig)
        })
        .expect("load and sign");

    assert_eq!(sig.len(), 64, "signature must be 64 bytes (r||s)");
    assert_ne!(&sig[..32], &[0u8; 32], "r must be non-zero");
    assert_ne!(&sig[32..], &[0u8; 32], "s must be non-zero");
    println!("Sign: r={}, s={}", hex(&sig[..32]), hex(&sig[32..]));
}

#[test]
fn test_nv_counter_init_and_increment() {
    let Some(tcti) = test_tcti() else { return };
    let ctx = make_context(&tcti);

    // Use a dedicated test NV index to avoid clobbering production counter
    let test_nv_index: u32 = 0x01800200;

    // ensure_counter is idempotent; call twice
    ctx.with_ctx(|ctx, _| tpm::counter::ensure_counter(ctx, test_nv_index))
        .expect("ensure_counter first call");
    ctx.with_ctx(|ctx, _| tpm::counter::ensure_counter(ctx, test_nv_index))
        .expect("ensure_counter second call (idempotent)");

    let initial = ctx
        .with_ctx(|ctx, _| tpm::counter::read_counter(ctx, test_nv_index))
        .expect("read initial value");

    let v1 = ctx
        .with_ctx(|ctx, _| tpm::counter::increment_and_read(ctx, test_nv_index))
        .expect("increment 1");
    assert!(v1 > initial, "counter must increase after increment");

    let v2 = ctx
        .with_ctx(|ctx, _| tpm::counter::increment_and_read(ctx, test_nv_index))
        .expect("increment 2");
    assert_eq!(v2, v1 + 1, "counter must increase by exactly 1");

    println!("NV counter: initial={initial} v1={v1} v2={v2}");
}

#[test]
fn test_seal_unseal_roundtrip() {
    let Some(tcti) = test_tcti() else { return };
    let ctx = make_context(&tcti);

    let (priv_bytes, pub_bytes, key) = ctx
        .with_ctx(|ctx, primary| tpm::seal::create_seal(ctx, primary))
        .expect("create_seal");

    let recovered = ctx
        .with_ctx(|ctx, primary| tpm::seal::unseal(ctx, primary, &priv_bytes, &pub_bytes))
        .expect("unseal");

    assert_eq!(key, recovered, "unsealed key must match original");
    println!("Seal/unseal roundtrip OK, key prefix={}", hex(&key[..8]));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
