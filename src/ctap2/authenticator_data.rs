use ciborium::value::Value;

/// Build authenticatorData for MakeCredential (AT=1 flag, includes credential data).
pub(crate) fn build_make_cred_auth_data(
    rp_id_hash: &[u8; 32],
    credential_id: &[u8],
    public_key_x: &[u8; 32],
    public_key_y: &[u8; 32],
) -> Vec<u8> {
    let cose_key = encode_cose_key(public_key_x, public_key_y);
    let cred_id_len = credential_id.len() as u16;
    let mut data = Vec::new();
    data.extend_from_slice(rp_id_hash);
    data.push(0x41);  // flags: UP=1, AT=1
    data.extend_from_slice(&[0, 0, 0, 0]);  // signCount = 0
    data.extend_from_slice(&crate::config::AAGUID);
    data.extend_from_slice(&cred_id_len.to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(&cose_key);
    data
}

/// Build authenticatorData for GetAssertion (no AT flag).
pub(crate) fn build_get_assertion_auth_data(
    rp_id_hash: &[u8; 32],
    sign_count: u32,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(rp_id_hash);
    data.push(0x01);  // flags: UP=1
    data.extend_from_slice(&sign_count.to_be_bytes());
    data
}

/// Encode a P-256 public key as a COSE_Key CBOR map (kty=2, alg=-7, crv=1, x, y).
pub(crate) fn encode_cose_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let map = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3i64).into()), Value::Bytes(y.to_vec())),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).expect("COSE key encoding is infallible");
    buf
}

/// DER-encode a raw 64-byte P-256 ECDSA signature (r || s).
pub(crate) fn encode_der_ecdsa(raw: &[u8; 64]) -> Vec<u8> {
    let r_der = der_integer(&raw[0..32]);
    let s_der = der_integer(&raw[32..64]);
    let inner_len = (r_der.len() + s_der.len()) as u8;
    let mut out = vec![0x30u8, inner_len];
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    out
}

fn der_integer(n: &[u8]) -> Vec<u8> {
    let n: Vec<u8> = n.iter().skip_while(|&&b| b == 0).copied().collect();
    let n = if n.is_empty() { vec![0u8] } else { n };
    let pad = n[0] & 0x80 != 0;
    let mut out = vec![0x02u8, n.len() as u8 + pad as u8];
    if pad { out.push(0); }
    out.extend_from_slice(&n);
    out
}
