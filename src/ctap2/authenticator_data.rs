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
    data.push(0x41); // flags: UP=1, AT=1
    data.extend_from_slice(&[0, 0, 0, 0]); // signCount = 0
    data.extend_from_slice(&crate::config::AAGUID);
    data.extend_from_slice(&cred_id_len.to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(&cose_key);
    data
}

/// Build authenticatorData for GetAssertion (no AT flag).
pub(crate) fn build_get_assertion_auth_data(rp_id_hash: &[u8; 32], sign_count: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(rp_id_hash);
    data.push(0x01); // flags: UP=1
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
    if pad {
        out.push(0);
    }
    out.extend_from_slice(&n);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- encode_der_ecdsa ---

    #[test]
    fn test_der_ecdsa_structure() {
        let mut raw = [0u8; 64];
        raw[0] = 0x01; // r = 1
        raw[32] = 0x01; // s = 1
        let der = encode_der_ecdsa(&raw);
        // SEQUENCE tag
        assert_eq!(der[0], 0x30, "must start with SEQUENCE tag 0x30");
        // Total inner length
        let inner_len = der[1] as usize;
        assert_eq!(
            der.len(),
            2 + inner_len,
            "DER length field must be accurate"
        );
        // First INTEGER
        assert_eq!(der[2], 0x02, "r must start with INTEGER tag 0x02");
    }

    #[test]
    fn test_der_ecdsa_high_bit_padding() {
        // r = 0x80 (one significant byte with high bit set) → must prepend 0x00.
        // Set raw[31] = 0x80 so that after stripping leading zeros n = [0x80].
        let mut raw = [0u8; 64];
        raw[31] = 0x80;
        raw[63] = 0x01; // s = 1
        let der = encode_der_ecdsa(&raw);
        assert_eq!(der[2], 0x02, "r must be tagged as INTEGER");
        let r_len = der[3] as usize;
        assert_eq!(r_len, 2, "padded integer must be 2 bytes (0x00, 0x80)");
        assert_eq!(der[4], 0x00, "must be padded with 0x00 prefix");
        assert_eq!(der[5], 0x80);
    }

    #[test]
    fn test_der_ecdsa_leading_zeros_stripped() {
        // r = 0x01 (last byte non-zero, leading zeros fill the rest).
        // Set raw[31] = 0x01 so that after stripping leading zeros n = [0x01].
        let mut raw = [0u8; 64];
        raw[31] = 0x01;
        raw[63] = 0x01; // s = 1
        let der = encode_der_ecdsa(&raw);
        assert_eq!(der[2], 0x02, "r must be tagged as INTEGER");
        let r_len = der[3] as usize;
        assert_eq!(
            r_len, 1,
            "leading zeros must be stripped, leaving single byte"
        );
        assert_eq!(der[4], 0x01);
    }

    #[test]
    fn test_der_ecdsa_all_zeros_encodes_as_single_zero() {
        // If r is all zeros, it should encode as INTEGER 0x00 (one byte).
        let raw = [0u8; 64];
        let der = encode_der_ecdsa(&raw);
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 1, "zero integer must have length 1");
        assert_eq!(der[4], 0x00);
    }

    // --- encode_cose_key ---

    #[test]
    fn test_cose_key_is_cbor_map() {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let encoded = encode_cose_key(&x, &y);
        let val: ciborium::value::Value =
            ciborium::from_reader(encoded.as_slice()).expect("must be valid CBOR");
        assert!(matches!(val, Value::Map(_)), "COSE key must be a CBOR map");
    }

    #[test]
    fn test_cose_key_fields() {
        let x = [0xAAu8; 32];
        let y = [0xBBu8; 32];
        let encoded = encode_cose_key(&x, &y);
        let val: ciborium::value::Value = ciborium::from_reader(encoded.as_slice()).unwrap();
        let Value::Map(map) = val else {
            panic!("not a map")
        };

        let get = |key: i64| -> Option<&Value> {
            map.iter().find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    if i128::from(*i) == key as i128 {
                        return Some(v);
                    }
                }
                None
            })
        };

        // kty = 2 (EC2)
        assert!(matches!(get(1), Some(Value::Integer(i)) if i128::from(*i) == 2));
        // alg = -7 (ES256)
        assert!(matches!(get(3), Some(Value::Integer(i)) if i128::from(*i) == -7));
        // crv = 1 (P-256)
        assert!(matches!(get(-1), Some(Value::Integer(i)) if i128::from(*i) == 1));
        // x coordinate
        assert!(matches!(get(-2), Some(Value::Bytes(b)) if b == &[0xAAu8; 32]));
        // y coordinate
        assert!(matches!(get(-3), Some(Value::Bytes(b)) if b == &[0xBBu8; 32]));
    }

    // --- build_get_assertion_auth_data ---

    #[test]
    fn test_get_assertion_auth_data_layout() {
        let rp_id_hash = [0xABu8; 32];
        let sign_count: u32 = 42;
        let auth_data = build_get_assertion_auth_data(&rp_id_hash, sign_count);

        assert_eq!(
            auth_data.len(),
            37,
            "GetAssertion authData must be exactly 37 bytes"
        );
        assert_eq!(&auth_data[0..32], &rp_id_hash, "rpIdHash mismatch");
        assert_eq!(auth_data[32], 0x01, "flags must be 0x01 (UP only)");
        let count =
            u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
        assert_eq!(
            count, sign_count,
            "signCount must be big-endian encoded value"
        );
    }

    // --- build_make_cred_auth_data ---

    #[test]
    fn test_make_cred_auth_data_layout() {
        let rp_id_hash = [0x55u8; 32];
        let cred_id = [0x77u8; 32];
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let auth_data = build_make_cred_auth_data(&rp_id_hash, &cred_id, &x, &y);

        // Minimum length: 32 + 1 + 4 + 16 + 2 + 32 + cose_key_len
        assert!(
            auth_data.len() > 87,
            "MakeCredential authData must be at least 87 bytes"
        );
        assert_eq!(&auth_data[0..32], &rp_id_hash, "rpIdHash mismatch");
        assert_eq!(auth_data[32], 0x41, "flags must be 0x41 (UP+AT)");
        assert_eq!(
            &auth_data[33..37],
            &[0, 0, 0, 0],
            "signCount must be 0 for new credential"
        );
        assert_eq!(
            &auth_data[37..53],
            &crate::config::AAGUID,
            "AAGUID mismatch"
        );
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        assert_eq!(cred_id_len, 32, "credIdLen must be 32");
        assert_eq!(&auth_data[55..87], &cred_id, "credId mismatch");
    }
}
