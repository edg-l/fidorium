use ciborium::value::Value;

/// Maximum credential ID we ever emit (see `make_credential`: a 32-byte random ID).
pub(crate) const MAX_CREDENTIAL_ID_LENGTH: u64 = 32;
/// Maximum number of entries we will scan in an allowList/excludeList in one request.
pub(crate) const MAX_CREDENTIAL_COUNT_IN_LIST: u64 = 16;

/// Returns complete CTAP2 response bytes: [0x00] ++ CBOR(GetInfo response).
pub(crate) fn handle_get_info() -> Vec<u8> {
    let map = Value::Map(vec![
        // 0x01 versions
        (
            Value::Integer(1i64.into()),
            Value::Array(vec![Value::Text("FIDO_2_0".to_string())]),
        ),
        // 0x02 extensions
        (Value::Integer(2i64.into()), Value::Array(vec![])),
        // 0x03 aaguid
        (
            Value::Integer(3i64.into()),
            Value::Bytes(crate::config::AAGUID.to_vec()),
        ),
        // 0x04 options
        (
            Value::Integer(4i64.into()),
            Value::Map(vec![
                (Value::Text("plat".to_string()), Value::Bool(false)),
                (Value::Text("rk".to_string()), Value::Bool(true)),
                // Built-in user verification: pinentry prompts for a passphrase.
                // Reported as supported *and configured*, so clients use internal UV
                // rather than trying to negotiate clientPIN (which we don't implement).
                (Value::Text("uv".to_string()), Value::Bool(true)),
                (Value::Text("up".to_string()), Value::Bool(true)),
            ]),
        ),
        // 0x05 maxMsgSize
        (Value::Integer(5i64.into()), Value::Integer(1200i64.into())),
        // 0x07 maxCredentialCountInList
        (
            Value::Integer(7i64.into()),
            Value::Integer(MAX_CREDENTIAL_COUNT_IN_LIST.into()),
        ),
        // 0x08 maxCredentialIdLength
        (
            Value::Integer(8i64.into()),
            Value::Integer(MAX_CREDENTIAL_ID_LENGTH.into()),
        ),
        // 0x09 transports
        (
            Value::Integer(9i64.into()),
            Value::Array(vec![Value::Text("usb".to_string())]),
        ),
        // 0x0A algorithms
        (
            Value::Integer(10i64.into()),
            Value::Array(vec![Value::Map(vec![
                (
                    Value::Text("alg".to_string()),
                    Value::Integer((-7i64).into()),
                ),
                (
                    Value::Text("type".to_string()),
                    Value::Text("public-key".to_string()),
                ),
            ])]),
        ),
    ]);
    let mut buf = vec![0x00u8];
    ciborium::into_writer(&map, &mut buf).expect("GetInfo encoding is infallible");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::types::{cbor_get, cbor_get_str, parse_cbor};

    fn info_map() -> Vec<(Value, Value)> {
        let bytes = handle_get_info();
        assert_eq!(bytes[0], 0x00, "GetInfo must succeed");
        parse_cbor(&bytes[1..]).expect("GetInfo body must be a CBOR map")
    }

    #[test]
    fn test_get_info_reports_uv_supported() {
        let map = info_map();
        let options = cbor_get(&map, 4)
            .and_then(crate::ctap2::types::cbor_map)
            .unwrap();
        assert_eq!(
            cbor_get_str(options, "uv"),
            Some(&Value::Bool(true)),
            "uv must be advertised so RPs requiring user verification accept us"
        );
        assert_eq!(cbor_get_str(options, "rk"), Some(&Value::Bool(true)));
    }

    #[test]
    fn test_get_info_omits_client_pin_option() {
        // Absent (not `false`) means "clientPIN not supported", which steers
        // clients to internal UV instead of a PIN handshake we cannot answer.
        let map = info_map();
        let options = cbor_get(&map, 4)
            .and_then(crate::ctap2::types::cbor_map)
            .unwrap();
        assert!(cbor_get_str(options, "clientPin").is_none());
    }

    #[test]
    fn test_get_info_advertises_es256_and_usb() {
        let map = info_map();
        assert!(cbor_get(&map, 10).is_some(), "algorithms must be present");
        assert!(cbor_get(&map, 9).is_some(), "transports must be present");
        assert_eq!(
            cbor_get(&map, 8),
            Some(&Value::Integer(MAX_CREDENTIAL_ID_LENGTH.into())),
        );
    }
}
