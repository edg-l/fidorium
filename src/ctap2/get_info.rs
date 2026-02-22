use ciborium::value::Value;

/// Returns complete CTAP2 response bytes: [0x00] ++ CBOR(GetInfo response).
pub(crate) fn handle_get_info() -> Vec<u8> {
    let map = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Array(vec![Value::Text("FIDO_2_0".to_string())]),
        ),
        (Value::Integer(2i64.into()), Value::Array(vec![])),
        (
            Value::Integer(3i64.into()),
            Value::Bytes(crate::config::AAGUID.to_vec()),
        ),
        (
            Value::Integer(4i64.into()),
            Value::Map(vec![
                (Value::Text("rk".to_string()), Value::Bool(true)),
                (Value::Text("up".to_string()), Value::Bool(true)),
                (Value::Text("uv".to_string()), Value::Bool(false)),
                (Value::Text("plat".to_string()), Value::Bool(false)),
            ]),
        ),
        (Value::Integer(5i64.into()), Value::Integer(1200i64.into())),
    ]);
    let mut buf = vec![0x00u8];
    ciborium::into_writer(&map, &mut buf).expect("GetInfo encoding is infallible");
    buf
}
