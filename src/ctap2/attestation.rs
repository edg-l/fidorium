use super::types::Ctap2Error;
use ciborium::value::Value;

/// Build "packed" self-attestation CBOR object.
pub(crate) fn build_attestation_object(
    auth_data: &[u8],
    der_sig: &[u8],
) -> Result<Vec<u8>, Ctap2Error> {
    let map = Value::Map(vec![
        (
            Value::Integer(1i64.into()),
            Value::Text("packed".to_string()),
        ),
        (
            Value::Integer(2i64.into()),
            Value::Bytes(auth_data.to_vec()),
        ),
        (
            Value::Integer(3i64.into()),
            Value::Map(vec![
                (
                    Value::Text("alg".to_string()),
                    Value::Integer((-7i64).into()),
                ),
                (
                    Value::Text("sig".to_string()),
                    Value::Bytes(der_sig.to_vec()),
                ),
            ]),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    Ok(buf)
}
