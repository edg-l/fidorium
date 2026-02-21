use ciborium::value::Value;

pub(crate) const CTAP2_CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub(crate) const CTAP2_CMD_GET_ASSERTION:   u8 = 0x02;
pub(crate) const CTAP2_CMD_GET_INFO:        u8 = 0x04;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Ctap2Error {
    #[error("missing parameter")]     MissingParameter,
    #[error("unsupported algorithm")] UnsupportedAlgorithm,
    #[error("credential excluded")]   CredentialExcluded,
    #[error("operation denied")]      OperationDenied,
    #[error("user action timeout")]   UserActionTimeout,
    #[error("keepalive cancel")]      KeepaliveCancel,
    #[error("no credentials")]        NoCredentials,
    #[error("cbor: {0}")]             Cbor(String),
    #[error("tpm: {0}")]              Tpm(#[from] crate::tpm::TpmError),
    #[error("store: {0}")]            Store(#[from] crate::store::StoreError),
}

impl Ctap2Error {
    pub fn status_byte(&self) -> u8 {
        match self {
            Self::MissingParameter     => 0x14,
            Self::UnsupportedAlgorithm => 0x26,
            Self::CredentialExcluded   => 0x19,
            Self::OperationDenied      => 0x27,
            Self::UserActionTimeout    => 0x2A,
            Self::KeepaliveCancel      => 0x2D,
            Self::NoCredentials        => 0x2E,
            Self::Cbor(_)              => 0x11,
            Self::Tpm(_) | Self::Store(_) => 0x7F,
        }
    }
}

pub(crate) struct MakeCredentialRequest {
    pub client_data_hash: Vec<u8>,
    pub rp_id:            String,
    pub rp_name:          Option<String>,
    pub user_id:          Vec<u8>,
    pub user_name:        Option<String>,
    pub user_display:     Option<String>,
    pub resident_key:     bool,
    pub exclude_list:     Vec<Vec<u8>>,
    pub alg_ok:           bool,  // true if -7 (ES256) is in pubKeyCredParams
}

pub(crate) struct GetAssertionRequest {
    pub rp_id:            String,
    pub client_data_hash: Vec<u8>,
    pub allow_list:       Vec<Vec<u8>>,
}

// CBOR parsing helpers

pub(crate) fn parse_cbor(data: &[u8]) -> Result<Vec<(Value, Value)>, Ctap2Error> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| Ctap2Error::Cbor(e.to_string()))?;
    match value {
        Value::Map(map) => Ok(map),
        _ => Err(Ctap2Error::Cbor("expected map".into())),
    }
}

pub(crate) fn cbor_get<'a>(map: &'a [(Value, Value)], key: i64) -> Option<&'a Value> {
    let target = Value::Integer(key.into());
    map.iter().find(|(k, _)| k == &target).map(|(_, v)| v)
}

pub(crate) fn cbor_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
        .map(|(_, v)| v)
}

pub(crate) fn cbor_bytes(v: &Value) -> Option<&[u8]> {
    match v { Value::Bytes(b) => Some(b), _ => None }
}

pub(crate) fn cbor_text(v: &Value) -> Option<&str> {
    match v { Value::Text(s) => Some(s), _ => None }
}

pub(crate) fn cbor_bool(v: &Value) -> Option<bool> {
    match v { Value::Bool(b) => Some(*b), _ => None }
}

pub(crate) fn cbor_map(v: &Value) -> Option<&[(Value, Value)]> {
    match v { Value::Map(m) => Some(m), _ => None }
}

pub(crate) fn cbor_array(v: &Value) -> Option<&[Value]> {
    match v { Value::Array(a) => Some(a), _ => None }
}

impl TryFrom<&[u8]> for MakeCredentialRequest {
    type Error = Ctap2Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let map = parse_cbor(data)?;

        // 1: clientDataHash
        let client_data_hash = cbor_bytes(
            cbor_get(&map, 1).ok_or(Ctap2Error::MissingParameter)?,
        )
        .ok_or(Ctap2Error::MissingParameter)?
        .to_vec();

        // 2: rp
        let rp_val = cbor_get(&map, 2).ok_or(Ctap2Error::MissingParameter)?;
        let rp_map = cbor_map(rp_val).ok_or(Ctap2Error::MissingParameter)?;
        let rp_id = cbor_text(
            cbor_get_str(rp_map, "id").ok_or(Ctap2Error::MissingParameter)?,
        )
        .ok_or(Ctap2Error::MissingParameter)?
        .to_string();
        let rp_name = cbor_get_str(rp_map, "name").and_then(cbor_text).map(|s| s.to_string());

        // 3: user
        let user_val = cbor_get(&map, 3).ok_or(Ctap2Error::MissingParameter)?;
        let user_map = cbor_map(user_val).ok_or(Ctap2Error::MissingParameter)?;
        let user_id = cbor_bytes(
            cbor_get_str(user_map, "id").ok_or(Ctap2Error::MissingParameter)?,
        )
        .ok_or(Ctap2Error::MissingParameter)?
        .to_vec();
        let user_name = cbor_get_str(user_map, "name").and_then(cbor_text).map(|s| s.to_string());
        let user_display = cbor_get_str(user_map, "displayName").and_then(cbor_text).map(|s| s.to_string());

        // 4: pubKeyCredParams — check for alg=-7
        let alg_ok = if let Some(params_val) = cbor_get(&map, 4) {
            cbor_array(params_val).map_or(false, |arr| {
                arr.iter().any(|item| {
                    cbor_map(item).map_or(false, |m| {
                        cbor_get_str(m, "alg")
                            .map_or(false, |v| v == &Value::Integer((-7i64).into()))
                    })
                })
            })
        } else {
            false
        };

        // 6: excludeList
        let exclude_list = if let Some(excl_val) = cbor_get(&map, 6) {
            cbor_array(excl_val).map_or(vec![], |arr| {
                arr.iter()
                    .filter_map(|item| {
                        let m = cbor_map(item)?;
                        let id = cbor_get_str(m, "id").and_then(cbor_bytes)?;
                        Some(id.to_vec())
                    })
                    .collect()
            })
        } else {
            vec![]
        };

        // 7: options
        let resident_key = cbor_get(&map, 7)
            .and_then(cbor_map)
            .and_then(|m| cbor_get_str(m, "rk"))
            .and_then(cbor_bool)
            .unwrap_or(false);

        Ok(MakeCredentialRequest {
            client_data_hash,
            rp_id,
            rp_name,
            user_id,
            user_name,
            user_display,
            resident_key,
            exclude_list,
            alg_ok,
        })
    }
}

impl TryFrom<&[u8]> for GetAssertionRequest {
    type Error = Ctap2Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let map = parse_cbor(data)?;

        // 1: rpId
        let rp_id = cbor_text(
            cbor_get(&map, 1).ok_or(Ctap2Error::MissingParameter)?,
        )
        .ok_or(Ctap2Error::MissingParameter)?
        .to_string();

        // 2: clientDataHash
        let client_data_hash = cbor_bytes(
            cbor_get(&map, 2).ok_or(Ctap2Error::MissingParameter)?,
        )
        .ok_or(Ctap2Error::MissingParameter)?
        .to_vec();

        // 3: allowList (optional)
        let allow_list = if let Some(list_val) = cbor_get(&map, 3) {
            cbor_array(list_val).map_or(vec![], |arr| {
                arr.iter()
                    .filter_map(|item| {
                        let m = cbor_map(item)?;
                        let id = cbor_get_str(m, "id").and_then(cbor_bytes)?;
                        Some(id.to_vec())
                    })
                    .collect()
            })
        } else {
            vec![]
        };

        Ok(GetAssertionRequest { rp_id, client_data_hash, allow_list })
    }
}
