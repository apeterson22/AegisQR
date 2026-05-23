use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingPlaceholder {
    pub cbor: bool,
    pub msgpack_future: bool,
}
