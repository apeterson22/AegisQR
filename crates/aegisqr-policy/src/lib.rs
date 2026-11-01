use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterprisePolicyPlaceholder {
    pub engine_version: String,
}
