use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadataPlaceholder {
    pub sidecar_reference: Option<String>,
}
