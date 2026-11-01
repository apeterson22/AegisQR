use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditMetadataPlaceholder {
    pub event: String,
}
