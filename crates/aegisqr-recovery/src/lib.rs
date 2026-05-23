use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProfile {
    pub data_shards: u8,
    pub recovery_shards: u8,
    pub profile_name: String,
}

pub fn missing_chunks(total: u32, present: &[u32]) -> Vec<u32> {
    (0..total).filter(|i| !present.contains(i)).collect()
}
