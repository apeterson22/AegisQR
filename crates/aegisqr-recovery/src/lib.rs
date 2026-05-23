use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProfile {
    pub data_shards: u8,
    pub recovery_shards: u8,
    pub profile_name: String,
}

pub fn missing_chunks(total: u32, present: &[u32]) -> Vec<u32> {
    let present_set: BTreeSet<u32> = present.iter().copied().collect();
    (0..total).filter(|i| !present_set.contains(i)).collect()
}
