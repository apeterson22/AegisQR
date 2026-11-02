pub mod pqc;
pub use pqc::*;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoProviderInfo {
    pub provider: String,
    pub post_quantum_enabled: bool,
    pub classical_algorithms: Vec<String>,
    pub hybrid_algorithms: Vec<String>,
}

impl Default for CryptoProviderInfo {
    fn default() -> Self {
        Self {
            provider: "AegisQR Native Rust Cryptographic Core".to_string(),
            post_quantum_enabled: true,
            classical_algorithms: vec![
                "Ed25519".to_string(),
                "XChaCha20-Poly1305".to_string(),
                "Argon2id".to_string(),
                "BLAKE3".to_string(),
            ],
            hybrid_algorithms: vec![
                HYBRID_ALG_ED25519_ML_DSA_65.to_string(),
                HYBRID_ALG_ED25519_SLH_DSA.to_string(),
            ],
        }
    }
}
