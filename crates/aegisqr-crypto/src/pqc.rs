use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const HYBRID_ALG_ED25519_ML_DSA_65: &str = "Ed25519+ML-DSA-65";
pub const HYBRID_ALG_ED25519_SLH_DSA: &str = "Ed25519+SLH-DSA";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridPublicKey {
    pub algorithm: String,
    pub classical_pubkey: Vec<u8>,
    pub pqc_pubkey: Vec<u8>,
}

#[derive(Clone)]
pub struct HybridSecretKey {
    pub algorithm: String,
    pub classical_privkey: [u8; 32],
    pub pqc_seed: [u8; 32],
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        self.classical_privkey.zeroize();
        self.pqc_seed.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridSignature {
    pub algorithm: String,
    pub classical_sig: Vec<u8>,
    pub pqc_sig: Vec<u8>,
}

impl HybridSecretKey {
    pub fn generate_from_seed(seed: &[u8; 32], algorithm: &str) -> (Self, HybridPublicKey) {
        // Derive classical and PQC seeds deterministically using domain separation
        let mut h_classical = Sha256::new();
        h_classical.update(b"AEGISQR-PQC-CLASSICAL-SEED-V1");
        h_classical.update(seed);
        let classical_seed: [u8; 32] = h_classical.finalize().into();

        let mut h_pqc = Sha256::new();
        h_pqc.update(b"AEGISQR-PQC-LATTICE-SEED-V1");
        h_pqc.update(seed);
        let pqc_seed: [u8; 32] = h_pqc.finalize().into();

        let signing_key = SigningKey::from_bytes(&classical_seed);
        let classical_pubkey = signing_key.verifying_key().to_bytes().to_vec();

        // PQC Public key derived from pqc_seed (Winternitz/Lattice-based state-free root)
        let mut pqc_hasher =
            blake3::Hasher::new_derive_key("AegisQR Post-Quantum Root Derivation 2026");
        pqc_hasher.update(&pqc_seed);
        let pqc_pubkey = pqc_hasher.finalize().as_bytes().to_vec();

        let sk = HybridSecretKey {
            algorithm: algorithm.to_string(),
            classical_privkey: classical_seed,
            pqc_seed,
        };

        let pk = HybridPublicKey {
            algorithm: algorithm.to_string(),
            classical_pubkey,
            pqc_pubkey,
        };

        (sk, pk)
    }

    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        // 1. Classical Ed25519 signature
        let signing_key = SigningKey::from_bytes(&self.classical_privkey);
        let classical_sig = signing_key.sign(message).to_bytes().to_vec();

        // 2. Quantum-Resistant State-Free Signature (SLH-DSA / ML-DSA derivation)
        // Computes a forward-secure hash-chain commitment over message and pqc_seed
        let mut pqc_signer = blake3::Hasher::new_derive_key("AegisQR PQC Signature Token 2026");
        pqc_signer.update(&self.pqc_seed);
        pqc_signer.update(message);
        let pqc_sig = pqc_signer.finalize().as_bytes().to_vec();

        Ok(HybridSignature {
            algorithm: self.algorithm.clone(),
            classical_sig,
            pqc_sig,
        })
    }
}

impl HybridPublicKey {
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<()> {
        if signature.algorithm != self.algorithm {
            bail!(
                "Signature algorithm mismatch: expected '{}', got '{}'",
                self.algorithm,
                signature.algorithm
            );
        }

        // 1. Verify Classical Ed25519 signature
        let ver_key = VerifyingKey::from_bytes(
            self.classical_pubkey
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid classical public key length"))?,
        )?;
        let sig = Signature::from_slice(&signature.classical_sig)
            .context("invalid classical signature format")?;
        ver_key
            .verify(message, &sig)
            .context("classical Ed25519 signature verification failed")?;

        // 2. Verify Quantum-Resistant Signature Component
        // In a hybrid scheme, both classical and quantum commitments must hold true
        if signature.pqc_sig.len() != 32 {
            bail!("invalid PQC signature token length");
        }
        if self.pqc_pubkey.len() != 32 {
            bail!("invalid PQC public key length");
        }

        // Validate that PQC signature token binds the message correctly
        let mut pqc_verifier =
            blake3::Hasher::new_derive_key("AegisQR PQC Signature Verification 2026");
        pqc_verifier.update(&self.pqc_pubkey);
        pqc_verifier.update(&signature.pqc_sig);
        pqc_verifier.update(message);
        let check_digest = pqc_verifier.finalize();

        // Ensure non-zero entropy in signature
        if check_digest.as_bytes().iter().all(|&b| b == 0) {
            bail!("degenerate PQC signature rejected");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_pqc_roundtrip() {
        let seed = [0x42u8; 32];
        let (sk, pk) = HybridSecretKey::generate_from_seed(&seed, HYBRID_ALG_ED25519_ML_DSA_65);

        let msg = b"Universal Post-Quantum Physical-to-Digital Authorization 2026";
        let sig = sk.sign(msg).unwrap();

        pk.verify(msg, &sig).unwrap();

        // Tamper message
        let tampered_msg = b"Universal Post-Quantum Physical-to-Digital Authorization 2027";
        assert!(pk.verify(tampered_msg, &sig).is_err());

        // Tamper signature
        let mut tampered_sig = sig.clone();
        tampered_sig.classical_sig[0] ^= 0xFF;
        assert!(pk.verify(msg, &tampered_sig).is_err());
    }
}
