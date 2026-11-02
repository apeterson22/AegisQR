use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustodyTransferManifest {
    pub manifest_id: String,
    pub sender_agent_id: String,
    pub receiver_agent_id: String,
    pub capsule_id: String,
    pub payload_blake3_hash: String,
    pub created_at: u64,
    pub geofence: Option<String>,
    pub temperature_max_celsius: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustodyTransferReceipt {
    pub receipt_id: String,
    pub manifest_id: String,
    pub receiver_agent_id: String,
    pub status: String,
    pub verified_hash: String,
    pub signed_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_signature: Option<Vec<u8>>,
}

impl CustodyTransferManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut clone = self.clone();
        clone.sender_signature = None;
        serde_json::to_vec(&clone).context("failed to serialize canonical manifest")
    }

    pub fn sign(&mut self, sender_privkey_bytes: &[u8]) -> Result<()> {
        let signing_key = SigningKey::from_bytes(
            sender_privkey_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid sender private key length"))?,
        );
        let canonical = self.canonical_bytes()?;
        let sig: Signature = signing_key.sign(&canonical);
        self.sender_signature = Some(sig.to_bytes().to_vec());
        Ok(())
    }

    pub fn verify_signature(&self, sender_pubkey_bytes: &[u8]) -> Result<()> {
        let sig_bytes = self
            .sender_signature
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("manifest is unsigned"))?;
        let ver_key = VerifyingKey::from_bytes(
            sender_pubkey_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid sender public key length"))?,
        )?;
        let sig = Signature::from_slice(sig_bytes).context("invalid signature format")?;
        let canonical = self.canonical_bytes()?;
        ver_key
            .verify(&canonical, &sig)
            .context("sender custody signature invalid")?;
        Ok(())
    }
}

impl CustodyTransferReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut clone = self.clone();
        clone.receiver_signature = None;
        serde_json::to_vec(&clone).context("failed to serialize canonical receipt")
    }

    pub fn sign(&mut self, receiver_privkey_bytes: &[u8]) -> Result<()> {
        let signing_key = SigningKey::from_bytes(
            receiver_privkey_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid receiver private key length"))?,
        );
        let canonical = self.canonical_bytes()?;
        let sig: Signature = signing_key.sign(&canonical);
        self.receiver_signature = Some(sig.to_bytes().to_vec());
        Ok(())
    }

    pub fn verify_signature(&self, receiver_pubkey_bytes: &[u8]) -> Result<()> {
        let sig_bytes = self
            .receiver_signature
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("receipt is unsigned"))?;
        let ver_key = VerifyingKey::from_bytes(
            receiver_pubkey_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid receiver public key length"))?,
        )?;
        let sig = Signature::from_slice(sig_bytes).context("invalid signature format")?;
        let canonical = self.canonical_bytes()?;
        ver_key
            .verify(&canonical, &sig)
            .context("receiver receipt signature invalid")?;
        Ok(())
    }
}

/// Verifies a complete bilateral autonomous agent handoff:
/// 1. Manifest signed by sender matches receiver expectations.
/// 2. Receipt signed by receiver matches manifest.
/// 3. Hashes and agent identities align without tampering.
pub fn verify_complete_custody_handoff(
    manifest: &CustodyTransferManifest,
    receipt: &CustodyTransferReceipt,
    sender_pubkey: &[u8],
    receiver_pubkey: &[u8],
) -> Result<()> {
    manifest.verify_signature(sender_pubkey)?;
    receipt.verify_signature(receiver_pubkey)?;

    if receipt.manifest_id != manifest.manifest_id {
        bail!(
            "Handoff mismatch: receipt manifest_id '{}' != manifest '{}'",
            receipt.manifest_id,
            manifest.manifest_id
        );
    }
    if receipt.receiver_agent_id != manifest.receiver_agent_id {
        bail!(
            "Handoff mismatch: receipt agent '{}' != expected receiver '{}'",
            receipt.receiver_agent_id,
            manifest.receiver_agent_id
        );
    }
    if receipt.verified_hash != manifest.payload_blake3_hash {
        bail!(
            "Handoff integrity failure: receiver hash '{}' != sender hash '{}'",
            receipt.verified_hash,
            manifest.payload_blake3_hash
        );
    }
    if receipt.status != "accepted" {
        bail!(
            "Custody transfer rejected by receiver: status='{}'",
            receipt.status
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autonomous_custody_handoff_lifecycle() {
        let sender_priv = [0x07u8; 32];
        let sender_pub = SigningKey::from_bytes(&sender_priv)
            .verifying_key()
            .to_bytes();

        let receiver_priv = [0x08u8; 32];
        let receiver_pub = SigningKey::from_bytes(&receiver_priv)
            .verifying_key()
            .to_bytes();

        let mut manifest = CustodyTransferManifest {
            manifest_id: "XFER-2026-001".to_string(),
            sender_agent_id: "drone-flight-402".to_string(),
            receiver_agent_id: "vault-kiosk-99".to_string(),
            capsule_id: "cap-8899".to_string(),
            payload_blake3_hash: "a3f5b7...".to_string(),
            created_at: 1700000000,
            geofence: Some("30.2672,-97.7431,50m".to_string()),
            temperature_max_celsius: Some(4.0),
            sender_signature: None,
        };
        manifest.sign(&sender_priv).unwrap();
        manifest.verify_signature(&sender_pub).unwrap();

        let mut receipt = CustodyTransferReceipt {
            receipt_id: "RCPT-2026-001".to_string(),
            manifest_id: "XFER-2026-001".to_string(),
            receiver_agent_id: "vault-kiosk-99".to_string(),
            status: "accepted".to_string(),
            verified_hash: "a3f5b7...".to_string(),
            signed_at: 1700000010,
            receiver_signature: None,
        };
        receipt.sign(&receiver_priv).unwrap();
        receipt.verify_signature(&receiver_pub).unwrap();

        // Verify end-to-end bilateral handoff
        verify_complete_custody_handoff(&manifest, &receipt, &sender_pub, &receiver_pub).unwrap();
    }
}
