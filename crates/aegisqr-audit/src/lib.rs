use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The operation recorded in an audit event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Pack,
    ExportQr,
    ImportQr,
    Verify,
    Stage,
    Approve,
    Reject,
    Unpack,
}

/// A single timestamped, actor-attributed event in the capsule audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unix timestamp (seconds since epoch) as a decimal string.
    pub timestamp: String,
    /// Identity of the actor who performed the action (e.g. signer ID, user, service).
    pub actor: String,
    pub action: AuditAction,
    /// `"ok"` on success; an error description on failure.
    pub result: String,
    pub notes: Option<String>,
}

/// A group of audit events from one processing session.
///
/// A capsule accumulates multiple `AuditRecord`s as it moves through the
/// pack → sign → approve → handoff → import lifecycle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditRecord {
    pub events: Vec<AuditEvent>,
}

/// An approval endorsement signed by a named approver using Ed25519.
///
/// The signed payload is the UTF-8 byte string:
/// `"{bundle_id}|{approver_id}|{approved_at}"`
///
/// Tokens are appended to the capsule by `aegisqr approve` and checked by
/// `verify_capsule` when `enterprise_policy.approval_required` is true.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    /// Must match the capsule's `public_header.bundle_id`.
    pub bundle_id: String,
    /// Signer ID; must appear in `enterprise_policy.approvers` to count.
    pub approver_id: String,
    /// Unix timestamp (seconds since epoch) as a decimal string.
    pub approved_at: String,
    /// Raw Ed25519 signature bytes (64 bytes).
    pub signature: Vec<u8>,
    /// Raw Ed25519 verifying-key bytes (32 bytes).
    pub public_key: Vec<u8>,
}

impl ApprovalToken {
    /// Returns the canonical byte payload that is signed and verified.
    pub fn signing_payload(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}",
            self.bundle_id, self.approver_id, self.approved_at
        )
        .into_bytes()
    }

    /// Verifies the approval token's Ed25519 signature.
    pub fn verify(&self) -> Result<()> {
        let key_bytes: &[u8; 32] = self
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid approval token public key length"))?;
        let key = VerifyingKey::from_bytes(key_bytes)?;
        let sig = Signature::from_slice(&self.signature)?;
        key.verify(&self.signing_payload(), &sig)?;
        Ok(())
    }

    /// Returns `Ok(())` if the token has not expired relative to `now_unix`.
    ///
    /// A `None` TTL means the approval never expires.
    pub fn check_ttl(&self, ttl_seconds: Option<u64>, now_unix: u64) -> Result<()> {
        if let Some(ttl) = ttl_seconds {
            let approved_at: u64 = self
                .approved_at
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid approved_at timestamp"))?;
            if now_unix.saturating_sub(approved_at) > ttl {
                bail!("approval token expired");
            }
        }
        Ok(())
    }
}
