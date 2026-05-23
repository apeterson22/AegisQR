//! Repository handoff interface for the AICX ↔ AegisQR enterprise integration.
//!
//! This crate defines the **thin adapter layer** between AegisQR and
//! Artifactory/Nexus plugins.  AegisQR never calls repository APIs directly;
//! instead this crate provides:
//!
//! * typed structures for plugin API contracts,
//! * the [`validate_handoff_package`] function that plugins call before
//!   issuing any repository API request, and
//! * the [`plugin_api`] module with endpoint path and content-type constants.
//!
//! ## Integration flow
//!
//! ```text
//! aegisqr pack  → aegisqr approve → aegisqr handoff
//!                                        │
//!                         validate_handoff_package()
//!                                        │
//!                   Artifactory/Nexus plugin (HTTP call)
//! ```

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use aegisqr_core::{
    read_capsule_file, verify_capsule, AicxSidecar, ApprovalToken, AuditRecord, RepoType,
    TrustStore,
};

// Re-export so consumers only need `aegisqr-repo`.
pub use aegisqr_core::SerializationProfile;

// ─── Plugin API constants ────────────────────────────────────────────────────

/// Constants describing the Artifactory/Nexus plugin REST API endpoints.
///
/// The primary protocol is **REST/JSON over HTTPS** with token-based auth.
/// Every endpoint accepts `application/json`; AI-facing consumers may
/// negotiate `application/toon` for the same schema in TOON wire format.
pub mod plugin_api {
    /// Versioned base path for all plugin endpoints.
    pub const BASE_PATH: &str = "/api/plugins/aicx/v1";

    /// `POST /api/plugins/aicx/v1/exports`
    /// Initiates an export job.  Body: [`ExportRequest`](super::ExportRequest).
    pub const EXPORTS: &str = "/api/plugins/aicx/v1/exports";

    /// `POST /api/plugins/aicx/v1/imports`
    /// Initiates an import job.  Body: [`ImportRequest`](super::ImportRequest).
    pub const IMPORTS: &str = "/api/plugins/aicx/v1/imports";

    /// `GET /api/plugins/aicx/v1/jobs/{job_id}`
    /// Returns the current status of a job.
    pub const JOB: &str = "/api/plugins/aicx/v1/jobs/{job_id}";

    /// `POST /api/plugins/aicx/v1/jobs/{job_id}/approve`
    /// Approves a pending job.
    pub const JOB_APPROVE: &str = "/api/plugins/aicx/v1/jobs/{job_id}/approve";

    /// `POST /api/plugins/aicx/v1/jobs/{job_id}/cancel`
    /// Cancels a pending or in-progress job.
    pub const JOB_CANCEL: &str = "/api/plugins/aicx/v1/jobs/{job_id}/cancel";

    /// `GET /api/plugins/aicx/v1/capabilities`
    /// Returns plugin capabilities and supported AICX/AegisQR versions.
    pub const CAPABILITIES: &str = "/api/plugins/aicx/v1/capabilities";

    /// Default request/response content type.
    pub const CONTENT_TYPE_JSON: &str = "application/json";

    /// AI-optimized alternate content type (same schema, TOON wire format).
    pub const CONTENT_TYPE_TOON: &str = "application/toon";
}

// ─── Auth ────────────────────────────────────────────────────────────────────

/// Token authentication type used by the plugin when calling the repository API.
///
/// HTTPS + token auth is mandatory for all automated access.  SSH is
/// reserved for operational/admin workflows (bastion access, repo automation).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    /// OAuth2/OIDC bearer token.
    Bearer,
    /// Personal access token.
    Pat,
    /// Scoped service account token.
    ServiceToken,
}

/// Authentication hint carried in a [`HandoffPackage`].
///
/// The `token` field is intentionally `None` by default; the repository
/// plugin sources the actual credential from its own secure store at runtime.
/// AegisQR records the *type* of token required so the plugin can select the
/// correct credential without exposing secrets in the handoff package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub auth_type: AuthType,
    /// Credential value, populated by the plugin at runtime.  Should be
    /// `None` when the handoff package is written to disk.
    pub token: Option<String>,
}

// ─── Repository coordinates ──────────────────────────────────────────────────

/// Full coordinates identifying where to import/export an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryCoordinates {
    pub repo_type: RepoType,
    /// Base URL of the repository instance (e.g. `"https://repo.example.com"`).
    pub base_url: String,
    /// Logical repository name within the instance.
    pub repository: String,
    /// Maven-style group or namespace.
    pub group: String,
    /// Artifact name.
    pub name: String,
    /// Version string.
    pub version: String,
    /// Optional classifier suffix.
    pub classifier: Option<String>,
}

// ─── Plugin job request types ────────────────────────────────────────────────

/// Body for `POST /exports`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRequest {
    pub coordinates: Vec<RepositoryCoordinates>,
    #[serde(default)]
    pub serialization_profile: SerializationProfile,
}

/// Body for `POST /imports`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRequest {
    pub handoff_package_path: PathBuf,
    #[serde(default)]
    pub serialization_profile: SerializationProfile,
}

// ─── Handoff package ─────────────────────────────────────────────────────────

/// A complete handoff package passed from AegisQR to the repository plugin.
///
/// The plugin calls [`validate_handoff_package`] before issuing any repository
/// API request.  On `HandoffState::Approved`, the plugin proceeds to call the
/// Artifactory/Nexus REST API using its own credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffPackage {
    /// Path to the sealed `.aqr` capsule file.
    pub capsule_path: PathBuf,
    /// AICX sidecar forwarded from the capsule's `agent_index`.
    pub aicx_sidecar: AicxSidecar,
    /// Audit trail accumulated during the seal/approve lifecycle.
    pub audit_log: Vec<AuditRecord>,
    /// External approval tokens (out-of-band approvals not embedded in the capsule).
    #[serde(default)]
    pub approval_tokens: Vec<ApprovalToken>,
    /// Target repository coordinates for the import step.
    pub target_coords: RepositoryCoordinates,
    /// Auth hint for the plugin.  Token value filled by the plugin at runtime.
    pub auth_config: Option<AuthConfig>,
    /// Preferred serialization profile for the plugin's API responses.
    #[serde(default)]
    pub serialization_profile: SerializationProfile,
}

// ─── Handoff state machine ───────────────────────────────────────────────────

/// Lifecycle state of a handoff package.
///
/// Every state transition is reflected in a [`HandoffEvent`], which is
/// machine-readable and can be serialized as JSON or TOON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HandoffState {
    /// Package created; validation not yet attempted.
    Pending,
    /// Capsule verified; waiting for required approval tokens.
    AwaitingApproval,
    /// All checks passed; ready for repository ingestion.
    Approved,
    /// Validation failed for a policy reason (e.g. explicit rejection).
    Rejected,
    /// Successfully delivered to the repository.
    Delivered,
    /// Validation or delivery failed with a diagnostic message.
    Failed(String),
}

/// Machine-readable event emitted on every [`HandoffState`] transition.
///
/// Can be serialized as JSON (`application/json`) or TOON
/// (`application/toon`) — same schema, same field semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffEvent {
    /// Job identifier (bundle_id of the capsule).
    pub job_id: String,
    pub bundle_id: String,
    pub state: HandoffState,
    /// Unix timestamp of the transition (seconds since epoch).
    pub timestamp: String,
    /// Serialization profile used by the event producer.
    #[serde(default)]
    pub serialization_profile: SerializationProfile,
    pub message: Option<String>,
}

impl HandoffEvent {
    fn new(bundle_id: String, state: HandoffState, message: Option<String>) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            job_id: bundle_id.clone(),
            bundle_id,
            state,
            timestamp: ts.to_string(),
            serialization_profile: SerializationProfile::Json,
            message,
        }
    }
}

/// Result returned by [`validate_handoff_package`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoHandoffResult {
    pub bundle_id: String,
    pub state: HandoffState,
    pub event: HandoffEvent,
    /// Populated by the repository plugin after successful ingestion.
    pub repo_artifact_url: Option<String>,
}

// ─── Validation ──────────────────────────────────────────────────────────────

/// Validates a [`HandoffPackage`] without making any HTTP calls.
///
/// Plugins **must** call this before issuing any repository API request.
/// Returns a [`RepoHandoffResult`] whose `state` field indicates whether
/// the plugin may proceed.
///
/// # Validation steps
///
/// 1. Read and verify the capsule's Ed25519 signature and chunk table.
/// 2. Check that the sidecar `bundle_id` is consistent with the capsule.
/// 3. Evaluate the enterprise approval gate (if `approval_required`).
///
/// # Auth
///
/// This function performs no network I/O and does not evaluate
/// `auth_config.token`.  The plugin is responsible for credential injection.
pub fn validate_handoff_package(
    pkg: &HandoffPackage,
    trust_store: Option<&TrustStore>,
) -> Result<RepoHandoffResult> {
    // 1. Verify capsule signature + chunk integrity.
    if let Err(e) = verify_capsule(&pkg.capsule_path, trust_store, false) {
        let msg = format!("capsule verification failed: {e:#}");
        let state = HandoffState::Failed(msg.clone());
        let bid = pkg.aicx_sidecar.bundle_id.clone();
        return Ok(RepoHandoffResult {
            bundle_id: bid.clone(),
            event: HandoffEvent::new(bid, state.clone(), Some(msg)),
            state,
            repo_artifact_url: None,
        });
    }

    let capsule = read_capsule_file(&pkg.capsule_path)?;
    let bundle_id = capsule.public_header.bundle_id.clone();

    // 2. AICX sidecar bundle_id consistency.
    if !pkg.aicx_sidecar.bundle_id.is_empty() {
        // The sidecar in the handoff package must match the one embedded in the
        // capsule's agent_index (if present).
        if let Some(embedded) = &capsule.agent_index.aicx_sidecar {
            if embedded.bundle_id != pkg.aicx_sidecar.bundle_id {
                let msg = format!(
                    "AICX sidecar bundle_id mismatch: handoff has {}, capsule has {}",
                    pkg.aicx_sidecar.bundle_id, embedded.bundle_id
                );
                let state = HandoffState::Failed(msg.clone());
                let bid = bundle_id.clone();
                return Ok(RepoHandoffResult {
                    bundle_id: bid.clone(),
                    event: HandoffEvent::new(bid, state.clone(), Some(msg)),
                    state,
                    repo_artifact_url: None,
                });
            }
        }
    }

    // 3. Enterprise approval gate.
    let enterprise_policy = match &capsule.enterprise_policy {
        Some(p) if p.approval_required => p,
        _ => {
            // No approval required — proceed immediately.
            let state = HandoffState::Approved;
            return Ok(RepoHandoffResult {
                bundle_id: bundle_id.clone(),
                event: HandoffEvent::new(
                    bundle_id.clone(),
                    state.clone(),
                    Some("no approval gate configured".into()),
                ),
                state,
                repo_artifact_url: None,
            });
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Count tokens from both the capsule (embedded by `aegisqr approve`) and
    // any externally-provided tokens in the handoff package.
    let all_tokens = capsule
        .approval_tokens
        .iter()
        .chain(pkg.approval_tokens.iter());

    let valid_count = all_tokens
        .filter(|t| {
            enterprise_policy.approvers.contains(&t.approver_id)
                && t.bundle_id == bundle_id
                && t.verify().is_ok()
                && t.check_ttl(enterprise_policy.approval_ttl_seconds, now)
                    .is_ok()
        })
        .count();

    let state = if valid_count >= enterprise_policy.min_approvals as usize {
        HandoffState::Approved
    } else {
        HandoffState::AwaitingApproval
    };

    let message = Some(format!(
        "{valid_count}/{} valid approvals",
        enterprise_policy.min_approvals
    ));

    Ok(RepoHandoffResult {
        bundle_id: bundle_id.clone(),
        event: HandoffEvent::new(bundle_id, state.clone(), message),
        state,
        repo_artifact_url: None,
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_api_paths_are_versioned() {
        assert!(plugin_api::EXPORTS.starts_with("/api/plugins/aicx/v1"));
        assert!(plugin_api::IMPORTS.starts_with("/api/plugins/aicx/v1"));
        assert!(plugin_api::CAPABILITIES.starts_with("/api/plugins/aicx/v1"));
    }

    #[test]
    fn handoff_event_serializes_as_json() {
        let evt = HandoffEvent::new(
            "abc123".into(),
            HandoffState::Approved,
            Some("all checks passed".into()),
        );
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("approved"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn handoff_state_await_approval_roundtrip() {
        let state = HandoffState::AwaitingApproval;
        let json = serde_json::to_string(&state).unwrap();
        let back: HandoffState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}
