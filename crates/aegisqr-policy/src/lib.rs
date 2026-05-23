use serde::{Deserialize, Serialize};

/// The type of artifact repository the capsule targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RepoType {
    Artifactory,
    Nexus,
}

/// Repository routing target embedded in a capsule's enterprise policy.
///
/// Credentials are intentionally excluded; the repository plugin supplies
/// those at runtime via its own credential store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoTarget {
    pub repo_type: RepoType,
    /// Base URL of the Artifactory/Nexus instance (e.g. `"https://repo.example.com"`).
    pub base_url: String,
    /// Logical repository name within the instance (e.g. `"libs-release-local"`).
    pub repository: String,
}

/// Enterprise security and approval policy embedded in a capsule.
///
/// Evaluated by `verify_capsule` and `validate_handoff_package` before
/// any approval or delivery action is permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterprisePolicy {
    /// When `true`, the capsule must have at least `min_approvals` valid
    /// [`ApprovalToken`](aegisqr_audit::ApprovalToken)s before it can be
    /// delivered.
    pub approval_required: bool,
    /// Minimum number of distinct valid approval tokens required.
    pub min_approvals: u8,
    /// Signer IDs whose approval tokens count towards `min_approvals`.
    pub approvers: Vec<String>,
    /// How long (seconds) an approval token remains valid after issuance.
    /// `None` means tokens never expire.
    pub approval_ttl_seconds: Option<u64>,
    /// Optional routing hint for the Artifactory/Nexus plugin.
    pub repo_target: Option<RepoTarget>,
}
