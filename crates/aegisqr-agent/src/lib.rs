use serde::{Deserialize, Serialize};

/// Preferred wire serialization format for AI-facing or plugin consumers.
///
/// JSON is the canonical source-of-truth format; TOON is an AI-optimized
/// alternate projection of the same schema with identical field semantics.
/// AegisQR carries this flag but does not render TOON output itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SerializationProfile {
    #[default]
    Json,
    Toon,
}

/// Repository coordinates identifying a single artifact within an artifact store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactCoordinate {
    /// Logical repository name (e.g. `"libs-release-local"`).
    pub repo: String,
    /// Maven-style group or namespace (e.g. `"com.example"`).
    pub group: String,
    /// Artifact name (e.g. `"my-service"`).
    pub name: String,
    /// Artifact version string (e.g. `"1.4.2"`).
    pub version: String,
    /// Optional classifier suffix (e.g. `"sources"`, `"javadoc"`).
    pub classifier: Option<String>,
}

/// Provenance metadata captured by the CI/CD pipeline that produced the bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    /// CI system run identifier (e.g. GitHub Actions run ID).
    pub ci_run_id: Option<String>,
    /// URL to the pipeline run page.
    pub pipeline_url: Option<String>,
    /// Identity of the build agent or service account.
    pub builder_identity: Option<String>,
    /// Full source VCS commit SHA.
    pub source_commit: Option<String>,
}

/// Sidecar metadata produced by AICX and embedded in an AegisQR capsule.
///
/// AegisQR treats `.aicx` archives as opaque blobs; the sidecar conveys
/// artifact identity and provenance without requiring AegisQR to parse
/// archive internals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AicxSidecar {
    /// Matches the AICX archive's own bundle identity.
    pub bundle_id: String,
    /// BLAKE3 hex digest of the complete `.aicx` archive file.
    ///
    /// AegisQR validates this against the packed bytes at seal time when the
    /// payload type is `AicxArchive`.
    pub manifest_hash: String,
    /// One entry per artifact contained in the bundle.
    pub artifact_coordinates: Vec<ArtifactCoordinate>,
    /// Semantic version of the AICX format used to produce this bundle.
    pub aicx_format_version: String,
    /// Optional provenance captured from the build pipeline.
    pub provenance: Option<ProvenanceRecord>,
    /// Preferred serialization profile for plugin/AI consumers of this sidecar.
    ///
    /// Does not affect the AegisQR capsule's own CBOR/JSON encoding.
    #[serde(default)]
    pub serialization_profile: SerializationProfile,
}
