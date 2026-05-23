# AICX ↔ AegisQR Enterprise Integration Contract v2

> **Status:** Implemented — see crates `aegisqr-agent`, `aegisqr-audit`,
> `aegisqr-policy`, `aegisqr-repo`, and the `approve`/`handoff` CLI subcommands.

---

## Summary

Keep the integration **REST/JSON over HTTPS** for the plugin API, with
**token-based auth** as the default security model.  Add **TOON** as an
AI-optimized response/serialisation option for model-facing consumers, while
keeping JSON as the canonical contract.  Use **SSH** only where it fits
operationally: secure admin access, tunnelled workflows, or repository-side
automation that benefits from key-based access.

---

## Architecture

```
CI Pipeline  →  AICX produces .aicx + sidecar.json
                                    │
            aegisqr pack --aicx-sidecar sidecar.json
                                    │
            ┌────────────────────────────────────────┐
            │            AegisQR capsule (.aqr)       │
            │  • Ed25519 signature over core content  │
            │  • XChaCha20-Poly1305 payload           │
            │  • AicxSidecar (manifest_hash, coords)  │
            │  • EnterprisePolicy (approval gate)     │
            │  • ApprovalTokens (after signing)       │
            │  • AuditLog (lifecycle events)          │
            └────────────────────────────────────────┘
                                    │
            aegisqr approve (security gate)
                                    │
            aegisqr export qr  (optional air-gap)
            aegisqr import qr
                                    │
            aegisqr handoff  →  handoff-package.json
                                    │
            Artifactory/Nexus Plugin
              calls validate_handoff_package()
              on Approved: calls repo REST API
              stores bundle_id + audit_log as provenance
```

---

## Key changes from v1

### Plugin API endpoints (`/api/plugins/aicx/v1`)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/exports` | Initiate an export job |
| `POST` | `/imports` | Initiate an import job |
| `GET`  | `/jobs/{job_id}` | Poll job status |
| `POST` | `/jobs/{job_id}/approve` | Approve a pending job |
| `POST` | `/jobs/{job_id}/cancel` | Cancel a job |
| `GET`  | `/capabilities` | Plugin/version capabilities |

All paths are declared as constants in `aegisqr_repo::plugin_api`.

**Default content type:** `application/json`  
**AI-facing alternate:** `application/toon` — same schema, TOON wire format

### Security and transport

- **HTTPS** for all plugin REST traffic.
- **Token auth** for API access: OAuth2/OIDC bearer tokens, PATs, or scoped
  service tokens.  Represented by `aegisqr_repo::AuthConfig` / `AuthType`.
- **SSH** for operational access where needed: admin workflows, secured bastion
  access, or repository host automation.
- No plaintext or unauthenticated handoff paths.

### AICX bundle fields (`aegisqr_agent::AicxSidecar`)

```rust
pub struct AicxSidecar {
    pub bundle_id: String,
    pub manifest_hash: String,          // BLAKE3 of .aicx archive bytes
    pub artifact_coordinates: Vec<ArtifactCoordinate>,
    pub aicx_format_version: String,
    pub provenance: Option<ProvenanceRecord>,
    pub serialization_profile: SerializationProfile, // NEW: json | toon
}
```

The existing bundle contract is preserved.  The `serialization_profile` field
is additive (defaults to `json`) and tells the plugin which wire format the
producer prefers for model-facing consumers.

### AegisQR handoff states (`aegisqr_repo::HandoffState`)

```
Pending → AwaitingApproval → Approved → Delivered
                           ↘ Rejected
              * any state → Failed(String)
```

Every state transition emits a [`HandoffEvent`] that is machine-readable and
serialisable as JSON or TOON.  Treat TOON as the model-friendly projection of
the same state machine — not a separate workflow.

### AegisQR planning file

This file (`docs/plan-enterprise.md`) is the canonical reference for:

- Plugin API endpoint paths and content types
- AICX bundle field definitions and `serialization_profile` semantics
- AegisQR handoff state machine and event schema
- Auth expectations (HTTPS + token; SSH operational-only)
- Payload schema for inter-component contracts

---

## Crate responsibilities

| Crate | Role |
|---|---|
| `aegisqr-agent` | `AicxSidecar`, `ArtifactCoordinate`, `ProvenanceRecord`, `SerializationProfile` |
| `aegisqr-audit` | `AuditRecord`, `AuditEvent`, `AuditAction`, `ApprovalToken` (with Ed25519 verify) |
| `aegisqr-policy` | `EnterprisePolicy`, `RepoTarget`, `RepoType` |
| `aegisqr-core` | Capsule format, pack/verify/approve, `CapsuleInspection` |
| `aegisqr-repo` | `HandoffPackage`, `HandoffState`, `HandoffEvent`, `RepositoryCoordinates`, `AuthConfig`, plugin API constants, `validate_handoff_package()` |
| `aegisqr-cli` | `pack`, `inspect`, `verify`, `unpack`, `stage`, `export qr`, `import qr`, `approve`, `handoff`, `keygen` |
| `aegisqr-ui` | Interactive wrapper for all CLI flows including Approve and Handoff |

---

## CLI reference

```bash
# Generate an Ed25519 signing key
aegisqr keygen --out sec-officer.key

# Pack an AICX archive with sidecar
aegisqr pack artifact.aicx --aicx --aicx-sidecar sidecar.json \
    --passphrase "..." --out release.aqr

# Verify (strict trust optional)
aegisqr verify release.aqr [--strict-trust --trust-store corp.json]

# Approve (security gate)
aegisqr approve release.aqr \
    --signer-id sec-officer \
    --signing-key sec-officer.key

# Optional air-gap via QR
aegisqr export qr release.aqr --out qr-frames/
aegisqr import qr ./qr-frames --out release-recv.aqr

# Prepare handoff package for the plugin
aegisqr handoff release.aqr \
    --target-coords nexus-target.json \
    --out handoff-package.json

# Inspect (shows sidecar + approval status, no decryption)
aegisqr inspect release.aqr
```

### Key file format

Signing keys are **hex-encoded 32-byte Ed25519 seeds** (64 ASCII characters).
Generate with `aegisqr keygen` and protect like a password.

### `target-coords` JSON schema

```json
{
  "repo_type": "nexus",
  "base_url": "https://repo.example.com",
  "repository": "libs-release-local",
  "group": "com.example",
  "name": "my-service",
  "version": "1.4.2",
  "classifier": null
}
```

---

## Plugin integration guide

1. **Receive `handoff-package.json`** from the AegisQR operator.
2. **Call `validate_handoff_package(&pkg, trust_store)`** from `aegisqr-repo`.
3. **Check `result.state`**:
   - `Approved` → proceed to step 4.
   - `AwaitingApproval` → request additional approvals.
   - `Failed(msg)` → surface error to the operator.
4. **Inject credentials**: fill `auth_config.token` from your secure store.
5. **Call Artifactory/Nexus REST API** at the coordinates in `target_coords`.
6. **Store provenance**: save `bundle_id` and `audit_log` as artifact metadata.

The plugin never re-implements crypto, path safety, or capsule parsing.

---

## Test plan

- Verify export/import jobs over HTTPS with token auth.
- Verify TOON and JSON render the same semantic payload (`serialization_profile`
  field carries the hint; field names and types are identical).
- Verify SSH-backed admin or tunnel flows do not bypass validation or
  authorisation (no plaintext handoff paths in `aegisqr-repo`).
- Exercise state transitions: `pack` → `approve` → `handoff` → `Approved`.
- Exercise `AwaitingApproval` when `min_approvals` is not yet satisfied.
- Exercise `Failed` path on tampered capsule.
- Verify `approval_ttl_seconds` expiry causes `AwaitingApproval`.

---

## Assumptions

- JSON stays the source-of-truth wire format; TOON is an alternate projection
  for AI consumers — same schema, same field semantics.
- SSH is an operational/security transport, not the primary plugin API protocol.
- Token auth is mandatory for automated access; unauthenticated access is out
  of scope.
- AegisQR continues to own sealing, encryption, approval, and secure transfer
  behaviour.
- AegisQR never parses `.aicx` internals — the archive is an opaque blob.
- AegisQR never calls Artifactory/Nexus APIs — that is the plugin's job.
