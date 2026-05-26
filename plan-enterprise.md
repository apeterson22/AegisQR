# AegisQR Enterprise Integration Brief

## Summary
AegisQR is the secure courier and policy layer for enterprise artifact exchange. It receives validated AICX bundles from repository plugins, applies encryption, signing, QR transport, approval controls, and recovery handling, then releases the payload back to Artifactory or Nexus for final import.

JSON over HTTPS is the canonical integration protocol. TOON is an optional AI-optimized projection of the same payloads. SSH is reserved for admin access, trusted tunnels, and host automation; it does not replace authenticated HTTPS API traffic.

## Plugin Contract
Base path: `/api/plugins/aicx/v1`

Consumed endpoints:
- `GET /capabilities`
- `POST /exports`
- `GET /jobs/{job_id}`
- `POST /jobs/{job_id}/approve`
- `POST /jobs/{job_id}/cancel`
- `POST /imports`
- `POST /imports/{job_id}/finalize`

Expected behavior:
- Export jobs collect repository artifacts and package them with AICX.
- Import jobs accept an AegisQR-delivered capsule, verify it, then restore into the target repository.
- Every job transition must be observable and machine-readable.

## AICX Bundle Fields
Treat the AICX bundle as the validated artifact exchange envelope, not the encrypted transport layer.

Required fields:
- `bundle_id`
- `format`
- `format_version`
- `serialization_profile`
- `created_at`
- `created_by`
- `source_system`
- `source_repository`
- `target_system`
- `target_repository`
- `package_type`
- `artifact_count`
- `hash_algorithm`
- `compression_profile`
- `manifest_digest`
- `payload_digest`
- `sidecar_digest`
- `artifacts[]`
- `sidecar`
- `provenance`

Artifact record minimum:
- `artifact_id`
- `coordinates`
- `repository_path`
- `package_type`
- `version`
- `classifier`
- `size_bytes`
- `digests`
- `labels`
- `dependencies`
- `chunk_refs`
- `restore_hint`

## AegisQR Handoff States
Keep the state machine explicit and asynchronous.

- **AICX-owned:** `queued` → `collected` → `bundled` → `validated`
- **AegisQR-owned:** `sealed` → `signed` → `encrypted` → `encoded` → `transferred` → `received` → `verified` → `approved` → `decrypted` → `released` → `restored` → `completed`
- **Terminal failure states:** `failed`, `cancelled`, `expired`

Rules:
- AegisQR must never assume an AICX bundle is trustworthy without signature and integrity checks.
- AegisQR must not reimplement archive parsing, path validation, or restore logic; those stay in AICX.
- Import into the repository only occurs after `verified` and `approved`.

## Security and Transport
- Use HTTPS for all plugin API traffic.
- Require token-based authentication for machine access.
- Allow SSH only for admin access, tunneling, or host-level automation.
- Keep auto-execution disabled by default; execution requires explicit local policy and trust verification.
- Preserve the invariant that scanning, decrypting, and restoring do not imply execution.
- Preserve checksum-first handling for portable/offline archive distribution; direct remote archive installs should remain HTTPS-only and checksum-verified unless an operator explicitly opts out.
- Treat QR transport as a verified courier channel: reject packets with inconsistent index/total/hash/checksum metadata or conflicting duplicates before any import/finalize step.
- Preserve enterprise compatibility field names in the wire contract even if implementation structs rename placeholder fields internally.

## Implementation Guidance
- Keep the plugin thin and integrate by contract, not by shared archive code.
- Emit audit-friendly events for every handoff transition.
- Render the same semantic payloads as JSON or TOON without changing state meaning.
- Treat AICX as the artifact format, not the secure transport.
- Treat AegisQR as the secure courier, not the repository of record.
- Keep release automation aligned with enterprise expectations: portable bundles should be checksum-published, installer-smoke-tested, and scanned by repository security automation such as CodeQL and Dependabot.

## Assumptions
- Artifactory and Nexus remain the repository systems of record.
- AICX owns bundle correctness and metadata structure.
- AegisQR owns seal, sign, encrypt, QR transport, policy enforcement, and approval gates.
- Enterprise agents should use this brief as the implementation contract for AegisQR-side work.
