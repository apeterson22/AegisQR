# Copilot Instructions

## Build, test, and lint commands

- Rust stable is expected; CI installs `rustfmt` and `clippy`.
- `cargo fetch --locked`
- `cargo build --workspace`
- `cargo build --workspace --release --locked`
- `cargo build -p aegisqr-cli --release --locked` builds the portable-release binary that `.github/workflows/release-portable.yml` packages.
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo test --workspace --locked`
- `cargo test -p aegisqr-core scenario_ --locked` runs the scenario-focused core tests that CI calls out separately.
- `cargo test -p aegisqr-core <test_name> -- --exact` is the usual single-test form for the inline core regressions.
- `cargo test -p aegisqr-core scenario_roundtrip_file_and_qr_reconstruct -- --exact`
- `cargo test -p aegisqr-core path_traversal_in_raw_original_name_is_blocked -- --exact`
- `cargo test -p aegisqr-core auto_execute_requested_without_capable_is_normalised_to_false -- --exact`
- `cargo test -p aegisqr-core section_table_does_not_contain_stale_signature_block_hash -- --exact`
- `cargo test -p aegisqr-core --test property_placeholder property_placeholder_deterministic_encoding -- --exact`
- `cargo run -p aegisqr-cli -- --help`
- `cargo run -p aegisqr-ui`
- `./packaging/install.sh --help` and `./packaging/install.ps1 -Help` exercise the portable installer entry points documented in `docs/portable-install.md`.
- `.github/workflows/release-portable.yml` now smoke-tests the packaged installers against the generated archives; keep installer flags and bundle layout in sync with that workflow.

## High-level architecture

- This is a Rust workspace, but the implemented product behavior is concentrated in `crates/aegisqr-core/src/lib.rs`; most sibling crates are stubs or future extension points, not alternate implementations.
- `aegisqr-core` owns the AQR1 format types, deterministic CBOR serialization, cryptography, trust verification, pack/unpack flows, quarantine logic, and QR packet export/import.
- The pack pipeline is: detect payload type -> tar directories in memory when needed -> compress -> encrypt with AAD bound to bundle ID, version, section, policy hash, and payload hash -> build chunk and section tables -> sign -> write `AQR1` magic plus deterministic CBOR.
- The read paths are intentionally split. `inspect` reads only the public header without a passphrase; `verify` validates public-header/section-table/chunk-table consistency, checks signature validity, optional strict trust-store membership, and ciphertext chunk hashes; `unpack` / `stage` repeat the structural/signature checks, decrypt, verify the decrypted payload hash, decompress, and restore with traversal/symlink blocking and quarantine rules.
- `crates/aegisqr-cli/src/main.rs` and `crates/aegisqr-ui/src/main.rs` are intentionally thin front ends. They collect input, resolve passphrases, and delegate to core APIs such as `pack_to_file`, `verify_capsule`, `unpack_capsule`, `stage_capsule`, `export_qr_packets`, and `import_qr_packets`.
- `SPEC.md` is the wire-format contract for AQR1. Changes to header fields, signature coverage, chunk layout, or QR packet structure must stay synchronized across `SPEC.md`, `aegisqr-core`, and the scenario tests.
- `README.md` is the user-facing contract for CLI semantics, passphrase handling, quarantine behavior, and install flows. Keep examples aligned with the real CLI surface.
- Scenario coverage lives in `crates/aegisqr-core/tests/integration_scenarios.rs`; smaller regression tests stay inline in `crates/aegisqr-core/src/lib.rs`.
- Portable release packaging is defined in `.github/workflows/release-portable.yml` and `packaging/`. Releases are built from `cargo build -p aegisqr-cli --release --locked`, then wrapped as `aegisqr-<target>.tar.gz` or `.zip` with a top-level `aegisqr-<target>` directory.
- Each portable bundle contains only the CLI binary (`aegisqr` or `aegisqr.exe`), `manifest.json`, and `trust-store.example.json`. The workflow also publishes `SHA256SUMS`, and both installers use that checksum file unless the caller explicitly opts out.
- Repository security automation also lives in `.github`: CI, CodeQL, Dependabot, and portable-release smoke tests are part of the expected maintenance surface.
- `apps/desktop-tauri`, `apps/mobile`, `bindings/node`, and `bindings/python` are placeholder directories today; do not infer active implementation work from their presence alone.

## Key conventions

- Preserve the security boundary from `README.md` and `THREAT_MODEL.md`: inspecting, verifying, decrypting, unpacking, staging, and restoring never execute payloads.
- Keep the deny-by-default posture intact: `auto_execute_default` remains `false`, `requires_signature` remains `true`, `requires_policy` remains `true`, and `ClientPolicy::default()` keeps native execution disabled and sandbox/quarantine requirements enabled.
- Auto-execute metadata must remain internally consistent: `auto_execute_requested` is normalized away unless `auto_execute_capable` is also true, and MVP behavior still denies execution even when the metadata is present.
- Keep orchestration in `aegisqr-core`; CLI and UI changes should call the core rather than reimplementing security checks, archive handling, or format logic.
- `verify` and restore are separate trust boundaries. Strict signer enforcement only happens when callers opt into `strict_trust` with a `TrustStore`; `unpack` and `stage` do not silently add trust-store policy checks.
- Directory packing is intentionally in-memory tar creation. Symlinks are rejected during pack, and restore rejects absolute paths, `..` traversal, symlinks, and hard links before writing anything.
- Restore behavior is conservative by design: executable-looking files are redirected into `quarantine/`, and `stage` forces all restored content into quarantine.
- Deterministic serialization matters. Capsules are `AQR1` magic bytes followed by deterministic CBOR, and signature coverage includes the expiration field when present.
- Verification is layered: structural consistency checks precede restore, signature verification precedes decrypt, strict trust requires a signer match in `TrustStore`, and chunk hashes are checked against ciphertext during `verify_capsule`.
- The section table intentionally excludes `signature_block`. Signing happens after table construction, so hashing a placeholder signature block would create stale integrity data; the Ed25519 signature is the integrity mechanism for that block.
- Preserve serialized enterprise compatibility names even when Rust fields are placeholders or renamed: `aicx_sidecar`, `toon_export`, `enterprise_policy`, and `approval_tokens` remain part of the compatibility surface.
- Passphrases are never accepted on the command line. Automation should use `--passphrase-stdin`; `AEGISQR_PASSPHRASE` is intentionally rejected, and passphrases/keys are zeroized where practical.
- Keep the portable install story aligned across `docs/portable-install.md`, `packaging/install.sh`, `packaging/install.ps1`, `packaging/manifest.json`, and the release workflow. Remote archives are HTTPS-only and should require explicit checksums unless the caller intentionally uses the skip-checksum escape hatch.
- The Unix installer expects a single extracted top-level bundle directory named `aegisqr-*`; do not change release archive layout casually or local archive installs will break.
- QR import hardening is deliberate: reject out-of-range indexes, empty identifiers/hashes, conflicting duplicates, inconsistent totals/capsule hashes, and reconstructed files that do not start with `AQR1`.
- Prefer scenario-style tests for behavior changes in `aegisqr-core`, especially for format, restore, trust, and QR transport changes, because CI runs both the full workspace tests and the explicit `scenario_` pass.
