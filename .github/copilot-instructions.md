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
- `cargo test -p aegisqr-core scenario_roundtrip_file_and_qr_reconstruct -- --exact`
- `cargo test -p aegisqr-core path_traversal_in_raw_original_name_is_blocked -- --exact`
- `cargo test -p aegisqr-core auto_execute_requested_without_capable_is_normalised_to_false -- --exact`
- `cargo run -p aegisqr-cli -- --help`
- `cargo run -p aegisqr-ui`
- `./packaging/install.sh --help` and `./packaging/install.ps1 -Help` exercise the portable installer entry points documented in `docs/portable-install.md`.

## High-level architecture

- This is a Rust workspace, but the implemented product behavior is concentrated in `crates/aegisqr-core/src/lib.rs`; most sibling crates are stubs or future extension points, not alternate implementations.
- `aegisqr-core` owns the AQR1 format types, deterministic CBOR serialization, cryptography, trust verification, pack/unpack flows, quarantine logic, and QR packet export/import.
- The end-to-end pipeline is: inspect input type -> tar directories in memory when needed -> compress -> encrypt with bundle/policy-bound context -> sign -> write `AQR1` magic plus deterministic CBOR. The reverse path is verify signature and trust -> verify chunk integrity -> decrypt -> decompress -> restore with traversal and quarantine checks.
- `crates/aegisqr-cli/src/main.rs` and `crates/aegisqr-ui/src/main.rs` are intentionally thin front ends. They collect input, resolve passphrases, and delegate to core APIs such as `pack_to_file`, `verify_capsule`, `unpack_capsule`, `stage_capsule`, `export_qr_packets`, and `import_qr_packets`.
- `SPEC.md` is the wire-format contract for AQR1. Changes to header fields, signature coverage, chunk layout, or QR packet structure must stay synchronized across `SPEC.md`, `aegisqr-core`, and the scenario tests.
- `README.md` is the user-facing contract for CLI semantics, passphrase handling, quarantine behavior, and install flows. Keep examples aligned with the real CLI surface.
- Scenario coverage lives in `crates/aegisqr-core/tests/integration_scenarios.rs`; smaller regression tests stay inline in `crates/aegisqr-core/src/lib.rs`.
- Portable release packaging is defined in `.github/workflows/release-portable.yml` and `packaging/`. Releases are built from `cargo build -p aegisqr-cli --release --locked`, then wrapped as `aegisqr-<target>.tar.gz` or `.zip` with a top-level `aegisqr-<target>` directory.
- Each portable bundle contains only the CLI binary (`aegisqr` or `aegisqr.exe`), `manifest.json`, and `trust-store.example.json`. The workflow also publishes `SHA256SUMS`, and both installers use that checksum file unless the caller explicitly opts out.
- `apps/desktop-tauri`, `apps/mobile`, `bindings/node`, and `bindings/python` are placeholder directories today; do not infer active implementation work from their presence alone.

## Key conventions

- Preserve the security boundary from `README.md` and `THREAT_MODEL.md`: inspecting, verifying, decrypting, unpacking, staging, and restoring never execute payloads.
- Keep the deny-by-default posture intact: `auto_execute_default` remains `false`, `requires_signature` remains `true`, `requires_policy` remains `true`, and `ClientPolicy::default()` keeps native execution disabled and sandbox/quarantine requirements enabled.
- Auto-execute metadata must remain internally consistent: `auto_execute_requested` is normalized away unless `auto_execute_capable` is also true, and MVP behavior still denies execution even when the metadata is present.
- Keep orchestration in `aegisqr-core`; CLI and UI changes should call the core rather than reimplementing security checks, archive handling, or format logic.
- Directory packing is intentionally in-memory tar creation. Symlinks are rejected during pack, and restore rejects absolute paths, `..` traversal, symlinks, and hard links before writing anything.
- Restore behavior is conservative by design: executable-looking files are redirected into `quarantine/`, and `stage` forces all restored content into quarantine.
- Deterministic serialization matters. Capsules are `AQR1` magic bytes followed by deterministic CBOR, and signature coverage includes the expiration field when present.
- Verification is layered: signature verification precedes restore, strict trust requires a signer match in `TrustStore`, and chunk hashes are checked against ciphertext during `verify_capsule`.
- Passphrases are never accepted on the command line. Automation should use `--passphrase-stdin`; `AEGISQR_PASSPHRASE` is intentionally rejected, and passphrases/keys are zeroized where practical.
- Keep the portable install story aligned across `docs/portable-install.md`, `packaging/install.sh`, `packaging/install.ps1`, `packaging/manifest.json`, and the release workflow. If the bundle layout, archive naming, or manifest fields change, update the installers and docs together.
- The Unix installer expects a single extracted top-level bundle directory named `aegisqr-*`; do not change release archive layout casually or local archive installs will break.
- Prefer scenario-style tests for behavior changes in `aegisqr-core`, especially for format, restore, trust, and QR transport changes, because CI runs both the full workspace tests and the explicit `scenario_` pass.
