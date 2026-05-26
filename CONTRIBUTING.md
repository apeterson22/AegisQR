# Contributing to AegisQR

This document outlines the coding, contribution, security, and privacy standards specifically for the **AegisQR** repository. All developers and agents contributing to this project must follow these rules.

---

## 🛠️ Contribution Standards

* **PR Flow:** The `main` branch is protected. All contributions must be submitted via a **Pull Request (PR)** and approved by a maintainer prior to merge.
* **Agent Handoff:** In the event of token exhaustion or agent transition, you must generate an `AGENT_HANDOFF.md` package and push your working progress to an `agent-handoff/` branch.

---

## 💻 Rust Coding Standards

AegisQR is a highly secure, mission-critical cryptographic capsule library. Code quality must remain exceptional:

### 1. Formatting & Code Style
* **Rustfmt:** Format all Rust files using `cargo fmt` before staging.
* **Clippy:** Address all warnings from `cargo clippy`. Unchecked warnings will cause CI pipelines to fail.
* **Preserve Documentation:** Retain all existing inline comments, module docs, and structural docstrings.
* **No Unsafes:** Avoid `unsafe` Rust blocks unless absolutely necessary and mathematically proven safe.

### 2. Workspace Management
AegisQR is organized as a Cargo workspace:
* `crates/aegisqr-core/`: Cryptographic models, offline licensing, safe path validation, and parsing logic.
* `crates/aegisqr-cli/`: The command-line interface binary.
* `crates/aegisqr-ui/`: The lightweight interactive visual interface.
* Keep workspace versions unified under the featured release tag (`"0.1.0-featured"`).

### 3. CI/CD & Testing Guidelines
* **Sequential Testing:** Always run tests with a single thread to prevent directory-overwriting race conditions:
  ```bash
  RUST_TEST_THREADS=1 cargo test
  ```
* **Local Self-Hosted Runner:** The GitHub Actions workflow targets the `aegis-local` self-hosted runner. Ensure Homebrew-based python dependencies are bypassed without overriding systems pip packages.

---

## 🔗 The Sibling Integration Contract (AICX Coupling)

AegisQR and `aicx` communicate **strictly via decoupled command-line execution and metadata sidecars**:
* **Decoupled Architecture:** Under no circumstances should AegisQR crates introduce Cargo-level dependencies on `aicx` crates.
* **Sidecar Validation:** Maintain rigorous fail-closed metadata checks. If `--aicx-strict` is active, missing, malformed, or mismatching digests must immediately quarantine operations and abort.
* **Auto-Discovery:** Maintain robust autodiscovery logic for companion `.sidecar.json` profiles.

---

## 🛡️ Security & Privacy Standards

* **Auto-Execute Denied:** The `auto_execute_default` field in capsule headers must remain immutably `false`.
* **Path-Traversal Block:** Ensure path validation rejects absolute paths or `..` traversals in all capsule extractions.
* **Executable Quarantine:** Any unpacked files matching executable extensions must be quarantined in the `quarantine/` folder.
* **Zero Telemetry:** AegisQR does not collect telemetry or communicate over networks. License validations (`.aqlic`) must execute entirely offline.
* **Rotatable Trust Store:** Rotated verification keys must be loaded exclusively from the local `/etc/aegisqr/trusted_keys.d/` directory.
