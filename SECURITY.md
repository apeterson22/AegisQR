# Security Policy: AegisQR

This document outlines the core security practices, threat assumptions, and vulnerability disclosure policies for the **AegisQR** capsule format and CLI ecosystem.

---

## 🛡️ Secure Defaults

AegisQR enforces a strict, fail-closed zero-trust security architecture:

* **Zero Auto-Execution:** Reading, importing, or decrypting a capsule never executes its contents. The `auto_execute_default` header parameter is immutably `false`.
* **Executable Isolation:** Extracted executable files (`.sh`, `.py`, `.ps1`, `.bat`, `.cmd`, `.exe`, `.dll`, `.so`, `.dylib`, `.jar`, `.wasm`) are automatically routed to a `quarantine/` subdirectory during unpack operations.
* **Insulated Cryptography:**
  - Passphrase-based encryption uses **XChaCha20-Poly1305 AEAD** with **Argon2id** key derivation.
  - Digital signatures and metadata authenticity are enforced using **Ed25519**.
* **Path-Traversal Protection:** Unsafe parent directory traversals (`..` injections) and filesystem root redirections are strictly blocked at the library level. Symlinks and hard links are disallowed in all capsule configurations.

---

## ⚡ Threat Assumptions

Our design operates under the following threat model constraints:
1. **Adversarial Transport:** We assume transit paths (network, printed QR sheets, NFC tags) are insecure and subject to hostile package alteration or injection.
2. **Untrusted Signers:** Capsule signatures are rejected unless their corresponding public key is explicitly trusted in the local trust stores (`/etc/aegisqr/trusted_keys.d/`).
3. **Host Isolation:** AI agents and shell environments must be completely shielded from accidental execution of restored payloads.

---

## 🔒 Privacy & Offline Commitment

AegisQR operates **100% offline**:
* **No Telemetry:** We collect zero metrics, tracking data, or usage diagnostics.
* **Offline Licensing:** License status checks and validations run strictly locally against offline public Ed25519 keys, preserving operational confidentiality.

---

## 🐛 Vulnerability Disclosure

If you identify a security issue, please do not open a public issue. Report it privately to the maintainers or utilize GitHub's Private Vulnerability Reporting features to coordinate a fix and release.
