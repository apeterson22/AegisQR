# AegisQR

AegisQR is a **secure, encrypted, signed, and compressed QR-native capsule format** (`.aqr`) for safely packaging and transferring files, code, executables, workflows, model artifacts, configurations, secret placeholders, firmware, and agent tasks.

---

## Table of Contents

1. [What is AegisQR?](#what-is-aegisqr)
2. [Why use AegisQR?](#why-use-aegisqr)
3. [When to use AegisQR](#when-to-use-aegisqr)
4. [Where to use AegisQR](#where-to-use-aegisqr)
5. [Security model and defaults](#security-model-and-defaults)
6. [Build and install](#build-and-install)
7. [CLI reference](#cli-reference)
8. [Interactive UI](#interactive-ui-lightweight-alternative-to-the-cli)
9. [Examples](#examples)
10. [AQR1 capsule format overview](#aqr1-capsule-format-overview)
11. [Project status and roadmap](#project-status-and-roadmap)

---

## What is AegisQR?

An **AegisQR capsule** (`.aqr` file) is a self-describing, tamper-evident bundle that:

- **Encrypts** its payload with XChaCha20-Poly1305 and Argon2id key derivation.
- **Signs** the entire capsule (header, policy, agent metadata, payload hash, chunk table) with Ed25519.
- **Compresses** the payload (zstd at configurable levels) before encrypting.
- **Splits** the capsule into QR-code-sized packets for air-gap transfer or physical hand-off.
- **Quarantines** executable file types on restore — payloads are never automatically executed.
- **Carries its own policy** block that enforces safe defaults (no auto-execute, sandboxing required).

Compared to a simple encrypted zip or tarball, an AegisQR capsule adds:
- Authenticated encryption (the key is bound to bundle identity and policy state — tampering is detected).
- An immutable public header readable without a passphrase (useful for inspection kiosks and routers).
- A chunk table for granular integrity verification and future Reed-Solomon recovery.
- A structured agent-index that describes what the capsule contains without decrypting it.
- QR-packet transport designed for physical or off-line data paths.

---

## Why use AegisQR?

| Concern | How AegisQR addresses it |
|---|---|
| Payload confidentiality | XChaCha20-Poly1305 AEAD with Argon2id; ciphertext is authenticated |
| Integrity / tamper detection | Ed25519 signature covers header, policy, payload hash, chunk table |
| Accidental execution | Executable file types are always quarantined; auto-execute default is `false` |
| Air-gap transfer | Capsule splits into QR packets; each packet carries its own checksum |
| Policy enforcement | Embedded `ClientPolicy` block defines execution constraints |
| Auditability | Public header is inspectable without decryption; structured agent index |
| Future-proof format | Magic bytes `AQR1`, versioned structure, additive CBOR fields |

---

## When to use AegisQR

Use AegisQR when you need to:

- **Transfer files across an air gap** using QR codes printed on paper or displayed on a screen.
- **Hand off a software update, firmware image, or script** to a machine that has no network access.
- **Package secrets placeholders, configuration files, or agent tasks** that must be encrypted at rest and in transit.
- **Distribute a signed artefact** (model weights, policy bundle, executable) to a recipient who must verify the sender's identity before unpacking.
- **Stage potentially executable content for human review** before it is manually inspected and run.
- **Send files physically** (NFC tag, printed QR page, USB stick) when network transport is unavailable or untrusted.

Do **not** use AegisQR today for:
- Real-time or streaming data (AegisQR is a batch capsule format).
- Situations where the recipient must run the payload automatically (auto-execute is disabled in MVP and requires explicit future policy gates).

---

## Where to use AegisQR

| Context | Recommended entry point |
|---|---|
| CI/CD pipeline, scripted workflows | `aegisqr-cli` binary (`cargo run -p aegisqr-cli`) |
| Desktop interactive use | `aegisqr-ui` interactive app (`cargo run -p aegisqr-ui`) |
| Rust application integration | `aegisqr-core` crate (add as a dependency) |
| Air-gap workstation (pack side) | CLI `pack` + `export qr` → print QR sheets |
| Air-gap workstation (receive side) | CLI `import qr` + `verify` + `unpack` / `stage` |
| Secure hand-off kiosk | `inspect` (no passphrase needed) to show public header |

---

## Security model and defaults

- **Scanning does not execute** — reading or decrypting a capsule never runs its payload.
- **Decrypting does not execute** — `unpack` / `stage` write files to disk; they never call `exec`.
- **Restoring does not execute** — even a fully unpacked capsule requires a deliberate manual step to run anything.
- **Auto-execute default is always `false`** — the `auto_execute_default` field in every capsule header is immutably `false` in this implementation.
- **Executable file types are quarantined** — on restore, files with extensions `.sh .py .ps1 .bat .cmd .exe .dll .so .dylib .jar .wasm` are placed in a `quarantine/` subdirectory instead of their nominal output path.
- **Signature is required** — `requires_signature: true` is baked into every capsule produced by this implementation.
- **Policy is required** — an embedded `ClientPolicy` block travels with every capsule; the default policy disables native execution and requires a sandbox.
- **Path traversal is blocked** — `..` components and absolute paths in tar entries or `original_name` are rejected at restore time.
- **Symlinks are blocked** — tar entries that are symlinks or hard links are rejected on pack and restore.

---

## Build and install

### Prerequisites

- Rust 1.78+ (stable toolchain)
- `cargo` in `$PATH`

### Build everything

```bash
git clone https://github.com/apeterson22/AegisQR
cd AegisQR
cargo build --workspace
```

### Run the test suite

```bash
cargo test --workspace
```

### Install the CLI globally

```bash
cargo install --path crates/aegisqr-cli
```

After installation the `aegisqr` binary is on your `$PATH`.

---

## CLI reference

All commands follow the pattern:

```
aegisqr <subcommand> [options]
```

Run `aegisqr --help` or `aegisqr <subcommand> --help` for up-to-date flag descriptions.

---

### `pack` — create a capsule

```bash
aegisqr pack <INPUT> --out <BUNDLE.aqr> --passphrase <PASS> [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--compression <PROFILE>` | `balanced` | `none` / `fast` / `balanced` / `qr-basic` |
| `--aicx` | off | Treat `INPUT` as an AICX archive (`payload_type: aicx-archive`) |
| `--auto-execute-capable` | off | Mark the capsule as capable of auto-execution (metadata only) |
| `--auto-execute-requested` | off | Declare intent to auto-execute (requires `--auto-execute-capable`) |

`INPUT` can be a single file **or** a directory (packed as a tar archive).

```bash
# Pack a single file
aegisqr pack report.pdf --out report.aqr --passphrase "hunter2"

# Pack a directory
aegisqr pack ./my-project --out project.aqr --passphrase "hunter2" --compression qr-basic

# Pack an AICX archive
aegisqr pack model.aicx --out model.aqr --passphrase "hunter2" --aicx
```

---

### `inspect` — read the public header (no passphrase required)

```bash
aegisqr inspect <BUNDLE.aqr>
```

Prints the public header as pretty-printed JSON. Useful for routing and classification without decryption.

```bash
aegisqr inspect report.aqr
```

---

### `verify` — check signature and chunk integrity

```bash
aegisqr verify <BUNDLE.aqr> [--strict-trust] [--trust-store <STORE.json>]
```

| Option | Description |
|---|---|
| `--strict-trust` | Require the signer to be listed in the trust store; fails if no trust store is provided |
| `--trust-store <PATH>` | Path to a JSON `TrustStore` file containing trusted public keys |

```bash
# Verify signature only (any signer)
aegisqr verify report.aqr

# Verify and require a known signer
aegisqr verify report.aqr --strict-trust --trust-store /etc/aegisqr/trust.json
```

---

### `unpack` — decrypt and restore payload

```bash
aegisqr unpack <BUNDLE.aqr> --out <DIR> --passphrase <PASS>
```

- Verifies the signature before decrypting.
- Extracts all files to `DIR`.
- Files with executable extensions go to `DIR/quarantine/`.

```bash
aegisqr unpack report.aqr --out ./restored --passphrase "hunter2"
```

---

### `stage` — quarantine-only restore

```bash
aegisqr stage <BUNDLE.aqr> --out <DIR> --passphrase <PASS>
```

Identical to `unpack` except **all** files go to `DIR/quarantine/` regardless of type. Use this for maximum caution when the origin of the capsule is unknown.

```bash
aegisqr stage suspicious.aqr --out ./staging --passphrase "hunter2"
```

---

### `export qr` — split capsule into QR packets

```bash
aegisqr export qr <BUNDLE.aqr> --out <QR_DIR> [--packet-size <BYTES>] [--png]
```

| Option | Default | Description |
|---|---|---|
| `--packet-size <N>` | `800` | Maximum bytes per QR packet |
| `--png` | off | Also write a `.png` QR image per packet (requires `qr-png` feature, enabled by default) |

Each packet is written as both a `.cbor` file and a `.json` file to `QR_DIR`.

```bash
aegisqr export qr report.aqr --out ./qr-packets --packet-size 600 --png
```

---

### `import qr` — reassemble capsule from QR packets

```bash
aegisqr import qr <QR_DIR> --out <RECOVERED.aqr>
```

Reads all `.cbor` packets (or `.json` if no `.cbor` files are found) from `QR_DIR`, verifies per-packet checksums, verifies the overall capsule hash, and writes the reconstructed capsule.

```bash
aegisqr import qr ./qr-packets --out recovered.aqr
```

---

## Interactive UI (lightweight alternative to the CLI)

The `aegisqr-ui` crate provides a guided terminal menu for all operations. It prompts for paths, passphrases (with echo-off), and options interactively — no flags to remember.

```bash
cargo run -p aegisqr-ui
```

On startup you will see:

```
AegisQR Interface
Secure defaults: scan/decrypt/restore never execute payloads.

Choose an action:
  1) Pack
  2) Inspect
  3) Verify
  4) Unpack
  5) Stage
  6) Export QR
  7) Import QR
  8) Exit
```

Each flow prompts for only the inputs required for that operation. Passphrases are read with hidden input (via `rpassword`). The Pack flow asks for the passphrase twice and rejects mismatches.

---

## Examples

### Personal air-gap file transfer

Pack a sensitive document on the sending machine:

```bash
aegisqr pack secret.pdf --out secret.aqr --passphrase "correct-horse-battery"
aegisqr export qr secret.aqr --out ./qr --packet-size 500 --png
# Print the PNG sheets or display them on screen
```

Reassemble and restore on the receiving machine:

```bash
# Scan QR images into a directory, then:
aegisqr import qr ./scanned-qr --out secret.aqr
aegisqr verify secret.aqr
aegisqr unpack secret.aqr --out ./received --passphrase "correct-horse-battery"
```

---

### Enterprise signed distribution

A CI pipeline packs and the receiving host verifies against a pinned trust store:

```bash
# Pack (CI side)
aegisqr pack ./dist --out release.aqr --passphrase "$CI_PASSPHRASE" --compression qr-basic

# Inspect without decrypting (routing / SIEM)
aegisqr inspect release.aqr

# Verify with strict trust (receiving host)
aegisqr verify release.aqr --strict-trust --trust-store /etc/aegisqr/corp-trust.json

# Stage first for human review
aegisqr stage release.aqr --out /var/staging --passphrase "$HOST_PASSPHRASE"
# Review quarantine/ contents, then manually promote
```

---

### Staging unknown content

When the origin of a capsule is not fully trusted, always stage instead of unpack:

```bash
aegisqr stage unknown.aqr --out ./sandbox --passphrase "mypass"
# All files land in ./sandbox/quarantine/
# Manually inspect before promoting any executable
```

---

### Programmatic use (Rust)

Add `aegisqr-core` to your `Cargo.toml`:

```toml
[dependencies]
aegisqr-core = { path = "crates/aegisqr-core" }
```

```rust
use aegisqr_core::{pack_to_file, verify_capsule, unpack_capsule, PackOptions};
use std::path::Path;

// Pack
let capsule = pack_to_file(
    Path::new("input.txt"),
    Path::new("output.aqr"),
    "my-passphrase",
    PackOptions::default(),
)?;

// Verify (no passphrase needed)
verify_capsule(Path::new("output.aqr"), None, false)?;

// Unpack
unpack_capsule(Path::new("output.aqr"), Path::new("out-dir"), "my-passphrase")?;
```

---

## AQR1 capsule format overview

| Field | Details |
|---|---|
| Magic bytes | `AQR1` (4 bytes, unencrypted) |
| Encoding | Deterministic CBOR after the magic |
| Encryption | XChaCha20-Poly1305; key derived via Argon2id from passphrase + 16-byte salt |
| Signature | Ed25519; covers header, section table, policy block, payload hash, agent index hash, chunk table hash |
| Compression | zstd (levels 1 / 5 / 9 for fast / balanced / qr-basic; or none) |
| Chunk size | 1024 bytes; each chunk carries a BLAKE3 hash |
| QR packet magic | `AQRP`; each packet carries its own BLAKE3 checksum and the full capsule hash |

See [`SPEC.md`](SPEC.md) for the complete schema.

---

## AegisQR vs AICX

AICX is a separate repository. AegisQR includes an integration interface (`payload_type: aicx-archive`) so future versions can wrap external AICX archives, but does not implement AICX internally.

---

## Project status and roadmap

MVP is implemented with:

- Rust-first workspace crates
- AQR1 capsule data model and deterministic serialisation
- Passphrase encryption, Ed25519 signing, zstd compression
- QR packet export and import with full hash verification
- Safe staging and quarantine with path-traversal and symlink protection
- Unit tests, integration tests, and CI

See [`PLAN.md`](PLAN.md) for the phased roadmap (AICX deeper integration, hardware keys, animated QR, mobile scanner, WASM runtime, Reed-Solomon recovery, reproducible builds).

