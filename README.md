# AegisQR

AegisQR is a secure encrypted, signed, compressed, QR-native agent capsule format (`.aqr`) for packaging and transferring files, code, executables, workflows, model artifacts, configs, secrets placeholders, firmware placeholders, and agent tasks.

## AegisQR vs AICX

AICX is a separate repository. This project includes an integration interface (`payload_type: aicx-archive`) so future versions can wrap external AICX archives, but does not implement AICX internally.

## Secure defaults

- Scanning does not execute
- Decrypting does not execute
- Restoring does not execute
- Runtime execution is denied in MVP
- Auto-execute default is always `false`
- Signature and policy gates are required for future execution paths

## Build and install

```bash
cargo build --workspace
cargo test --workspace
cargo run -p aegisqr-cli -- --help
```

## Quickstart

```bash
aegisqr pack <input> --out <bundle.aqr> --passphrase <pass>
aegisqr inspect <bundle.aqr>
aegisqr verify <bundle.aqr>
aegisqr unpack <bundle.aqr> --out <dir> --passphrase <pass>
aegisqr export qr <bundle.aqr> --out <qr-dir>
aegisqr import qr <qr-dir> --out <recovered.aqr>
aegisqr stage <bundle.aqr> --out <staging-dir> --passphrase <pass>
```

## Interface app (lightweight alternative to CLI)

Run the interactive interface:

```bash
cargo run -p aegisqr-ui
```

It provides guided prompts for pack/inspect/verify/unpack/stage/export/import flows while preserving secure defaults (no automatic payload execution).

## Project status

MVP starter is implemented with Rust-first workspace crates, AQR1 capsule data model, deterministic serialization, compression, passphrase encryption, Ed25519 signing, QR packet export/import, safe staging/quarantine, tests, and CI.

## Roadmap

See `PLAN.md` for phased roadmap and future features (AICX deeper integration, hardware keys, WASM runtime, mobile scanner, recovery enhancements).
