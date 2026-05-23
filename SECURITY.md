# Security

## Secure defaults

- No auto-run from QR scanning
- No auto-run from decrypt/unpack/stage
- Execution is denied in MVP runtime stubs
- Passphrase encryption uses Argon2id + XChaCha20-Poly1305
- Metadata signing uses Ed25519

## Threat assumptions

- Attackers may tamper with packets/capsules
- Unknown signers are untrusted by default
- Restores are treated as untrusted until policy allows execution

## Responsible disclosure

Security reporting process placeholder: open a private advisory or contact maintainers directly.

## Current MVP limitations

- No production key management or revocation feeds yet
- No Reed-Solomon repair implementation yet
- No execution runtime enabled
