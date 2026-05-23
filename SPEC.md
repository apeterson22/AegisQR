# AegisQR Specification (AQR1 MVP)

## Capsule format

- File extension: `.aqr`
- Magic bytes: `AQR1`
- Encoding: deterministic CBOR payload after magic

## Public header schema

Contains non-sensitive metadata only:
- magic, version, bundle_id, profile, created_at
- payload_type, chunk_count, recovery_required
- encrypted, signed
- auto_execute_capable, auto_execute_default (always false)
- requires_signature, requires_policy

## Section table schema

Each section entry includes:
- section_id, offset, length
- encrypted, compressed
- hash, hash_algorithm
- required_for, content_type, policy_tags

Initial required sections:
- public_header
- policy_block
- agent_index
- payload
- signature_block
- chunk_table

## Policy schema

Client policy defaults:
- auto_execute_enabled: false
- native_execution_allowed: false
- required_signature: true
- required_sandbox: true
- max_risk_level: medium
- quarantine_executables: true

## Agent index schema

Includes capsule type, summary, payload type, entrypoint candidate, runtime requirement, requested permissions, expected outputs, schema placeholder, risk level, auto-execute declaration, and AICX sidecar placeholder.

## Signature coverage

Ed25519 signature covers:
- public header
- section table
- policy block
- encrypted payload hash
- agent index hash
- chunk table hash
- auto-execute declaration
- expiration (if set)

## QR packet schema

Packet fields:
- magic, version, bundle_id
- index, total
- capsule_hash
- payload_b64
- checksum

## Versioning rules

- `AQR1` identifies major wire format.
- Additive fields should be optional and backward-compatible.
- Breaking changes require a new magic/version pair.
