# AegisQR Build Plan

## Secure Encrypted Compressed QR-Native Agent Capsule Format

AegisQR is a proposed secure capsule system for packaging data, code, executables, workflows, model artifacts, configs, secrets, firmware, and agent tasks into compressed, encrypted, signed, recoverable QR bundles.

For enterprise repository exchange workflows with AICX, use `plan-enterprise.md` as the ready-to-use agent brief and integration contract.

The system supports static QR codes, animated QR transfer, spritesheets, printable contact-sheet PDFs, and air-gapped enterprise workflows. It is designed for agentic automation while keeping auto-execution disabled by default and controlled by explicit enterprise client policy.

## Current alignment notes

The current repository baseline is aligned around these constraints and implemented hardening decisions:

- Release automation should keep CI, portable release packaging, CodeQL, Dependabot, and installer smoke tests aligned.
- Direct remote archive installs must stay HTTPS-only and checksum-verified by default; local/manual bypasses must remain explicit opt-outs.
- QR import must validate packet magic/version/index/total/hash/checksum consistency, reject conflicting duplicates, and require reconstructed output to still be an `AQR1` capsule.
- Verification and restore should validate public-header, section-table, and chunk-table consistency before trust or decrypt decisions.
- Enterprise compatibility fields are still part of the format surface even when represented as placeholders in code; preserve wire names such as `aicx_sidecar`, `toon_export`, `enterprise_policy`, and `approval_tokens`.

---

## Target Ratings

```text
Performance:      11 / 10
Compressibility:  12 / 10
Security:         12 / 10
Agentic use:      15 / 10
QR efficiency:    10 / 10
```

These ratings are stretch goals. They are achieved by combining:

```text
1. Section-based capsule format
2. Agent-readable encrypted indexes
3. Adaptive compression and deduplication
4. Enterprise policy-gated execution
5. QR transport optimization with recovery and fallback modes
```

---

# 1. Product Goal

AegisQR should function as:

```text
A secure offline agent package and execution capsule standard.
```

It should allow enterprises, operators, developers, and air-gapped environments to securely transfer and restore sensitive files or executable agent tasks using QR-based transport.

The core principle:

```text
Scanning does not execute.
Decrypting does not execute.
Restoring does not execute.
Execution requires explicit local client policy and enterprise trust verification.
```

---

# 2. Core Architecture

Do **not** build AegisQR as one encrypted blob.

Build it as a **sectioned secure capsule**.

```text
AegisQR Capsule
├── Public Header
├── Trust Block
├── Policy Block
├── Agent Index
├── Semantic Index
├── Workflow Section
├── Payload Section
├── Secrets Section
├── Signature Block
├── Chunk Table
├── Reed-Solomon Recovery Shards
└── Audit Metadata
```

This allows an authorized agent to inspect metadata, workflow details, permissions, risk, and required runtime without decrypting or decompressing the full payload.

---

# 3. Recommended Technology Stack

## Core Engine

Use **Rust**.

Reasons:

```text
Memory safety
High performance
Small static binaries
Strong crypto ecosystem
Good mobile/desktop binding support
Good WASM support
Good CLI distribution
```

## CLI

```text
Rust + clap
```

## Desktop App

```text
Tauri frontend
Rust backend
```

## Mobile App

```text
Android first
Flutter or Kotlin frontend
Rust core through FFI
 iOS later
```

## Agent SDK

```text
Python bindings
Node.js bindings
Local CLI wrapper
Optional MCP/tool interface later
```

---

# 4. Suggested Rust Libraries

## Compression

```toml
zstd = "latest"
```

Use zstd for fast and high-ratio compression, including dictionary support.

## Encryption

```toml
chacha20poly1305 = "latest"
aes-gcm = "latest"
```

Default:

```text
XChaCha20-Poly1305
```

Optional enterprise compatibility:

```text
AES-256-GCM
```

## Key Derivation

```toml
argon2 = "latest"
```

Default passphrase KDF:

```text
Argon2id
```

## Signing

```toml
ed25519-dalek = "latest"
```

Default signature algorithm:

```text
Ed25519
```

## Encoding

```toml
serde = "latest"
serde_cbor = "latest"
rmp-serde = "latest"
```

Default internal encoding:

```text
CBOR
```

Optional:

```text
MessagePack
TOON export
JSON debug export
```

## Recovery

```toml
reed-solomon-erasure = "latest"
```

Used for QR-loss recovery.

## Runtime

```toml
wasmtime = "latest"
wasmtime-wasi = "latest"
```

Preferred executable format:

```text
WASM + WASI
```

---

# 5. Repository Layout

```text
aegisqr/
├── README.md
├── PLAN.md
├── SECURITY.md
├── SPEC.md
├── THREAT_MODEL.md
├── Cargo.toml
├── crates/
│   ├── aegisqr-core/
│   ├── aegisqr-cli/
│   ├── aegisqr-container/
│   ├── aegisqr-compress/
│   ├── aegisqr-crypto/
│   ├── aegisqr-encoding/
│   ├── aegisqr-qr/
│   ├── aegisqr-recovery/
│   ├── aegisqr-policy/
│   ├── aegisqr-agent/
│   ├── aegisqr-runtime/
│   └── aegisqr-audit/
├── apps/
│   ├── desktop-tauri/
│   └── mobile/
├── bindings/
│   ├── python/
│   └── node/
├── examples/
│   ├── personal/
│   ├── enterprise/
│   ├── airgap/
│   └── agent-auto-execute/
├── test-vectors/
├── benches/
├── fuzz/
└── docs/
    ├── capsule-format.md
    ├── qr-transport.md
    ├── enterprise-policy.md
    ├── agent-index.md
    ├── auto-execute.md
    └── airgap-mode.md
```

---

# 6. Capsule Format

## File Extension

```text
.aqr
```

## Magic Bytes

```text
AQR1
```

## Logical Capsule Structure

```text
AQR1 Capsule
├── Header
├── Section Table
├── Trust Block
├── Policy Block
├── Key Wrap Table
├── Agent Index Section
├── Semantic Index Section
├── Workflow Section
├── Payload Section
├── Secrets Section
├── Signature Block
├── Chunk Table
└── Recovery Metadata
```

---

# 7. Public Header

The public header is readable without decryption.

It must contain only non-sensitive routing information.

Example logical structure:

```yaml
magic: AQR1
version: 1
bundle_id: 16-byte-random-id
profile: enterprise-agent-v1
created_at: timestamp
chunk_count: uint32
recovery_required: uint32
auto_execute_capable: true
auto_execute_default: false
requires_signature: true
requires_policy: true
```

The header allows scanners and agents to know:

```text
What format this is
How many chunks exist
Whether recovery shards exist
Whether the bundle is agent-capable
Whether auto-execute is possible
Whether enterprise signature is required
```

It must not reveal:

```text
Secrets
Commands
Source code
Credentials
Internal endpoint names
Sensitive business logic
```

---

# 8. Section Table

The section table is the most important performance and agentic-use feature.

```yaml
sections:
  - id: public_header
    encrypted: false
    compressed: false
    required_for:
      - routing

  - id: trust_block
    encrypted: false
    compressed: false
    required_for:
      - verification

  - id: policy_block
    encrypted: false
    compressed: false
    signed: true
    required_for:
      - policy_check

  - id: agent_index
    encrypted: true
    compressed: optional
    required_for:
      - inspect

  - id: semantic_index
    encrypted: true
    compressed: zstd-fast
    required_for:
      - agent_reasoning

  - id: workflow
    encrypted: true
    compressed: zstd-balanced
    required_for:
      - staging
      - execution

  - id: payload
    encrypted: true
    compressed: zstd-adaptive
    required_for:
      - restore
      - execution

  - id: secrets
    encrypted: true
    compressed: false
    required_for:
      - privileged_execution
```

This layout allows agents to selectively decrypt only what they need.

---

# 9. Compression Strategy

## Correct Order

```text
normalize → encode → deduplicate → compress → encrypt → sign → shard → QR
```

Never do:

```text
encrypt → compress
```

Encrypted data appears random and will not compress efficiently.

## Adaptive Compression Profiles

```yaml
compression_profiles:
  none:
    algorithm: none

  fast:
    algorithm: zstd
    level: 3

  balanced:
    algorithm: zstd
    level: 10

  max:
    algorithm: zstd
    level: 19

  ultra:
    algorithm: zstd
    level: 22

  dictionary:
    algorithm: zstd
    level: 12
    dictionary: enabled
```

## Type-Specific Compression Rules

```yaml
file_type_rules:
  json:
    normalize: toon_or_cbor
    compression: zstd_dictionary

  yaml:
    normalize: cbor
    compression: zstd_dictionary

  source_code:
    normalize: repo_pack
    deduplicate: true
    compression: zstd_max

  logs:
    normalize: dictionary_token_stream
    compression: zstd_dictionary

  executables:
    normalize: none
    compression: zstd_balanced
    detect_packed_binary: true

  images_video_audio_zip_pdf:
    sample_first: true
    skip_if_savings_under_percent: 3

  secrets:
    compression: false
```

## Compression Preflight

Before compressing large files:

```text
Read first 64 KB
Read middle 64 KB
Read last 64 KB
Try zstd levels 3, 10, 19
Estimate compression ratio
Select the best cost/benefit profile
```

This avoids wasting CPU on files that are already compressed.

---

# 10. Deduplication Layer

To reach maximum compressibility, add deduplication before compression.

Use:

```text
BLAKE3 hash per file
Rolling hash for large files
Duplicate block elimination
Dictionary generation from repeated structures
```

Directory pack flow:

```text
walk directory
normalize paths
reject unsafe paths
hash files
deduplicate identical files
split large repeated files
build file map
compress unique blocks
encrypt sections
```

This is especially useful for:

```text
source repositories
config bundles
logs
agent packages
model adapter directories
repeated deployment artifacts
```

---

# 11. Agent Index

The Agent Index is a small encrypted section that describes the capsule without exposing the full payload.

Example TOON export:

```toon
capsule:
  id: 9f3a12cc
  type: enterprise-agent-task
  risk: medium
  runtime: wasm
  entrypoint: diagnostic_agent.wasm
  auto_execute:
    capable: true
    requested: true
    client_must_enable: true
  permissions:
    filesystem: workspace-only
    network: internal-only
    secrets: vault-bound
  inputs:
    target_host: string
    mode: enum(scan,verify,report)
  outputs:
    - diagnostic_report.json
    - audit.log
  summary: Run approved diagnostics and produce signed report.
```

Internally store this as deterministic CBOR.

Export as TOON for humans and agents.

---

# 12. Semantic Index

The Semantic Index enables agent reasoning before restoring the full payload.

It should include:

```text
File map
Entrypoints
Dependency list
Runtime requirements
Permission request list
Function/symbol summary
Config schema
Expected outputs
Risk score
Known capabilities
Policy requirements
Chunk map by section
Optional embeddings or compact semantic tags
```

Example:

```yaml
semantic_index:
  capabilities:
    - diagnostic
    - report-generation
    - internal-network-check
  runtime:
    preferred: wasm
    fallback: python
  dependencies:
    - wasi
  forbidden:
    - raw-disk
    - unrestricted-network
    - privilege-escalation
  output_contract:
    report: diagnostic_report.json
    audit: audit.log
```

This allows an agent to answer:

```text
Should I run this?
Can I run this?
What does it need?
What will it produce?
Do I need the payload?
Which sections do I need?
```

---

# 13. Encryption Design

## Default Payload Encryption

```text
XChaCha20-Poly1305
```

Support optional:

```text
AES-256-GCM
```

Use independent keys per section:

```text
K_index
K_semantic
K_workflow
K_payload
K_secrets
K_exec
```

Each section must have:

```text
unique nonce
unique associated data
section ID bound into AEAD
capsule ID bound into AEAD
profile bound into AEAD
```

## Associated Data

Every encrypted section should bind:

```text
capsule_id
format_version
section_id
section_length
section_hash
policy_hash
signer_key_id
```

This prevents section swapping between capsules.

---

# 14. Key Management

Support three modes.

## Personal Mode

```text
Passphrase → Argon2id → wrapping key
```

Recommended Argon2id profile:

```yaml
argon2id:
  memory_kib: 262144
  iterations: 4
  parallelism: 4
```

## Team Mode

```text
Random section keys
X25519 recipient wrapping
Multiple recipients allowed
```

## Enterprise Mode

```text
Random section keys
KMS/HSM/hardware-backed wrapping
Policy-bound key release
Hardware-key challenge required
Offline trust store supported
```

Key table example:

```yaml
key_wraps:
  - recipient_id: enterprise-field-device-group
    algorithm: x25519-hkdf
    wrapped_keys:
      - K_index
      - K_workflow
      - K_payload

  - recipient_id: enterprise-admin
    algorithm: yubikey-piv
    wrapped_keys:
      - K_index
      - K_workflow
      - K_payload
      - K_secrets
```

---

# 15. Signing Design

Use:

```text
Ed25519
```

The signature must cover:

```text
public header
section table
policy block
key wrap table
encrypted section hashes
chunk table
recovery metadata
expiration
auto-execute declaration
```

Verification flow:

```text
Read public header
Read trust block
Canonicalize signed metadata
Verify Ed25519 signature
Check trust store
Check expiration
Check revocation snapshot
Proceed only if trusted
```

---

# 16. QR Packet Format

Do not use JSON in production QR packets.

Use compact CBOR.

Logical packet:

```yaml
m: AQR1
v: 1
b: bundle_id
i: chunk_index
n: total_chunks
t: shard_type
h: manifest_hash
p: payload_bytes
c: crc32c
```

Short keys reduce QR payload size.

Field meanings:

```text
m = magic
v = version
b = bundle id
i = index
n = total
t = type: data/recovery/manifest
h = manifest hash
p = payload
c = checksum
```

Encoding options:

```text
raw byte mode where supported
Base45 fallback
Base64 only for compatibility/debug
```

---

# 17. QR Efficiency Strategy

Support five transport modes.

## Mode 1: Single QR

For very small payloads:

```text
agent index
small secret
tiny config
small workflow
```

## Mode 2: Static QR Set

```text
qr_000001.png
qr_000002.png
qr_000003.png
```

## Mode 3: Animated QR

```text
transfer.webp
transfer.gif
transfer.mp4
```

Recommended settings:

```text
4–8 FPS
repeat manifest every cycle
repeat missing critical chunks more often
adaptive brightness border
visible chunk counter
```

## Mode 4: Spritesheet

```text
spritesheet_001.png
spritesheet_002.png
```

## Mode 5: Bootstrap QR

For large payloads, QR should contain only:

```text
capsule manifest
signature
payload hash
session ID
transfer options
key wrapping info
```

The encrypted payload can move through:

```text
USB
LAN
Bluetooth
Wi-Fi Direct
local file drop
NFC handoff
```

The QR still bootstraps trust.

---

# 18. Reed-Solomon Recovery

Recovery profiles:

```yaml
recovery_profiles:
  minimal:
    parity_percent: 10

  standard:
    parity_percent: 20

  rugged:
    parity_percent: 33

  airgap:
    parity_percent: 50

  hostile_print:
    parity_percent: 75
```

Validation flow:

```text
CRC each chunk
Verify Reed-Solomon reconstruction
Verify encrypted section hashes
Verify signature
Decrypt
Verify plaintext hashes
```

---

# 19. Auto-Execute Design

Auto-execute must exist as a feature, but it must be disabled by default.

Capsule-side declaration:

```yaml
auto_execute:
  capable: true
  requested: false
  client_must_enable: true
  default_enabled: false
```

Enterprise client policy:

```yaml
client_policy:
  auto_execute_enabled: false
  trusted_signers:
    - enterprise-prod-signing-001
  allowed_profiles:
    - enterprise-agent-v1
  allowed_runtimes:
    - wasm
    - container
    - python
  native_execution_allowed: false
  required_controls:
    signature: true
    sandbox: true
    hardware_key: true
    audit_log: true
  max_risk_level: medium
```

Auto-execute is allowed only when:

```text
Client enabled auto-execute
Capsule requests auto-execute
Enterprise signature is trusted
Policy allows the runtime
Sandbox is available
Requested permissions are allowed
Hardware key/device identity passes
Payload hash verifies
Audit logging is active
```

---

# 20. Runtime Execution Model

Default runtime priority:

```text
1. Signed workflow
2. WASM/WASI module
3. Container sandbox
4. Python isolated worker
5. Native executable only under enterprise-high-trust policy
```

## WASM Profile

```yaml
runtime:
  type: wasm
  engine: wasmtime
  wasi: true
  filesystem: workspace-only
  network: disabled-by-default
  env: allowlist-only
  memory_limit_mb: 256
  timeout_seconds: 300
```

## Python Profile

```yaml
runtime:
  type: python
  venv: isolated
  network: policy-controlled
  filesystem: workspace-only
  imports: allowlist
  timeout_seconds: 300
```

## Native Profile

```yaml
runtime:
  type: native
  allowed: enterprise-high-trust-only
  sandbox_required: true
  signed_binary_required: true
  no_admin_default: true
```

---

# 21. Security Non-Negotiables

The application must enforce:

```text
Scanning does not execute.
Decrypting does not execute.
Restoring does not execute.
Auto-execute requires explicit local client policy.
Unsigned capsules cannot execute.
Unknown signers cannot execute.
Expired capsules cannot execute.
Modified capsules cannot execute.
Payload hash mismatch stops restore.
Permission mismatch stops execution.
Sandbox unavailable stops execution.
```

Also:

```text
No silent persistence
No privilege escalation behavior
No automatic startup installation
No hidden network callbacks
No execution outside policy
No writing outside workspace
No plaintext temp files unless explicitly configured
No private-key export
```

---

# 22. Threat Model

Create `THREAT_MODEL.md` covering these attackers:

```text
Someone finds printed QR pages
Someone modifies QR chunks
Someone swaps chunks between bundles
Someone replays an old valid bundle
Someone creates a fake enterprise capsule
Someone tricks scanner into auto-executing
Compromised low-privilege agent
Malicious payload author
Lost hardware key
Insider with signing access
```

Required defenses:

```text
AEAD encryption
Section-bound associated data
Ed25519 signatures
Trust store
Expiration
Revocation snapshot
Policy gating
Hardware-key requirement
Sandboxing
Audit logs
Hash verification
Reed-Solomon plus cryptographic verification
```

---

# 23. CLI Commands

## Pack

```bash
aegisqr pack ./payload \
  --profile enterprise-agent \
  --recipient enterprise-agents.pub \
  --sign yubikey:slot9c \
  --compression adaptive \
  --recovery rugged \
  --agent-index ./agent-index.toon \
  --workflow ./workflow.aqr.yml \
  --out ./bundle
```

## Inspect Public Metadata

```bash
aegisqr inspect ./bundle
```

## Unlock Only Agent Index

```bash
aegisqr inspect ./bundle --unlock-index --hardware-key
```

## Generate Static QR

```bash
aegisqr export qr ./bundle --out ./qr
```

## Generate Animated QR

```bash
aegisqr export animated ./bundle --fps 6 --out transfer.webp
```

## Generate Spritesheet

```bash
aegisqr export spritesheet ./bundle --columns 8 --out spritesheet.png
```

## Generate PDF

```bash
aegisqr export pdf ./bundle --out contact_sheet.pdf
```

## Scan

```bash
aegisqr scan ./images --out recovered.aqr
```

## Verify

```bash
aegisqr verify recovered.aqr --trust-store ./enterprise_trust
```

## Stage

```bash
aegisqr stage recovered.aqr --out ./staging
```

## Run

```bash
aegisqr run recovered.aqr --policy ./client-policy.yml
```

## Force No Execution

```bash
aegisqr unpack recovered.aqr --no-execute --out ./restored
```

---

# 24. Agent Implementation Milestones

## Phase 0: Specs and Test Vectors

Deliverables:

```text
SPEC.md
THREAT_MODEL.md
SECURITY.md
capsule-format.md
test-vectors/
```

Agent tasks:

```text
Define capsule structs
Define deterministic CBOR encoding
Define section table
Define signature coverage
Define QR packet schema
Create fixed test vectors
```

Acceptance:

```text
Same input always produces same canonical metadata
Signature verification works across test vectors
Malformed capsules fail safely
```

---

## Phase 1: Core Capsule MVP

Deliverables:

```text
aegisqr-core
aegisqr-container
aegisqr-cli
```

Features:

```text
Pack single file
Build section table
Hash sections
Write .aqr file
Read .aqr file
Verify section hashes
```

Acceptance:

```text
Pack/unpack lossless
Path traversal blocked
Unsafe file names rejected
Hashes verified
```

---

## Phase 2: Compression Engine

Deliverables:

```text
aegisqr-compress
```

Features:

```text
zstd compression
adaptive compression preflight
skip poor compression targets
dictionary mode
section-specific compression
```

Acceptance:

```text
Text/code compresses well
Already-compressed files are skipped or low-effort compressed
Compression decisions are logged
```

---

## Phase 3: Crypto Engine

Deliverables:

```text
aegisqr-crypto
```

Features:

```text
XChaCha20-Poly1305
AES-256-GCM optional
Argon2id
X25519 key wrapping
Section keys
Associated data binding
Zeroize secrets
```

Acceptance:

```text
Wrong passphrase fails
Modified ciphertext fails
Section swapping fails
Nonce reuse prevented
Secrets zeroized where practical
```

---

## Phase 4: Signing and Trust

Deliverables:

```text
aegisqr-policy
trust store format
```

Features:

```text
Ed25519 signatures
Trusted signer store
Revocation snapshot
Expiration
Policy hash verification
```

Acceptance:

```text
Unsigned enterprise capsule rejected
Unknown signer rejected
Expired capsule rejected
Modified policy rejected
```

---

## Phase 5: QR Transport

Deliverables:

```text
aegisqr-qr
```

Features:

```text
CBOR QR packets
PNG QR export
QR image decode
Chunk table
CRC32C
Missing chunk report
```

Acceptance:

```text
QR export/import round-trips
Missing chunks detected
Wrong bundle chunks rejected
Duplicate chunks handled
```

---

## Phase 6: Reed-Solomon Recovery

Deliverables:

```text
aegisqr-recovery
```

Features:

```text
Recovery shard generation
Recovery shard import
Repair missing data shards
Recovery profiles
```

Acceptance:

```text
Rugged profile restores with expected missing chunks
Bad shards are rejected by hash verification
```

---

## Phase 7: Advanced Exports

Deliverables:

```text
animated QR export
spritesheet export
PDF contact sheet
```

Features:

```text
animated webp/gif/mp4
spritesheet png
printable PDF
human-readable labels
bundle fingerprint
chunk counter
```

Acceptance:

```text
Printed PDF can be scanned
Animated QR can be captured
Spritesheet can be imported
```

---

## Phase 8: Agent Index and Semantic Index

Deliverables:

```text
aegisqr-agent
```

Features:

```text
Agent Index
Semantic Index
TOON export
CBOR internal encoding
Input/output schema
Permission declaration
Runtime declaration
```

Acceptance:

```text
Agent can inspect capsule without decrypting payload
Agent can determine required runtime
Agent can determine requested permissions
Agent can decide stage/run/deny
```

---

## Phase 9: Execution Runtime

Deliverables:

```text
aegisqr-runtime
```

Features:

```text
WASM runtime
workflow runner
sandboxed workspace
timeout control
memory control
environment allowlist
output collection
audit log
```

Acceptance:

```text
Auto-execute disabled by default
Execution denied without trusted policy
WASM runs in sandbox
Outputs are hashed and logged
```

---

## Phase 10: Hardware Keys

Deliverables:

```text
hardware key provider abstraction
YubiKey/FIDO2 prototype
TPM provider later
```

Features:

```text
hardware-backed unlock
hardware-backed signing
device identity check
challenge-response
```

Acceptance:

```text
Private key cannot be exported
Unlock requires hardware key
Missing hardware key blocks protected sections
```

---

## Phase 11: Mobile Scanner MVP

Deliverables:

```text
Android scanner
Rust core binding
offline restore
```

Features:

```text
static QR scan
animated QR scan
spritesheet import
PDF/image import
signature verify
agent index inspect
safe restore
```

Acceptance:

```text
Works offline
Shows chunk progress
Rejects untrusted signer
Does not auto-execute by default
```

---

# 25. Cost-Effective Build Strategy

To keep cost low:

```text
Start CLI-only
Use open-source Rust crates
Avoid cloud dependencies
Use local trust store first
Delay desktop/mobile until core format is stable
Implement hardware keys after software key flows work
Implement WASM before native execution
```

Build order by value:

```text
1. CLI core
2. Compression/encryption/signing
3. QR export/import
4. Recovery shards
5. Agent index
6. Policy engine
7. WASM runtime
8. PDF/animated/spritesheet
9. Hardware keys
10. Mobile app
```

Avoid early costs:

```text
Do not build cloud KMS first
Do not build full GUI first
Do not build iOS first
Do not support every hardware key first
Do not optimize native execution first
```

---

# 26. Enhancements to Reach Stretch Scores

## Performance 11 / 10

Add:

```text
Section-level lazy loading
Parallel compression
Parallel encryption
Parallel QR generation
Memory-mapped capsule reading
SIMD-enabled Reed-Solomon where available
Streaming pack/unpack
Zero-copy decode path where possible
Incremental scan reconstruction
```

## Compressibility 12 / 10

Add:

```text
Adaptive zstd dictionaries
Content-defined deduplication
TOON/CBOR normalization
Repo-aware source packing
Columnar encoding for CSV/logs
Binary delta mode
Repeated asset detection
Compression sampling before full compression
```

## Security 12 / 10

Add:

```text
Formal threat model
Deterministic signed metadata
Section-bound AEAD associated data
Hardware-key support
Offline revocation snapshots
Policy-as-code
Sandboxed execution
Fuzzing
Supply-chain SBOM
Reproducible builds
Signed releases
Secret zeroization
No plaintext temp files by default
```

## Agentic Use 15 / 10

Add:

```text
Agent Index
Semantic Index
Workflow section
Capability manifest
Permission contract
Input/output schema
Risk score
Selective section unlock
Agent decision API
TOON export
MCP-compatible tool wrapper
Policy explanation output
Self-describing capsule docs
```

## QR Efficiency 10 / 10

Add:

```text
CBOR short-key packets
Base45/raw-byte QR mode
Adaptive QR chunk sizing
Animated QR
Spritesheets
PDF contact sheets
Reed-Solomon recovery
QR bootstrap mode
Repeated manifest frames
Missing-chunk prioritization
Scan quality scoring
```

---

# 27. Testing Strategy

## Unit Tests

Cover:

```text
Capsule creation
Section table validation
Compression decisions
Encryption/decryption
Signature verification
Key wrapping
QR packet encode/decode
Recovery reconstruction
Policy decisions
Runtime permission checks
```

## Property Tests

Cover:

```text
Random file round-trips
Random chunk loss recovery
Malformed packet rejection
Section swapping rejection
Random policy mismatch rejection
```

## Fuzzing

Fuzz:

```text
Capsule parser
CBOR parser
QR packet parser
Policy parser
Recovery shard parser
TOON import/export
```

## Security Tests

Attempt:

```text
Modified ciphertext
Modified manifest
Unknown signer
Expired capsule
Replayed capsule
Path traversal payload
Symlink escape
Permission escalation request
Auto-execute with disabled client policy
Native execution without enterprise-high-trust policy
```

## Performance Benchmarks

Benchmark:

```text
Pack speed
Unpack speed
Compression ratio
QR generation speed
Scan reconstruction speed
Recovery repair speed
Agent-index-only inspection time
Memory usage
```

---

# 28. Supply Chain Security

Required:

```text
cargo audit
cargo deny
SBOM generation
signed release artifacts
reproducible builds where possible
pinned dependencies for releases
CI security scans
fuzzing in CI
minimal unsafe Rust
secret scanning
```

Release artifacts should include:

```text
binary
checksum
signature
SBOM
release notes
security advisories if applicable
```

---

# 29. Final Optimized Pipeline

## Packaging Pipeline

```text
Input
  ↓
File type detection
  ↓
Normalization / TOON / CBOR / archive packing
  ↓
Deduplication
  ↓
Section splitting
  ↓
Adaptive zstd compression
  ↓
Section hashing
  ↓
Section encryption
  ↓
Recipient key wrapping
  ↓
Policy generation
  ↓
Ed25519 signing
  ↓
CBOR QR packetization
  ↓
Reed-Solomon recovery
  ↓
QR / animated QR / spritesheet / PDF / bootstrap export
```

## Restore and Execution Pipeline

```text
Scan/import
  ↓
Chunk validation
  ↓
Reed-Solomon repair
  ↓
Signature verification
  ↓
Policy evaluation
  ↓
Selective section decrypt
  ↓
Agent inspect
  ↓
Stage if allowed
  ↓
Execute only if local client policy enables auto-execute
  ↓
Sandbox runtime
  ↓
Audit output
```

---

# 30. Core Rules for Coding Agents

Coding agents building AegisQR must follow these rules:

```text
Never make convenience more important than trust boundaries.
```

```text
Every section must be independently verifiable, selectively decryptable, and policy-controlled.
```

```text
Scanning, decrypting, and restoring are separate operations from execution.
```

```text
Auto-execution is a client-side enterprise policy decision, not a QR-code behavior.
```

```text
Agents inspect indexes and workflows first. They only decrypt payload sections when authorization and necessity are proven.
```

---

# 31. Final Architecture Summary

AegisQR should become:

```text
A sectioned, signed, compressed, encrypted, QR-native agent capsule format.
```

It is optimized for:

```text
High performance
High compression
Enterprise security
Agent automation
Air-gapped transfer
QR-native transport
Offline restore
Policy-gated execution
```

The most important design pillars are:

```text
1. Section-based compression and encryption
2. Agent-readable encrypted indexes
3. CBOR/MessagePack binary transport
4. TOON debug/agent export
5. zstd adaptive compression
6. XChaCha20-Poly1305 encryption
7. Argon2id passphrase fallback
8. X25519 recipient key wrapping
9. Ed25519 signing
10. Reed-Solomon QR recovery
11. Explicit client-enabled auto-execute
12. WASM-first sandboxed execution
13. Enterprise policy and trust store
14. Hardware-key support
15. Offline/air-gapped operation
```

---

# 32. MVP Definition

The first useful MVP should include:

```text
Rust CLI
Single-file pack/unpack
zstd compression
Argon2id passphrase mode
XChaCha20-Poly1305 encryption
Ed25519 signing
CBOR capsule metadata
Static QR export/import
SHA-256 or BLAKE3 verification
No auto-execution
```

Then add:

```text
Reed-Solomon recovery
Agent Index
Policy engine
Animated QR
PDF contact sheet
WASM runtime
Hardware keys
Mobile scanner
```

---

# 33. Recommended First Sprint

## Sprint Goal

Build the smallest secure proof of concept.

## Tasks

```text
Create Rust workspace
Create aegisqr-core crate
Create aegisqr-cli crate
Define AQR1 header struct
Define section table struct
Implement deterministic CBOR serialization
Implement file hashing
Implement zstd compression
Implement XChaCha20-Poly1305 encryption
Implement Argon2id passphrase unlock
Implement pack command
Implement unpack command
Add basic tests
Create first test vector
```

## Acceptance Criteria

```text
Can pack a file into .aqr
Can unpack .aqr back to original file
Wrong passphrase fails
Modified capsule fails
Hash mismatch fails
No plaintext temp files are produced
Test vector is reproducible
```
