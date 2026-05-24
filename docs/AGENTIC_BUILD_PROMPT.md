Agentic Build Prompt for AegisQR and AICX

You are an AI coding agent tasked with building and enhancing two separate but integrated projects:

AegisQR – a secure encrypted, signed, and policy‑controlled QR/airgap/agent capsule system.
AICX – an AI‑native adaptive compression/archive engine that produces deterministic, semantic, and agent‑readable archives.

These projects live in separate repositories (AegisQR and aicx) and have distinct responsibilities, but they must interoperate seamlessly. You must treat them as two libraries that depend on each other via clearly defined interfaces.

AegisQR: Responsibilities and Goals
Core Goals
Secure Capsule Format – Implement a sectioned .aqr container with public header, policy block, trust block, agent index, encrypted payload, signature block, chunk table, and recovery metadata.
Encryption & Signing – Use Argon2id for KDF, XChaCha20‑Poly1305 (preferred) or AES‑GCM for encryption, and Ed25519 for signatures. Ensure all keys, nonces, salts, and associated data are handled securely.
Policy Model – Build a configuration system and CLI flags that gate any automatic execution. The default must be no auto‑execute. Enforce policy checks before decryption and execution.
Agent Index – Create a minimal encrypted section that describes the payload: capsule type, runtime requirements, permissions, entrypoints, expected outputs, risk level, and AICX sidecar references. Agents should inspect this without full payload decryption.
QR Transport – Provide packetization, export, import, and optional Reed–Solomon recovery. Implement static QR sets first, then animated QR, spritesheets, and PDF contact sheets. Support retail deep links and small signed payloads.
Retail Profiles – Implement lightweight retail QR modes: retail-public-link-v1, retail-signed-link-v1, retail-app-context-v1, and retail-associate-context-v1. These profiles embed SKU, UPC, store, aisle, bay, campaign, and deep‑link information and are signed to prevent tampering.
Associate Workflows – Allow the same QR code to route differently based on user role (customer vs. associate). Validate signatures and enforce role‑specific flows.
No Silent Execution – Scanning and decrypting do not execute anything by default. Execution must be policy‑gated, sandboxed, and require explicit opt‑in by the client and enterprise policy.
Implementation Notes
Use Rust for the production core of AegisQR. Separate crates for CLI, capsule format, crypto, policy, QR transport, runtime, and recovery. Keep high‑level logic out of the CLI layer.
Use CBOR for compact metadata where possible, with JSON fallback for compatibility.
Provide clear CLI commands: pack, inspect, verify, unpack, export qr, import qr, stage, run. The run command must remain stubbed until runtime integration is added.
Write comprehensive unit and scenario tests (see Scenario Testing section) to ensure tamper detection, policy enforcement, proper signature verification, path traversal blocking, and correct QR round‑trip behavior.
AICX: Responsibilities and Goals
Core Goals
Deterministic Archive Format – Create a versioned .aicx container with a manifest and sidecar. Use BLAKE3/SHA‑256 for hashes and ensure reproducible archives.
Adaptive Compression – Support multiple codecs (none, gzip, xz/lzma, zstd, lz4 if available) and select the best per chunk based on content classification and profile. Provide profiles like fast, balanced, max, qr-max, agent, and secure.
Classification & Transforms – Implement heuristic classification for JSON, YAML, XML, TOML, Markdown, text, source code, logs, CSV, binary, compressed, and unknown. Provide safe transforms (JSON canonicalization, line-ending normalization, etc.) and allow for future advanced transforms.
Sidecar Metadata – Generate an agent‑readable sidecar with file summaries, types, token estimates, entrypoint candidates, dependency hints, risk hints, extraction map, and (for retail) product indexes (SKU/UPC/category). This sidecar must be inspectable without full extraction.
Selective Extraction – Provide APIs to list contents and extract individual files or categories by path, SKU, or prefix without unpacking the entire archive.
Retail Knowledge Pack Mode – Implement a retail-knowledge-pack profile that packages product catalogs, feeding guides, SDS documents, training content, planogram data, and ScoutAI prompts. Include SKU, UPC, store, aisle, bay, category, and digest metadata in the sidecar.
Secure Compression Profile – Provide a secure profile that avoids compressing secret‑like files (e.g., .env, private keys) and emits risk hints instead.
Handoff to AegisQR – Export digest and sidecar metadata required by AegisQR so that the capsule can embed the sidecar reference and ensure integrity verification.
Implementation Notes
Use Rust for the core library. Separate crates for container, compression, chunking, classification, transforms, sidecar, hashing, and integration helpers.
Provide a CLI with commands: pack, unpack, inspect, list, extract, verify, report, sidecar, compare-profiles.
Keep encryption and signing out of AICX; that belongs to AegisQR. Focus on data integrity, deterministic packing, and rich metadata.
Use deterministic ordering and path normalization. Block path traversal on unpack.
Provide Python bindings for agent and data‑science use after the core is stable.
Integration Between AICX and AegisQR
AegisQR should treat AICX archives as one payload type. It wraps the .aicx file in its encrypted payload section and stores AICX sidecar fields in the agent index.
AICX must expose an export function that returns the manifest digest, sidecar digest, SKU index digest, original size, compressed size, risk hints, and recommended AegisQR profile.
The agent index in AegisQR should reference the AICX digest values to ensure integrity. During unpack, AegisQR should verify that the digests match and then pass the .aicx archive to AICX for extraction.
When using retail profiles, embed only the minimal metadata (SKU, store, experience ID, label version) and deep links in the QR. Do not embed large product data; that belongs in AICX knowledge packs.
Enterprise Retail Use Cases
Shelf Label QR Codes – Use AegisQR retail profiles to sign a compact payload containing SKU, UPC, store, aisle, bay, label version, campaign ID, deep-link URI, and fallback URL. This enables any standard QR scanner to decode the payload and open the correct page in the Tractor Supply app or website.
Retail Associate Workflows – Extend the same QR payload with an optional role or mode field. When an associate scans, the app routes to inventory, planogram, SDS lookup, training, or internal agent tasks. This mode must be signed and validated.
Offline Knowledge Packs – Build store‑specific knowledge packs with AICX (retail-knowledge-pack profile) and deploy them to store devices. When the app receives a signed QR payload for a product, it retrieves the relevant product info from the local pack without network access.
Tamper and Expiration Detection – AegisQR must sign shelf labels and include expiration timestamps. The app must validate the signature and expiration to avoid malicious QR stickers.
Scenario Testing

Design scenario tests beyond unit tests to validate real workflows. At minimum, implement these tests:

Retail QR Scan (Customer) – Generate a retail-public-link-v1 QR payload, decode it with a simple scanner, and verify that the deep link opens the correct product page. Ensure signature verification passes when signed and fails on tamper. Confirm that expiration is enforced.
Retail QR Scan (Associate) – Generate a retail-associate-context-v1 payload with SKU, store, and role. In a simulated app, ensure the scan opens internal workflows (inventory check, SDS lookup, training). Validate signature and role gating.
Knowledge Pack Generation and Extraction – Pack a mock catalog with retail-knowledge-pack profile. Inspect the sidecar to confirm SKU index presence and metadata. Selectively extract one SKU’s files and verify content integrity.
Wrap AICX in AegisQR – Pack a store knowledge pack, wrap it in a signed .aqr capsule, export to QR packet files, reassemble the capsule, verify the manifest, decrypt, and unpack. Confirm that the original .aicx archive matches bit‑for‑bit.
Tamper and Expiration Handling – Tamper with one byte in a retail QR payload; confirm that the app refuses to trust the scan. Generate an expired QR and confirm it is rejected even if signature is valid.
Auto‑Execute Denial – Create a capsule requesting auto‑execution. Attempt to run it with default policy (auto‑execute disabled). Verify that execution is denied and the user is informed.
Role-Based Routing – Scan the same QR code under customer and associate contexts. Confirm that the app uses the appropriate route and denies unauthorized access.
Offline Store Knowledge Pack – Simulate scanning a retail QR with no network connectivity. Confirm that the store device retrieves product information from its local AICX knowledge pack via the digest reference in the agent index.
Implementation Checklist
 Complete basic CLI and library skeletons in Rust for both projects.
 Define CBOR/JSON schemas for AegisQR public header, section table, policy block, agent index, and retail payloads.
 Define manifest and sidecar schemas for AICX. Include file and chunk tables and retail indexes.
 Implement deterministic serialization and hashing for both formats.
 Implement multi-codec compression and classification logic in AICX.
 Implement encryption, signing, and policy enforcement in AegisQR.
 Integrate AICX’s export metadata into AegisQR’s agent index.
 Implement QR packetization and simple import/export for AegisQR.
 Build comprehensive unit and scenario test suites.
 Document all CLI commands, formats, and profiles.
 Provide clear examples for retail use and internal workflows.

Follow these guidelines to ensure both projects are built in a robust, scalable, and enterprise‑grade way. Maintain a strict separation of concerns: AICX deals with compression and metadata; AegisQR deals with encryption, signing, policy enforcement, and QR transport. Together, they enable secure retail experiences and agentic workflows.

Resource Management, Security Hardening & Operational Guidelines

Enterprise‑grade software must not only implement the right features but also handle resources securely, efficiently, and with clarity of responsibilities. Incorporate these practices into your build process:

Memory and Resource Management
Streaming APIs – Long‑running tasks such as large archive creation, QR packet generation, or decompression must process data in a streaming manner instead of loading entire files into memory. Provide functions that accept Read/Write or AsyncRead/AsyncWrite traits and avoid unbounded buffers.
Concurrency & Timeouts – Use bounded thread pools (e.g., tokio or rayon) to avoid uncontrolled thread creation. Set explicit timeouts for I/O‑bound tasks (like QR import/export) to prevent runaway jobs. Use Rust’s Drop semantics and zeroize to release secrets and close file handles promptly.
Memory Budgets – Define reasonable memory budgets for packaging and decompression, especially on resource‑constrained store devices. Profile memory usage in tests and fail gracefully if budgets are exceeded.
GitHub Issue Resolution Workflow
Work as Tasks – Treat each GitHub issue as a discrete unit of work. Pull it, implement or verify the feature/fix, run the relevant scenario tests, then update or close the issue with notes.
Security & CI gates – Before closing an issue, run cargo clippy, cargo fmt, cargo test, cargo audit, and cargo deny to ensure that the new code is secure, formatted, and free of known vulnerabilities. Ensure scenario tests pass. For Python, use ruff/black/mypy equivalents.
Label Management – If new categories of work appear (e.g., security, memory, performance), create appropriate GitHub labels and update the issue templates accordingly.
Secure Coding Practices
Constant‑Time Operations – Use vetted cryptographic libraries (e.g., RustCrypto crates) that implement constant‑time algorithms and avoid side‑channel leaks. Never roll your own crypto.
Unsafe Code – Deny unsafe code at compile time (#![forbid(unsafe_code)]) unless absolutely necessary; then encapsulate it with thorough justification and review.
FIPS & NIST Compliance – Where customers require “military grade” security, prefer NIST‑approved algorithms (AES‑256‑GCM, XChaCha20‑Poly1305, Argon2id, Ed25519). Document FIPS‑compliant build options and ensure that all random number generators are cryptographically secure.
Zeroization & Secrets – Immediately zero sensitive memory (salts, nonces, keys) after use. Use types like zeroize::Zeroizing and RAII patterns to limit lifetime of secrets.
Input Validation – Validate and bound all untrusted lengths before allocating. Reject non‑UTF8 metadata. Sanitize file names and paths to block injection or traversal.
Dependency Hygiene – Run cargo audit and cargo deny in CI. Keep dependencies up to date. Avoid unmaintained crates.
Performance and Compression Tuning
Benchmark & Profile – Use cargo bench and profiling tools (like flamegraphs) on representative data sets (catalogs, source repos, large binaries). Identify slow paths (e.g., classification heuristics, QR generation) and optimize them.
Adaptive Tuning – For compression, test codec candidates on a small sample of the chunk before committing; choose the best ratio/time trade‑off. Provide caching or trained dictionaries for frequently repeated patterns (e.g., product descriptions).
Balanced Defaults – Set default profiles that balance speed and size (e.g., zstd level 3–6 for mixed content). Provide user‑configurable options for extreme compression but document the CPU cost.
Advanced Security Posture (“Military Grade”)
Key Rotation & Revocation – Design the signature and key‑wrap mechanisms so keys can be rotated without breaking old labels. Provide revocation lists or expiration fields in signed payloads.
Offline Trust Store – Support offline trust store updates for air‑gapped deployments. Store devices should verify shelf labels without contacting a network.
Threat‑Model Review – Each new feature should include a threat‑model review describing potential attacks (tampering, replay, impersonation) and mitigations.
Standard QR Scanner Compatibility
Small & High‑Contrast Codes – Retail payloads must be small enough to be robustly scanned by commodity QR readers. Avoid high error‑correction levels unless necessary, as they increase density.
Deep Links & Fallback – The QR payload should contain a deep link and a fallback URL. Any QR scanner can read the text; the OS will open the link in the default app or browser. The AegisQR app is only required for encrypted .aqr capsules or signed agent tasks.
Device Considerations – When scanning on older or low‑end devices, avoid long strings or high‑density codes; test scanning at various sizes and distances. Provide guidance to store staff on label placement and printing.

By incorporating these guidelines, you ensure not only that the functionality meets enterprise requirements but also that the implementation can handle long‑running tasks without exhausting resources, resolves GitHub issues cleanly, and adheres to stringent security and performance expectations.
