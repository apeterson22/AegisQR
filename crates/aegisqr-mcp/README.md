# 🛡️ AegisQR Model Context Protocol (MCP) Server

[![MCP Version](https://img.shields.io/badge/MCP-2024--11--05-blue.svg)](https://modelcontextprotocol.io/)
[![Security Invariants](https://img.shields.io/badge/Security-Fail--Closed%20%7C%20Quarantine-green.svg)](../../SECURITY.md)

`aegisqr-mcp` exposes high-assurance cryptographic verification, offline packaging, optical air-gap packet transport, and signed universal retail deep-linking primitives as a standard [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) JSON-RPC 2.0 stdio server.

Designed specifically for AI agent swarms (Claude Desktop, Antigravity, Cursor, Solomon Prime, OpenClaw), `aegisqr-mcp` enables autonomous agents to safely analyze untrusted data capsules without risking host compromise.

---

## 🔒 Core Security Invariants for AI Swarms

1. **Passphrase-Free Safe Inspection (`inspect_capsule`)**
   Agents can inspect sealed `.aqr` containers, extracting metadata, payload types, chunk counts, cryptographic algorithms, and embedded `AgentIndex` risk scores *before* deciding whether to decrypt.

2. **Mandatory Executable Quarantining (`unpack_capsule`)**
   When unpacking decrypted archives, all executable artifacts (`.sh`, `.exe`, `.bat`, `.py`, `.so`, `.elf`, etc.) are automatically segregated into an isolated `quarantine/` directory.

3. **Strict Dual-Persona Role Authorization (`verify_retail_url`)**
   Shelf-tag and product universal links with `associate` persona capabilities strictly require verified employee SSO authentication (`authenticated_associate: true`).

4. **100% Offline Cryptographic Determinism**
   Zero network calls, zero telemetry, and zero phone-home. All verification runs strictly offline using Ed25519, XChaCha20-Poly1305, Argon2id, and BLAKE3.

---

## 🛠️ Exposed MCP Tools

| Tool Name | Description | Key Parameters |
|:---|:---|:---|
| `inspect_capsule` | Inspect `.aqr` header, metadata, and AgentIndex risk score without decrypting. | `capsule_path` |
| `verify_capsule` | Cryptographically verify Ed25519 signature and BLAKE3 chunk hashes against trust store. | `capsule_path`, `strict_trust`, `trust_store_path` |
| `unpack_capsule` | Decrypt and unpack container with automated executable quarantining. | `capsule_path`, `output_dir`, `passphrase`, `quarantine_all` |
| `pack_capsule` | Seal files or directories into encrypted `.aqr` capsules with AICX sidecar auto-binding. | `input_path`, `output_path`, `passphrase`, `compression`, `is_aicx` |
| `verify_retail_url` | Verify universal retail shelf-tag URL (`?p=`) Ed25519 signature, expiration, and role. | `url`, `public_key_hex`, `key_id`, `authenticated_associate` |
| `pack_retail_url` | Generate signed universal HTTPS deep-link scannable by smartphone camera or industrial scan gun. | `retailer_id`, `sku`, `store_id`, `private_key_hex`, `key_id`, `role`, `expires_in_secs` |
| `export_qr_packets` | Slice sealed capsule into sequential air-gap packets (`.aqrp`) or scannable PNG QR codes. | `capsule_path`, `output_dir`, `packet_size`, `generate_png` |
| `import_qr_packets` | Reassemble capsule from optical QR packet sequence, verifying integrity across physical air gap. | `qr_dir`, `output_path` |
| `license_status` | Inspect offline `.aqlic` cryptographic enterprise license, seat allocations, and grace period. | *(None)* |

---

## 🚀 Installation & Configuration

### 1. Build the Binary

```bash
cargo build --release -p aegisqr-mcp
```

The compiled binary will be located at:
`target/release/aegisqr-mcp`

### 2. Configure Your Agent Client

#### Claude Desktop (`claude_desktop_config.json`)

On Linux (`~/.config/Claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "aegisqr": {
      "command": "/path/to/AegisQR/target/release/aegisqr-mcp",
      "args": []
    }
  }
}
```

#### Antigravity CLI / Swarm (`antigravity.json`)
```json
{
  "mcpServers": {
    "aegisqr": {
      "command": "/path/to/AegisQR/target/release/aegisqr-mcp"
    }
  }
}
```

#### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "aegisqr": {
      "command": "/path/to/AegisQR/target/release/aegisqr-mcp"
    }
  }
}
```

---

## 🧪 Testing & Verification

Run the MCP protocol suite testing the full handshake, tool discovery, retail signing, and capsule unpack life-cycle:

```bash
cargo test -p aegisqr-mcp --test mcp_protocol_tests
```
