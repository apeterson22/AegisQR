# 🛡️ AegisQR Model Context Protocol (MCP) Server

[![MCP Version](https://img.shields.io/badge/MCP-2024--11--05-blue.svg)](https://modelcontextprotocol.io/)
[![Security Invariants](https://img.shields.io/badge/Security-Fail--Closed%20%7C%20Quarantine-green.svg)](../../SECURITY.md)
[![Tools](https://img.shields.io/badge/Tools-15%20Autonomous%20Primitives-purple.svg)](#exposed-mcp-tools)
[![Harness Compatibility](https://img.shields.io/badge/Harness-Agnostic%20%7C%20Third--Party%20Ready-brightgreen.svg)](#third-party-agent-harness-integration)

`aegisqr-mcp` exposes high-assurance cryptographic verification, offline packaging, optical air-gap packet transport, signed GS1 Digital Link 2027 deep-linking, electronic shelf label (ESL) packing, and non-repudiable autonomous custody transfers as a standard [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) JSON-RPC 2.0 stdio server.

Designed specifically for **third-party agent harnesses and autonomous AI swarms** (Claude Desktop, Cursor, Antigravity, LangChain, AutoGen, CrewAI, LlamaIndex, and custom enterprise evaluation harnesses), `aegisqr-mcp` enables autonomous agents to safely analyze untrusted data capsules, manage physical shelf inventory, and exchange custody without risking host compromise.

---

## 🔒 Core Security Invariants for AI Swarms

1. **Passphrase-Free Safe Inspection (`inspect_capsule`)**
   Agents can inspect sealed `.aqr` containers, extracting metadata, payload types, chunk counts, cryptographic algorithms, and embedded `AgentIndex` risk scores *before* deciding whether to decrypt.

2. **Mandatory Executable Quarantining (`unpack_capsule`)**
   When unpacking decrypted archives, all executable artifacts (`.sh`, `.exe`, `.bat`, `.py`, `.so`, `.elf`, `.wasm`, etc.) are automatically segregated into an isolated `quarantine/` directory. Auto-execute is always `false`.

3. **Strict Dual-Persona Role Authorization (`verify_retail_url`)**
   Shelf-tag and product universal links with `associate` persona capabilities strictly require verified employee SSO authentication (`authenticated_associate: true`).

4. **GS1 Invariant Enforcement (`verify_gs1_digital_link`)**
   The scanned GTIN must match the cryptographically signed internal SKU, eliminating barcode ticket-switching fraud in automated retail inventory pipelines.

5. **100% Offline Cryptographic Determinism**
   Zero network calls, zero telemetry, and zero phone-home. All verification runs strictly offline using Ed25519, XChaCha20-Poly1305, Argon2id, and BLAKE3.

---

## 🛠️ Exposed MCP Tools (15 Autonomous Primitives)

| Tool Name | Domain | Description | Key Parameters |
|:---|:---|:---|:---|
| `inspect_capsule` | Security | Inspect `.aqr` header, metadata, and AgentIndex risk score without decrypting. | `capsule_path` |
| `verify_capsule` | Security | Cryptographically verify Ed25519 signature and BLAKE3 chunk hashes against trust store. | `capsule_path`, `strict_trust`, `trust_store_path` |
| `unpack_capsule` | Security | Decrypt and unpack container with automated executable quarantining. | `capsule_path`, `output_dir`, `passphrase`, `quarantine_all` |
| `pack_capsule` | Security | Create sealed, encrypted `.aqr` capsule with AICX sidecar auto-binding. | `input_path`, `output_path`, `passphrase`, `compression`, `is_aicx` |
| `pack_gs1_digital_link` | Retail | Generate signed GS1 Digital Link 2027 URI for retail shelf labels. | `gtin`, `sku`, `store_id`, `domain`, `private_key_hex`, `lot`, `serial`, `expires_in_secs` |
| `verify_gs1_digital_link` | Retail | Verify GS1 URI, Luhn-10 check digit, and GTIN-to-SKU invariant binding. | `url`, `public_key_hex` |
| `pack_esl_packet` | Retail | Generate compact 89-byte binary packet for e-ink shelf tags (Sub-GHz/BLE). | `sku`, `store_id`, `price_cents`, `private_key_hex`, `key_id`, `valid_hours` |
| `verify_esl_packet` | Retail | Cryptographically verify 89-byte ESL display binary packet. | `packet_hex`, `public_key_hex` |
| `verify_retail_url` | Retail | Verify legacy retail deep-link (`?p=`) with dual-persona SSO check. | `url`, `public_key_hex`, `key_id`, `authenticated_associate` |
| `pack_retail_url` | Retail | Generate signed retail deep-link URL scannable by phone or scan gun. | `retailer_id`, `sku`, `store_id`, `private_key_hex`, `key_id`, `role`, `expires_in_secs` |
| `sign_custody_transfer` | Logistics | Sign non-repudiable custody transfer manifest for autonomous hand-offs (AGV/Drone). | `transfer_id`, `sender_agent_id`, `recipient_agent_id`, `cargo_manifest_digest`, `private_key_hex` |
| `verify_custody_receipt` | Logistics | Verify signed custody transfer receipt from recipient agent. | `receipt_json`, `expected_transfer_id`, `expected_recipient_id`, `recipient_public_key_hex` |
| `export_qr_packets` | Air-Gap | Slice sealed capsule into sequential optical QR packets or PNG images. | `capsule_path`, `output_dir`, `packet_size`, `generate_png` |
| `import_qr_packets` | Air-Gap | Reassemble capsule from optical QR packet sequence across air gap. | `qr_dir`, `output_path` |
| `license_status` | Enterprise | Inspect offline `.aqlic` cryptographic enterprise license and seats. | *(None)* |

---

## 🚀 Third-Party Agent Harness Integration

`aegisqr-mcp` is designed to be completely **harness-agnostic**, working out-of-the-box with any AI agent harness that supports the open Model Context Protocol or standard subprocess communication.

### 1. Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "aegisqr": {
      "command": "/usr/local/bin/aegisqr-mcp",
      "args": []
    }
  }
}
```

### 2. Antigravity & Cursor (`mcpServers` configuration)
```json
{
  "mcpServers": {
    "aegisqr": {
      "command": "aegisqr-mcp"
    }
  }
}
```

### 3. LangChain / LangGraph (Python)
Integrate with LangChain agent workflows using the standard `mcp` client package:

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from langchain_core.tools import tool

# Spawn aegisqr-mcp as a background stdio server
server_params = StdioServerParameters(command="aegisqr-mcp", args=[])

async def verify_gs1_tag(url: str, pubkey_hex: str):
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "verify_gs1_digital_link",
                {"url": url, "public_key_hex": pubkey_hex}
            )
            return result.content[0].text
```

### 4. AutoGen / CrewAI Integration
```python
import subprocess
import json

class AegisQRToolAdapter:
    def __init__(self, binary="aegisqr-mcp"):
        self.proc = subprocess.Popen(
            [binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )

    def execute(self, tool_name: str, **kwargs):
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": kwargs}
        }
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        res = json.loads(self.proc.stdout.readline())
        return res.get("result")

# Reorder bot validates inventory tag before triggering PO
adapter = AegisQRToolAdapter()
verification = adapter.execute(
    "verify_gs1_digital_link",
    url="https://shop.brand.com/01/00812345678901?p=...",
    public_key_hex="e3b0c442..."
)
```

### 5. Custom Enterprise Agent Test Harnesses
You can test tool execution directly using standard UNIX pipes:
```bash
# Discover tools
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | aegisqr-mcp

# Call a tool directly
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_capsule","arguments":{"capsule_path":"test.aqr"}}}' | aegisqr-mcp
```

---

## 🧪 Testing & Verification

Run the comprehensive MCP protocol suite:
```bash
cargo test -p aegisqr-mcp --test mcp_protocol_tests
```
