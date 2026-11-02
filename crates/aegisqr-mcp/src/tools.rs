use std::fs;
use std::path::{Path, PathBuf};

use aegisqr_core::license::verify_license_status;
use aegisqr_core::{
    authorize_retail_action, build_gs1_digital_link, decode_esl_packet, encode_esl_packet,
    export_qr_packets, import_qr_packets, pack_to_file, read_capsule_file, sign_retail_payload,
    stage_capsule, unpack_capsule, validate_gtin_check_digit, verify_capsule,
    verify_complete_custody_handoff, verify_gs1_digital_link, verify_retail_payload,
    CompressionProfile, CustodyTransferManifest, CustodyTransferReceipt, EslData, PackOptions,
    PayloadType, RetailPayload, TrustStore,
};
use serde_json::{json, Value};

use crate::protocol::{CallToolResult, ToolDefinition};

pub fn list_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "inspect_capsule".to_string(),
            description: "Inspect an AegisQR (.aqr) sealed capsule without requiring the decryption passphrase. Returns public header metadata, bundle ID, payload type, security invariants, and embedded AgentIndex risk level.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "capsule_path": {
                        "type": "string",
                        "description": "Absolute path to the .aqr capsule file"
                    }
                },
                "required": ["capsule_path"]
            }),
        },
        ToolDefinition {
            name: "verify_capsule".to_string(),
            description: "Verify the cryptographic integrity of an AegisQR (.aqr) capsule. Validates Ed25519 signature over all headers, chunk table hashes, and checks against trust store if provided.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "capsule_path": {
                        "type": "string",
                        "description": "Absolute path to the .aqr capsule file"
                    },
                    "strict_trust": {
                        "type": "boolean",
                        "description": "Require signer to exist in the trust store (default: false)"
                    },
                    "trust_store_path": {
                        "type": "string",
                        "description": "Optional path to trust store JSON file"
                    }
                },
                "required": ["capsule_path"]
            }),
        },
        ToolDefinition {
            name: "unpack_capsule".to_string(),
            description: "Decrypt and unpack an AegisQR (.aqr) capsule into a destination directory. Automatically quarantines all executable file types (.sh, .py, .exe, etc.) into a quarantine/ subdirectory to protect the host.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "capsule_path": {
                        "type": "string",
                        "description": "Absolute path to the .aqr capsule file"
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Target destination directory"
                    },
                    "passphrase": {
                        "type": "string",
                        "description": "Decryption passphrase"
                    },
                    "quarantine_all": {
                        "type": "boolean",
                        "description": "Stage all restored files directly into quarantine/ (default: false)"
                    }
                },
                "required": ["capsule_path", "output_dir", "passphrase"]
            }),
        },
        ToolDefinition {
            name: "pack_capsule".to_string(),
            description: "Create a sealed, encrypted, and signed AegisQR (.aqr) capsule from a single file or directory. Encrypts with XChaCha20-Poly1305 + Argon2id and signs with Ed25519.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "input_path": {
                        "type": "string",
                        "description": "File or directory to package"
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Output .aqr capsule file path"
                    },
                    "passphrase": {
                        "type": "string",
                        "description": "Encryption passphrase"
                    },
                    "compression": {
                        "type": "string",
                        "enum": ["none", "fast", "balanced", "qr-basic"],
                        "description": "Compression profile (default: balanced)"
                    },
                    "is_aicx": {
                        "type": "boolean",
                        "description": "Treat input as an AICX archive and autodiscover companion sidecar"
                    },
                    "sidecar_path": {
                        "type": "string",
                        "description": "Optional explicit path to AICX sidecar metadata"
                    }
                },
                "required": ["input_path", "output_path", "passphrase"]
            }),
        },
        ToolDefinition {
            name: "verify_retail_url".to_string(),
            description: "Cryptographically verify a signed universal retail deep-link URL (from a physical shelf tag or QR code). Checks Ed25519 signature, expiration, SKU/Store binding, and enforces dual-persona role gating.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The complete universal deep link URL containing ?p= or &p="
                    },
                    "public_key_hex": {
                        "type": "string",
                        "description": "64-character hex Ed25519 public key"
                    },
                    "key_id": {
                        "type": "string",
                        "description": "Key ID matching the kid field"
                    },
                    "authenticated_associate": {
                        "type": "boolean",
                        "description": "Simulate an authenticated employee SSO session (required for associate roles)"
                    }
                },
                "required": ["url", "public_key_hex", "key_id"]
            }),
        },
        ToolDefinition {
            name: "pack_retail_url".to_string(),
            description: "Generate an Ed25519 signed universal retail deep-link URL. Binds SKU, store ID, campaign, expiration, and persona role into a standard HTTPS link scannable by any mobile camera.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "retailer_id": {
                        "type": "string",
                        "description": "Retailer identifier"
                    },
                    "sku": {
                        "type": "string",
                        "description": "Product SKU or UPC"
                    },
                    "store_id": {
                        "type": "string",
                        "description": "Store location identifier"
                    },
                    "private_key_hex": {
                        "type": "string",
                        "description": "64-character hex Ed25519 private key seed"
                    },
                    "key_id": {
                        "type": "string",
                        "description": "Key ID (kid)"
                    },
                    "role": {
                        "type": "string",
                        "enum": ["customer", "associate"],
                        "description": "Target persona role (default: customer)"
                    },
                    "base_url": {
                        "type": "string",
                        "description": "Base HTTPS URL (default: https://aegisqr.app/qr/product)"
                    },
                    "expires_in_secs": {
                        "type": "integer",
                        "description": "Seconds until expiration (0 = no expiration)"
                    }
                },
                "required": ["retailer_id", "sku", "store_id", "private_key_hex", "key_id"]
            }),
        },
        ToolDefinition {
            name: "export_qr_packets".to_string(),
            description: "Slice an AegisQR (.aqr) capsule into bounded QR packet files (AQRP) for optical camera scanning or screen handoff across physical air gaps.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "capsule_path": {
                        "type": "string",
                        "description": "Path to .aqr capsule file"
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Destination directory for packets"
                    },
                    "packet_size": {
                        "type": "integer",
                        "description": "Maximum payload bytes per packet (default: 512)"
                    },
                    "generate_png": {
                        "type": "boolean",
                        "description": "Generate scannable PNG QR code images (default: false)"
                    }
                },
                "required": ["capsule_path", "output_dir"]
            }),
        },
        ToolDefinition {
            name: "import_qr_packets".to_string(),
            description: "Reassemble an AegisQR (.aqr) capsule from scanned optical QR packet files, validating per-packet BLAKE3 checksums and overall capsule integrity.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "qr_dir": {
                        "type": "string",
                        "description": "Directory containing .cbor or .json QR packet files"
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Path to write reassembled .aqr capsule"
                    }
                },
                "required": ["qr_dir", "output_path"]
            }),
        },
        ToolDefinition {
            name: "license_status".to_string(),
            description: "Inspect the offline cryptographic .aqlic enterprise license status, reporting active tier, seat allocations, expiration date, and grace period.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
        ToolDefinition {
            name: "verify_gs1_digital_link".to_string(),
            description: "Verify a GS1 Digital Link 2027 standard URI. Validates GTIN check digit, URI segment syntax, verifies Ed25519 signature payload in ?p=, and confirms GTIN binding to SKU/UPC.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Complete GS1 Digital Link URI (e.g., https://example.com/01/00012345678905/21/SER123?p=...)"
                    },
                    "public_key_hex": {
                        "type": "string",
                        "description": "64-character hex Ed25519 public key of the signer"
                    },
                    "key_id": {
                        "type": "string",
                        "description": "Key ID matching the kid field in the retail payload"
                    }
                },
                "required": ["url", "public_key_hex", "key_id"]
            }),
        },
        ToolDefinition {
            name: "pack_gs1_digital_link".to_string(),
            description: "Generate a GS1 Digital Link 2027 compliant URI with cryptographic Ed25519 AegisQR payload embedded in query parameter ?p=.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Base domain or URL (default: https://id.aegisqr.app)"
                    },
                    "gtin": {
                        "type": "string",
                        "description": "Standard GS1 GTIN (GTIN-8, GTIN-12, GTIN-13, or GTIN-14)"
                    },
                    "retailer_id": {
                        "type": "string",
                        "description": "Retailer identifier"
                    },
                    "store_id": {
                        "type": "string",
                        "description": "Store location identifier"
                    },
                    "private_key_hex": {
                        "type": "string",
                        "description": "64-character hex Ed25519 private key seed"
                    },
                    "key_id": {
                        "type": "string",
                        "description": "Key ID (kid)"
                    },
                    "sku": {
                        "type": "string",
                        "description": "Optional SKU (defaults to gtin if omitted)"
                    },
                    "serial": {
                        "type": "string",
                        "description": "Optional product serial number"
                    },
                    "lot": {
                        "type": "string",
                        "description": "Optional batch/lot number"
                    },
                    "store_gln": {
                        "type": "string",
                        "description": "Optional store Global Location Number"
                    },
                    "expires_in_secs": {
                        "type": "integer",
                        "description": "Seconds until expiration (0 = no expiration)"
                    }
                },
                "required": ["gtin", "retailer_id", "store_id", "private_key_hex", "key_id"]
            }),
        },
        ToolDefinition {
            name: "pack_esl_packet".to_string(),
            description: "Encode an Electronic Shelf Label (ESL) binary micro-packet (exactly 89 bytes) signed with Ed25519 for low-bandwidth BLE / Sub-GHz wireless displays.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sku_numeric": {
                        "type": "integer",
                        "description": "Numeric product SKU (u64)"
                    },
                    "store_id": {
                        "type": "integer",
                        "description": "Numeric store ID (u16)"
                    },
                    "price_cents": {
                        "type": "integer",
                        "description": "Price in cents (e.g. 1999 for $19.99)"
                    },
                    "private_key_hex": {
                        "type": "string",
                        "description": "64-character hex Ed25519 private key seed"
                    },
                    "retailer_id_hash": {
                        "type": "integer",
                        "description": "Retailer ID hash (u32, default: 0)"
                    },
                    "expires_at": {
                        "type": "integer",
                        "description": "Expiration unix timestamp in seconds (0 = no expiration)"
                    },
                    "is_associate_gated": {
                        "type": "boolean",
                        "description": "Gated for employee handhelds only (default: false)"
                    },
                    "is_sale_active": {
                        "type": "boolean",
                        "description": "Active promotional sale flag (default: false)"
                    }
                },
                "required": ["sku_numeric", "store_id", "price_cents", "private_key_hex"]
            }),
        },
        ToolDefinition {
            name: "decode_esl_packet".to_string(),
            description: "Decode and cryptographically verify an Electronic Shelf Label (ESL) 89-byte binary packet (supplied as hex string).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "packet_hex": {
                        "type": "string",
                        "description": "178-character hex encoded 89-byte ESL packet"
                    },
                    "public_key_hex": {
                        "type": "string",
                        "description": "64-character hex Ed25519 public key"
                    }
                },
                "required": ["packet_hex", "public_key_hex"]
            }),
        },
        ToolDefinition {
            name: "create_custody_transfer".to_string(),
            description: "Create and sign an Autonomous Agent-to-Agent (A2A) Custody Transfer Manifest for physical air-gapped or robotic asset handovers.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "manifest_id": {
                        "type": "string",
                        "description": "Unique manifest identifier"
                    },
                    "sender_agent_id": {
                        "type": "string",
                        "description": "Sender autonomous agent / robot ID"
                    },
                    "receiver_agent_id": {
                        "type": "string",
                        "description": "Expected receiver agent / robot ID"
                    },
                    "capsule_id": {
                        "type": "string",
                        "description": "AegisQR capsule bundle ID or asset tag"
                    },
                    "payload_blake3_hash": {
                        "type": "string",
                        "description": "Cryptographic BLAKE3 hash of the cargo or capsule"
                    },
                    "sender_private_key_hex": {
                        "type": "string",
                        "description": "64-character hex Ed25519 private key seed for sender agent"
                    },
                    "geofence": {
                        "type": "string",
                        "description": "Optional geofence coordinates or zone identifier"
                    },
                    "temperature_max_celsius": {
                        "type": "number",
                        "description": "Optional cold-chain temperature threshold"
                    }
                },
                "required": ["manifest_id", "sender_agent_id", "receiver_agent_id", "capsule_id", "payload_blake3_hash", "sender_private_key_hex"]
            }),
        },
        ToolDefinition {
            name: "verify_custody_transfer".to_string(),
            description: "Verify complete bilateral non-repudiation between Custody Transfer Manifest and Receipt for autonomous logistics handoffs.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "manifest": {
                        "type": "object",
                        "description": "CustodyTransferManifest JSON object"
                    },
                    "receipt": {
                        "type": "object",
                        "description": "CustodyTransferReceipt JSON object"
                    },
                    "sender_public_key_hex": {
                        "type": "string",
                        "description": "64-character hex Ed25519 public key of sender agent"
                    },
                    "receiver_public_key_hex": {
                        "type": "string",
                        "description": "64-character hex Ed25519 public key of receiver agent"
                    }
                },
                "required": ["manifest", "receipt", "sender_public_key_hex", "receiver_public_key_hex"]
            }),
        },
    ]
}

pub fn handle_tool_call(name: &str, arguments: &Value) -> CallToolResult {
    match name {
        "inspect_capsule" => inspect_capsule(arguments),
        "verify_capsule" => verify_capsule_tool(arguments),
        "unpack_capsule" => unpack_capsule_tool(arguments),
        "pack_capsule" => pack_capsule_tool(arguments),
        "verify_retail_url" => verify_retail_url_tool(arguments),
        "pack_retail_url" => pack_retail_url_tool(arguments),
        "export_qr_packets" => export_qr_packets_tool(arguments),
        "import_qr_packets" => import_qr_packets_tool(arguments),
        "license_status" => license_status_tool(),
        "verify_gs1_digital_link" => verify_gs1_digital_link_tool(arguments),
        "pack_gs1_digital_link" => pack_gs1_digital_link_tool(arguments),
        "pack_esl_packet" => pack_esl_packet_tool(arguments),
        "decode_esl_packet" => decode_esl_packet_tool(arguments),
        "create_custody_transfer" => create_custody_transfer_tool(arguments),
        "verify_custody_transfer" => verify_custody_transfer_tool(arguments),
        unknown => CallToolResult::err(format!("Unknown tool: {unknown}")),
    }
}

fn inspect_capsule(args: &Value) -> CallToolResult {
    let path_str = match args.get("capsule_path").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: capsule_path"),
    };
    let path = Path::new(path_str);
    match read_capsule_file(path) {
        Ok(capsule) => {
            let output = json!({
                "bundle_id": capsule.public_header.bundle_id,
                "version": capsule.public_header.version,
                "created_at": capsule.public_header.created_at,
                "payload_type": capsule.public_header.payload_type,
                "chunk_count": capsule.public_header.chunk_count,
                "encrypted": capsule.public_header.encrypted,
                "signed": capsule.public_header.signed,
                "auto_execute_capable": capsule.public_header.auto_execute_capable,
                "auto_execute_default": capsule.public_header.auto_execute_default,
                "requires_signature": capsule.public_header.requires_signature,
                "requires_policy": capsule.public_header.requires_policy,
                "agent_index": {
                    "capsule_type": capsule.agent_index.capsule_type,
                    "summary": capsule.agent_index.summary,
                    "risk_level": capsule.agent_index.risk_level,
                    "runtime_requirement": capsule.agent_index.runtime_requirement,
                    "entrypoint_candidate": capsule.agent_index.entrypoint_candidate,
                    "permissions_requested": capsule.agent_index.permissions_requested,
                    "expected_outputs": capsule.agent_index.expected_outputs,
                },
                "policy_block": {
                    "auto_execute_enabled": capsule.policy_block.auto_execute_enabled,
                    "native_execution_allowed": capsule.policy_block.native_execution_allowed,
                    "required_sandbox": capsule.policy_block.required_sandbox,
                    "quarantine_executables": capsule.policy_block.quarantine_executables,
                    "max_risk_level": capsule.policy_block.max_risk_level,
                }
            });
            CallToolResult::ok(serde_json::to_string_pretty(&output).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Failed to inspect capsule: {e:#}")),
    }
}

fn verify_capsule_tool(args: &Value) -> CallToolResult {
    let path_str = match args.get("capsule_path").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: capsule_path"),
    };
    let path = Path::new(path_str);
    let strict = args
        .get("strict_trust")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let ts = match args.get("trust_store_path").and_then(|v| v.as_str()) {
        Some(ts_path) => match fs::read(ts_path) {
            Ok(bytes) => match serde_json::from_slice::<TrustStore>(&bytes) {
                Ok(store) => Some(store),
                Err(e) => return CallToolResult::err(format!("Failed to parse trust store: {e}")),
            },
            Err(e) => return CallToolResult::err(format!("Failed to read trust store file: {e}")),
        },
        None => None,
    };

    match verify_capsule(path, ts.as_ref(), strict) {
        Ok(()) => {
            let res = json!({
                "status": "valid",
                "capsule_path": path_str,
                "strict_trust": strict,
                "verified": true,
                "message": "Capsule cryptographic signature and chunk table verification succeeded."
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Verification failed: {e:#}")),
    }
}

fn unpack_capsule_tool(args: &Value) -> CallToolResult {
    let capsule_path = match args.get("capsule_path").and_then(|v| v.as_str()) {
        Some(s) => Path::new(s),
        None => return CallToolResult::err("Missing required argument: capsule_path"),
    };
    let output_dir = match args.get("output_dir").and_then(|v| v.as_str()) {
        Some(s) => Path::new(s),
        None => return CallToolResult::err("Missing required argument: output_dir"),
    };
    let passphrase = match args.get("passphrase").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: passphrase"),
    };
    let quarantine_all = args
        .get("quarantine_all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let res = if quarantine_all {
        stage_capsule(capsule_path, output_dir, passphrase)
    } else {
        unpack_capsule(capsule_path, output_dir, passphrase)
    };

    match res {
        Ok(()) => {
            let status = json!({
                "status": "restored",
                "output_dir": output_dir.display().to_string(),
                "quarantine_enforced": true,
                "message": "Capsule unpacked successfully. Executable files isolated to quarantine/."
            });
            CallToolResult::ok(serde_json::to_string_pretty(&status).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Unpack failed: {e:#}")),
    }
}

fn pack_capsule_tool(args: &Value) -> CallToolResult {
    let input_path = match args.get("input_path").and_then(|v| v.as_str()) {
        Some(s) => Path::new(s),
        None => return CallToolResult::err("Missing required argument: input_path"),
    };
    let output_path = match args.get("output_path").and_then(|v| v.as_str()) {
        Some(s) => Path::new(s),
        None => return CallToolResult::err("Missing required argument: output_path"),
    };
    let passphrase = match args.get("passphrase").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: passphrase"),
    };

    let comp_str = args
        .get("compression")
        .and_then(|v| v.as_str())
        .unwrap_or("balanced");
    let compression = match comp_str {
        "none" => CompressionProfile::None,
        "fast" => CompressionProfile::Fast,
        "balanced" => CompressionProfile::Balanced,
        "qr-basic" => CompressionProfile::QrBasic,
        other => return CallToolResult::err(format!("Invalid compression profile: {other}")),
    };

    let is_aicx = args
        .get("is_aicx")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let sidecar_buf = args
        .get("sidecar_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    let payload_type = if is_aicx {
        Some(PayloadType::AicxArchive)
    } else if input_path.is_dir() {
        Some(PayloadType::DirectoryTar)
    } else {
        Some(PayloadType::RawFile)
    };

    let opts = PackOptions {
        compression,
        payload_type,
        auto_execute_capable: false,
        auto_execute_requested: false,
        aicx_sidecar_path: sidecar_buf,
        aicx_strict: is_aicx,
        ..PackOptions::default()
    };

    match pack_to_file(input_path, output_path, passphrase, opts) {
        Ok(capsule) => {
            let res = json!({
                "status": "packed",
                "bundle_id": capsule.public_header.bundle_id,
                "output_path": output_path.display().to_string(),
                "chunks": capsule.public_header.chunk_count,
                "signed": capsule.public_header.signed,
                "encrypted": capsule.public_header.encrypted
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Failed to pack capsule: {e:#}")),
    }
}

fn verify_retail_url_tool(args: &Value) -> CallToolResult {
    let url = match args.get("url").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: url"),
    };
    let pubkey_hex = match args.get("public_key_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: public_key_hex"),
    };
    let kid = match args.get("key_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: key_id"),
    };
    let is_auth_associate = args
        .get("authenticated_associate")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let pubkey_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid public_key_hex: {e}")),
    };

    let p_param = if let Some(idx) = url.find("?p=") {
        &url[idx + 3..]
    } else if let Some(idx) = url.find("&p=") {
        &url[idx + 3..]
    } else {
        return CallToolResult::err("URL does not contain ?p= or &p= signed payload parameter");
    };

    let envelope_b64 = p_param.split('&').next().unwrap_or(p_param);

    let mut trust_store = TrustStore::default();
    trust_store.add_signer(kid.to_string(), pubkey_bytes);

    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => return CallToolResult::err(format!("System time error: {e}")),
    };

    match verify_retail_payload(envelope_b64, &trust_store, now) {
        Ok(payload) => {
            if let Err(auth_err) = authorize_retail_action(&payload, is_auth_associate) {
                return CallToolResult::err(format!("Authorization Denied: {auth_err:#}"));
            }
            let res = json!({
                "status": "verified",
                "retailer_id": payload.retailer_id,
                "sku": payload.sku,
                "store_id": payload.store_id,
                "role": payload.role.unwrap_or_else(|| "customer".to_string()),
                "issued_at": payload.issued_at,
                "expires_at": payload.expires_at,
                "campaign_id": payload.campaign_id,
                "message": "Retail signature cryptographically valid."
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Verification failed: {e:#}")),
    }
}

fn pack_retail_url_tool(args: &Value) -> CallToolResult {
    let retailer_id = match args.get("retailer_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return CallToolResult::err("Missing required argument: retailer_id"),
    };
    let sku = match args.get("sku").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return CallToolResult::err("Missing required argument: sku"),
    };
    let store_id = match args.get("store_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return CallToolResult::err("Missing required argument: store_id"),
    };
    let privkey_hex = match args.get("private_key_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: private_key_hex"),
    };
    let kid = match args.get("key_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return CallToolResult::err("Missing required argument: key_id"),
    };

    let privkey_bytes = match hex::decode(privkey_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid private_key_hex: {e}")),
    };

    let role = args
        .get("role")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let base_url = args
        .get("base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("https://aegisqr.app/qr/product");
    let expires_in = args
        .get("expires_in_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => return CallToolResult::err(format!("System time error: {e}")),
    };
    let expires_at = if expires_in > 0 { now + expires_in } else { 0 };

    let payload = RetailPayload {
        retailer_id,
        sku,
        upc: None,
        store_id,
        aisle: None,
        bay: None,
        shelf: None,
        campaign_id: None,
        experience_id: None,
        role,
        label_version: 1,
        issued_at: now,
        expires_at,
        fallback_url_id: None,
    };

    match sign_retail_payload(payload, &privkey_bytes, kid) {
        Ok(b64) => {
            let base = base_url.trim_end_matches('/');
            let separator = if base.contains('?') { "&p=" } else { "?p=" };
            let full_url = format!("{}{}{}", base, separator, b64);
            let res = json!({
                "status": "generated",
                "signed_url": full_url,
                "b64_payload": b64,
                "issued_at": now,
                "expires_at": expires_at
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Failed to pack retail URL: {e:#}")),
    }
}

fn export_qr_packets_tool(args: &Value) -> CallToolResult {
    let capsule_path = match args.get("capsule_path").and_then(|v| v.as_str()) {
        Some(s) => Path::new(s),
        None => return CallToolResult::err("Missing required argument: capsule_path"),
    };
    let output_dir = match args.get("output_dir").and_then(|v| v.as_str()) {
        Some(s) => Path::new(s),
        None => return CallToolResult::err("Missing required argument: output_dir"),
    };
    let packet_size = args
        .get("packet_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(512) as usize;
    let generate_png = args
        .get("generate_png")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    fs::create_dir_all(output_dir).ok();

    match export_qr_packets(capsule_path, output_dir, packet_size, generate_png) {
        Ok(()) => {
            let res = json!({
                "status": "exported",
                "capsule_path": capsule_path.display().to_string(),
                "output_dir": output_dir.display().to_string(),
                "packet_size": packet_size,
                "png_generated": generate_png
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Failed to export QR packets: {e:#}")),
    }
}

fn import_qr_packets_tool(args: &Value) -> CallToolResult {
    let qr_dir = match args.get("qr_dir").and_then(|v| v.as_str()) {
        Some(s) => Path::new(s),
        None => return CallToolResult::err("Missing required argument: qr_dir"),
    };
    let output_path = match args.get("output_path").and_then(|v| v.as_str()) {
        Some(s) => Path::new(s),
        None => return CallToolResult::err("Missing required argument: output_path"),
    };

    match import_qr_packets(qr_dir, output_path) {
        Ok(()) => {
            let res = json!({
                "status": "imported",
                "qr_dir": qr_dir.display().to_string(),
                "output_path": output_path.display().to_string(),
                "message": "Capsule successfully reassembled and verified from QR packets."
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Failed to import QR packets: {e:#}")),
    }
}

fn license_status_tool() -> CallToolResult {
    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };
    let lic = verify_license_status(now);
    let res = json!({
        "status": lic.status,
        "license_id": lic.license_id,
        "organization": lic.organization,
        "tier": lic.tier,
        "seats": lic.seats,
        "expires_at": lic.expires_at,
        "days_remaining": lic.days_remaining
    });
    CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
}

fn verify_gs1_digital_link_tool(args: &Value) -> CallToolResult {
    let url = match args.get("url").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: url"),
    };
    let pubkey_hex = match args.get("public_key_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: public_key_hex"),
    };
    let key_id = match args.get("key_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: key_id"),
    };

    let pubkey_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid public_key_hex: {e}")),
    };

    let mut trust_store = TrustStore::default();
    trust_store.add_signer(key_id.to_string(), pubkey_bytes);

    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };

    match verify_gs1_digital_link(url, &trust_store, now) {
        Ok(verified) => {
            let res = json!({
                "status": "verified",
                "gtin": verified.gtin,
                "serial": verified.serial,
                "lot": verified.lot,
                "store_gln": verified.store_gln,
                "check_digit_valid": verified.check_digit_valid,
                "path_gtin_matches_payload": verified.path_gtin_matches_payload,
                "retail_payload": verified.verified_retail_payload,
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("GS1 Digital Link verification failed: {e:#}")),
    }
}

fn pack_gs1_digital_link_tool(args: &Value) -> CallToolResult {
    let gtin = match args.get("gtin").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: gtin"),
    };
    let retailer_id = match args.get("retailer_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: retailer_id"),
    };
    let store_id = match args.get("store_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: store_id"),
    };
    let privkey_hex = match args.get("private_key_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: private_key_hex"),
    };
    let key_id = match args.get("key_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: key_id"),
    };

    if !validate_gtin_check_digit(gtin) {
        return CallToolResult::err(format!("Invalid GTIN check digit for '{gtin}'"));
    }

    let privkey_bytes = match hex::decode(privkey_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid private_key_hex: {e}")),
    };

    let domain = args
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("https://id.aegisqr.app");
    let sku = args.get("sku").and_then(|v| v.as_str()).unwrap_or(gtin);
    let serial = args.get("serial").and_then(|v| v.as_str());
    let lot = args.get("lot").and_then(|v| v.as_str());
    let store_gln = args.get("store_gln").and_then(|v| v.as_str());
    let expires_in_secs = args
        .get("expires_in_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };
    let expires_at = if expires_in_secs > 0 {
        now + expires_in_secs
    } else {
        0
    };

    let payload = RetailPayload {
        retailer_id: retailer_id.to_string(),
        sku: sku.to_string(),
        upc: Some(gtin.to_string()),
        store_id: store_id.to_string(),
        aisle: None,
        bay: None,
        shelf: None,
        campaign_id: None,
        experience_id: None,
        role: None,
        label_version: 1,
        issued_at: now,
        expires_at,
        fallback_url_id: None,
    };

    let token = match sign_retail_payload(payload, &privkey_bytes, key_id.to_string()) {
        Ok(t) => t,
        Err(e) => return CallToolResult::err(format!("Failed to sign retail payload: {e:#}")),
    };

    match build_gs1_digital_link(domain, gtin, serial, lot, store_gln, &token) {
        Ok(url) => {
            let res = json!({
                "status": "created",
                "url": url,
                "gtin": gtin,
                "sku": sku,
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Failed to build GS1 Digital Link: {e:#}")),
    }
}

fn pack_esl_packet_tool(args: &Value) -> CallToolResult {
    let sku_numeric = match args.get("sku_numeric").and_then(|v| v.as_u64()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: sku_numeric"),
    };
    let store_id = match args.get("store_id").and_then(|v| v.as_u64()) {
        Some(s) => s as u16,
        None => return CallToolResult::err("Missing required argument: store_id"),
    };
    let price_cents = match args.get("price_cents").and_then(|v| v.as_u64()) {
        Some(s) => s as u32,
        None => return CallToolResult::err("Missing required argument: price_cents"),
    };
    let privkey_hex = match args.get("private_key_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: private_key_hex"),
    };

    let privkey_bytes = match hex::decode(privkey_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid private_key_hex: {e}")),
    };

    let retailer_id_hash = args
        .get("retailer_id_hash")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let expires_at = args.get("expires_at").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let is_associate_gated = args
        .get("is_associate_gated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_sale_active = args
        .get("is_sale_active")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let esl_data = EslData {
        retailer_id_hash,
        sku_numeric,
        store_id,
        price_cents,
        expires_at,
        is_associate_gated,
        is_sale_active,
    };

    match encode_esl_packet(&esl_data, &privkey_bytes) {
        Ok(pkt) => {
            let res = json!({
                "status": "encoded",
                "packet_hex": hex::encode(&pkt),
                "packet_len": pkt.len(),
                "sku_numeric": sku_numeric,
                "price_cents": price_cents,
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Failed to encode ESL packet: {e:#}")),
    }
}

fn decode_esl_packet_tool(args: &Value) -> CallToolResult {
    let packet_hex = match args.get("packet_hex").and_then(|v| v.as_str()) {
        Some(s) => s.trim(),
        None => return CallToolResult::err("Missing required argument: packet_hex"),
    };
    let pubkey_hex = match args.get("public_key_hex").and_then(|v| v.as_str()) {
        Some(s) => s.trim(),
        None => return CallToolResult::err("Missing required argument: public_key_hex"),
    };

    let packet_bytes = match hex::decode(packet_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid packet_hex: {e}")),
    };
    let pubkey_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid public_key_hex: {e}")),
    };

    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };

    match decode_esl_packet(&packet_bytes, &pubkey_bytes, now) {
        Ok(data) => {
            let res = json!({
                "status": "verified",
                "esl": data,
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Failed to decode/verify ESL packet: {e:#}")),
    }
}

fn create_custody_transfer_tool(args: &Value) -> CallToolResult {
    let manifest_id = match args.get("manifest_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: manifest_id"),
    };
    let sender_agent_id = match args.get("sender_agent_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: sender_agent_id"),
    };
    let receiver_agent_id = match args.get("receiver_agent_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: receiver_agent_id"),
    };
    let capsule_id = match args.get("capsule_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: capsule_id"),
    };
    let payload_blake3_hash = match args.get("payload_blake3_hash").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: payload_blake3_hash"),
    };
    let privkey_hex = match args.get("sender_private_key_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::err("Missing required argument: sender_private_key_hex"),
    };

    let privkey_bytes = match hex::decode(privkey_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid sender_private_key_hex: {e}")),
    };

    let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };

    let geofence = args
        .get("geofence")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let temp_max = args
        .get("temperature_max_celsius")
        .and_then(|v| v.as_f64())
        .map(|f| f as f32);

    let mut manifest = CustodyTransferManifest {
        manifest_id: manifest_id.to_string(),
        sender_agent_id: sender_agent_id.to_string(),
        receiver_agent_id: receiver_agent_id.to_string(),
        capsule_id: capsule_id.to_string(),
        payload_blake3_hash: payload_blake3_hash.to_string(),
        created_at: now,
        geofence,
        temperature_max_celsius: temp_max,
        sender_signature: None,
    };

    match manifest.sign(&privkey_bytes) {
        Ok(()) => {
            let res = json!({
                "status": "created",
                "manifest": manifest,
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Failed to sign custody manifest: {e:#}")),
    }
}

fn verify_custody_transfer_tool(args: &Value) -> CallToolResult {
    let manifest_val = match args.get("manifest") {
        Some(v) => v,
        None => return CallToolResult::err("Missing required argument: manifest"),
    };
    let receipt_val = match args.get("receipt") {
        Some(v) => v,
        None => return CallToolResult::err("Missing required argument: receipt"),
    };
    let sender_pubkey_hex = match args.get("sender_public_key_hex").and_then(|v| v.as_str()) {
        Some(s) => s.trim(),
        None => return CallToolResult::err("Missing required argument: sender_public_key_hex"),
    };
    let receiver_pubkey_hex = match args.get("receiver_public_key_hex").and_then(|v| v.as_str()) {
        Some(s) => s.trim(),
        None => return CallToolResult::err("Missing required argument: receiver_public_key_hex"),
    };

    let manifest: CustodyTransferManifest = match serde_json::from_value(manifest_val.clone()) {
        Ok(m) => m,
        Err(e) => return CallToolResult::err(format!("Invalid manifest object: {e}")),
    };
    let receipt: CustodyTransferReceipt = match serde_json::from_value(receipt_val.clone()) {
        Ok(r) => r,
        Err(e) => return CallToolResult::err(format!("Invalid receipt object: {e}")),
    };

    let sender_pub = match hex::decode(sender_pubkey_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid sender_public_key_hex: {e}")),
    };
    let receiver_pub = match hex::decode(receiver_pubkey_hex) {
        Ok(b) => b,
        Err(e) => return CallToolResult::err(format!("Invalid receiver_public_key_hex: {e}")),
    };

    match verify_complete_custody_handoff(&manifest, &receipt, &sender_pub, &receiver_pub) {
        Ok(()) => {
            let res = json!({
                "status": "verified",
                "manifest_id": manifest.manifest_id,
                "receipt_id": receipt.receipt_id,
                "verified_hash": manifest.payload_blake3_hash,
                "handoff_status": receipt.status,
            });
            CallToolResult::ok(serde_json::to_string_pretty(&res).unwrap_or_default())
        }
        Err(e) => CallToolResult::err(format!("Custody transfer verification failed: {e:#}")),
    }
}
