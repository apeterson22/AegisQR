use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn test_mcp_handshake_and_tools_list() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aegisqr-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start aegisqr-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    // 1. Initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0.0" }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&init_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let init_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "aegisqr-mcp");
    assert!(init_resp["result"]["capabilities"]["tools"].is_object());

    // 2. Initialized notification
    let notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    writeln!(stdin, "{}", serde_json::to_string(&notif).unwrap()).unwrap();
    stdin.flush().unwrap();

    // 3. Ping
    let ping_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "ping"
    });
    writeln!(stdin, "{}", serde_json::to_string(&ping_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let ping_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ping_resp["id"], 2);

    // 4. Tools list
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list"
    });
    writeln!(stdin, "{}", serde_json::to_string(&list_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let list_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(list_resp["id"], 3);
    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert_eq!(tools.len(), 15);

    let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(tool_names.contains(&"inspect_capsule"));
    assert!(tool_names.contains(&"verify_capsule"));
    assert!(tool_names.contains(&"unpack_capsule"));
    assert!(tool_names.contains(&"pack_capsule"));
    assert!(tool_names.contains(&"verify_retail_url"));
    assert!(tool_names.contains(&"pack_retail_url"));
    assert!(tool_names.contains(&"export_qr_packets"));
    assert!(tool_names.contains(&"import_qr_packets"));
    assert!(tool_names.contains(&"license_status"));
    assert!(tool_names.contains(&"verify_gs1_digital_link"));
    assert!(tool_names.contains(&"pack_gs1_digital_link"));
    assert!(tool_names.contains(&"pack_esl_packet"));
    assert!(tool_names.contains(&"decode_esl_packet"));
    assert!(tool_names.contains(&"create_custody_transfer"));
    assert!(tool_names.contains(&"verify_custody_transfer"));

    // 5. Tools call: license_status
    let lic_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "license_status",
            "arguments": {}
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&lic_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let lic_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(lic_resp["id"], 4);
    assert!(lic_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("status"));

    drop(stdin);
    child.wait().unwrap();
}

#[test]
fn test_mcp_retail_url_pack_and_verify() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aegisqr-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start aegisqr-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    let key_priv = "0707070707070707070707070707070707070707070707070707070707070707";
    let key_pub = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

    // Call pack_retail_url
    let pack_req = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "pack_retail_url",
            "arguments": {
                "retailer_id": "aegisqr",
                "sku": "SKU-99001",
                "store_id": "STORE-042",
                "private_key_hex": key_priv,
                "key_id": "key-1",
                "role": "customer"
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&pack_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let pack_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(pack_resp["id"], 10);
    let text = pack_resp["result"]["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed["status"], "generated");
    let signed_url = parsed["signed_url"].as_str().unwrap().to_string();

    // Call verify_retail_url
    let verify_req = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "verify_retail_url",
            "arguments": {
                "url": signed_url,
                "public_key_hex": key_pub,
                "key_id": "key-1",
                "authenticated_associate": false
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&verify_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let verify_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(verify_resp["id"], 11);
    let v_text = verify_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let v_parsed: Value = serde_json::from_str(v_text).unwrap();
    assert_eq!(v_parsed["status"], "verified");
    assert_eq!(v_parsed["sku"], "SKU-99001");
    assert_eq!(v_parsed["store_id"], "STORE-042");

    drop(stdin);
    child.wait().unwrap();
}

#[test]
fn test_mcp_capsule_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let test_file = dir.path().join("payload.txt");
    std::fs::write(&test_file, b"Confidential AI Swarm Payload").unwrap();
    let capsule_path = dir.path().join("secure.aqr");
    let unpack_dir = dir.path().join("unpacked");

    let mut child = Command::new(env!("CARGO_BIN_EXE_aegisqr-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start aegisqr-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    // 1. Pack capsule
    let pack_req = json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "pack_capsule",
            "arguments": {
                "input_path": test_file.to_str().unwrap(),
                "output_path": capsule_path.to_str().unwrap(),
                "passphrase": "super-strong-passphrase",
                "compression": "balanced"
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&pack_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let pack_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(pack_resp["id"], 20);
    let p_text = pack_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(p_text.contains("packed"));

    // 2. Inspect capsule without passphrase
    let inspect_req = json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {
            "name": "inspect_capsule",
            "arguments": {
                "capsule_path": capsule_path.to_str().unwrap()
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&inspect_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let insp_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(insp_resp["id"], 21);
    let insp_text = insp_resp["result"]["content"][0]["text"].as_str().unwrap();
    let insp_val: Value = serde_json::from_str(insp_text).unwrap();
    assert!(insp_val["bundle_id"].is_string());
    assert_eq!(insp_val["encrypted"], true);

    // 3. Verify capsule integrity
    let verify_req = json!({
        "jsonrpc": "2.0",
        "id": 22,
        "method": "tools/call",
        "params": {
            "name": "verify_capsule",
            "arguments": {
                "capsule_path": capsule_path.to_str().unwrap()
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&verify_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let v_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v_resp["id"], 22);
    let v_text = v_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(v_text.contains("valid"));

    // 4. Unpack capsule
    let unpack_req = json!({
        "jsonrpc": "2.0",
        "id": 23,
        "method": "tools/call",
        "params": {
            "name": "unpack_capsule",
            "arguments": {
                "capsule_path": capsule_path.to_str().unwrap(),
                "output_dir": unpack_dir.to_str().unwrap(),
                "passphrase": "super-strong-passphrase"
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&unpack_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let unp_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(unp_resp["id"], 23);
    let unp_text = unp_resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(unp_text.contains("restored"));

    // Check restored file content
    let restored_file = unpack_dir.join("payload.txt");
    assert!(restored_file.exists());
    assert_eq!(
        std::fs::read(restored_file).unwrap(),
        b"Confidential AI Swarm Payload"
    );

    drop(stdin);
    child.wait().unwrap();
}

#[test]
fn test_mcp_gs1_esl_and_custody_tools() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aegisqr-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start aegisqr-mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    let key_priv = "0707070707070707070707070707070707070707070707070707070707070707";
    let key_pub = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    let key2_priv = "0808080808080808080808080808080808080808080808080808080808080808";
    let key2_pub = "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca";

    // 1. Pack GS1 Digital Link
    let pack_gs1_req = json!({
        "jsonrpc": "2.0",
        "id": 30,
        "method": "tools/call",
        "params": {
            "name": "pack_gs1_digital_link",
            "arguments": {
                "gtin": "00012345678905",
                "retailer_id": "target",
                "store_id": "T-808",
                "private_key_hex": key_priv,
                "key_id": "key-1",
                "serial": "SER-999"
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&pack_gs1_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let gs1_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(gs1_resp["id"], 30);
    let text = gs1_resp["result"]["content"][0]["text"].as_str().unwrap();
    let parsed_gs1: Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed_gs1["status"], "created");
    let gs1_url = parsed_gs1["url"].as_str().unwrap().to_string();

    // 2. Verify GS1 Digital Link
    let verify_gs1_req = json!({
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/call",
        "params": {
            "name": "verify_gs1_digital_link",
            "arguments": {
                "url": gs1_url,
                "public_key_hex": key_pub,
                "key_id": "key-1"
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&verify_gs1_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let v_gs1_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v_gs1_resp["id"], 31);
    let text_v = v_gs1_resp["result"]["content"][0]["text"].as_str().unwrap();
    let parsed_v: Value = serde_json::from_str(text_v).unwrap();
    assert_eq!(parsed_v["status"], "verified");
    assert_eq!(parsed_v["gtin"], "00012345678905");
    assert_eq!(parsed_v["check_digit_valid"], true);
    assert_eq!(parsed_v["path_gtin_matches_payload"], true);

    // 3. Pack ESL Packet
    let pack_esl_req = json!({
        "jsonrpc": "2.0",
        "id": 32,
        "method": "tools/call",
        "params": {
            "name": "pack_esl_packet",
            "arguments": {
                "sku_numeric": 123456789,
                "store_id": 42,
                "price_cents": 2999,
                "private_key_hex": key_priv
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&pack_esl_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let esl_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(esl_resp["id"], 32);
    let text_esl = esl_resp["result"]["content"][0]["text"].as_str().unwrap();
    let parsed_esl: Value = serde_json::from_str(text_esl).unwrap();
    assert_eq!(parsed_esl["status"], "encoded");
    let packet_hex = parsed_esl["packet_hex"].as_str().unwrap().to_string();

    // 4. Decode ESL Packet
    let decode_esl_req = json!({
        "jsonrpc": "2.0",
        "id": 33,
        "method": "tools/call",
        "params": {
            "name": "decode_esl_packet",
            "arguments": {
                "packet_hex": packet_hex,
                "public_key_hex": key_pub
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&decode_esl_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let dec_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(dec_resp["id"], 33);
    let text_dec = dec_resp["result"]["content"][0]["text"].as_str().unwrap();
    let parsed_dec: Value = serde_json::from_str(text_dec).unwrap();
    assert_eq!(parsed_dec["status"], "verified");
    assert_eq!(parsed_dec["esl"]["sku_numeric"], 123456789);
    assert_eq!(parsed_dec["esl"]["price_cents"], 2999);

    // 5. Create Custody Transfer Manifest
    let cust_req = json!({
        "jsonrpc": "2.0",
        "id": 34,
        "method": "tools/call",
        "params": {
            "name": "create_custody_transfer",
            "arguments": {
                "manifest_id": "manifest-robot-99",
                "sender_agent_id": "drone-alpha",
                "receiver_agent_id": "docking-bay-04",
                "capsule_id": "capsule-xyz",
                "payload_blake3_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "sender_private_key_hex": key_priv
            }
        }
    });
    writeln!(stdin, "{}", serde_json::to_string(&cust_req).unwrap()).unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let cust_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(cust_resp["id"], 34);
    let text_cust = cust_resp["result"]["content"][0]["text"].as_str().unwrap();
    let parsed_cust: Value = serde_json::from_str(text_cust).unwrap();
    assert_eq!(parsed_cust["status"], "created");
    let manifest_val = parsed_cust["manifest"].clone();

    // Create a matching receipt using receiver key
    let mut receipt = aegisqr_core::CustodyTransferReceipt {
        receipt_id: "receipt-dock-01".to_string(),
        manifest_id: "manifest-robot-99".to_string(),
        receiver_agent_id: "docking-bay-04".to_string(),
        status: "accepted".to_string(),
        verified_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .to_string(),
        signed_at: 1700000000,
        receiver_signature: None,
    };
    let rec_priv = hex::decode(key2_priv).unwrap();
    receipt.sign(&rec_priv).unwrap();
    let receipt_val = serde_json::to_value(&receipt).unwrap();

    // 6. Verify Custody Transfer Handoff
    let verify_cust_req = json!({
        "jsonrpc": "2.0",
        "id": 35,
        "method": "tools/call",
        "params": {
            "name": "verify_custody_transfer",
            "arguments": {
                "manifest": manifest_val,
                "receipt": receipt_val,
                "sender_public_key_hex": key_pub,
                "receiver_public_key_hex": key2_pub
            }
        }
    });
    writeln!(
        stdin,
        "{}",
        serde_json::to_string(&verify_cust_req).unwrap()
    )
    .unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let v_cust_resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v_cust_resp["id"], 35);
    let text_vc = v_cust_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let parsed_vc: Value = serde_json::from_str(text_vc).unwrap();
    assert_eq!(parsed_vc["status"], "verified");
    assert_eq!(parsed_vc["handoff_status"], "accepted");

    drop(stdin);
    child.wait().unwrap();
}
