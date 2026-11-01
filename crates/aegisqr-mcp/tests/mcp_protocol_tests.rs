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
    assert_eq!(tools.len(), 9);

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
