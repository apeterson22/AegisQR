mod protocol;
mod tools;

use protocol::{JsonRpcRequest, JsonRpcResponse};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn main() -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(e) => {
                let err_resp = JsonRpcResponse::error(None, -32700, format!("Parse error: {e}"));
                let out = serde_json::to_string(&err_resp)?;
                writeln!(stdout, "{out}")?;
                stdout.flush()?;
                continue;
            }
        };

        let is_notification = request.id.is_none();
        let id = request.id.clone();

        match request.method.as_str() {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "aegisqr-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                });
                let resp = JsonRpcResponse::success(id, result);
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{out}")?;
                stdout.flush()?;
            }
            "notifications/initialized" => {
                if !is_notification {
                    let resp = JsonRpcResponse::success(id, json!({}));
                    let out = serde_json::to_string(&resp)?;
                    writeln!(stdout, "{out}")?;
                    stdout.flush()?;
                }
            }
            "ping" => {
                let resp = JsonRpcResponse::success(id, json!({}));
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{out}")?;
                stdout.flush()?;
            }
            "tools/list" => {
                let tools_list = tools::list_tools();
                let result = json!({
                    "tools": tools_list
                });
                let resp = JsonRpcResponse::success(id, result);
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{out}")?;
                stdout.flush()?;
            }
            "tools/call" => {
                let params = request.params.unwrap_or(Value::Null);
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

                let tool_res = tools::handle_tool_call(tool_name, &arguments);
                let resp = JsonRpcResponse::success(id, serde_json::to_value(&tool_res)?);
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{out}")?;
                stdout.flush()?;
            }
            other => {
                if !is_notification {
                    let resp =
                        JsonRpcResponse::error(id, -32601, format!("Method '{other}' not found"));
                    let out = serde_json::to_string(&resp)?;
                    writeln!(stdout, "{out}")?;
                    stdout.flush()?;
                }
            }
        }
    }

    Ok(())
}
