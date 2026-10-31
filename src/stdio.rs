//! `pocketwire mcp`: the private tools over stdio, for AI apps that start local servers. It
//! answers initialize and tools/list itself and forwards tool calls to the running Bridge.

use std::sync::Arc;

use bytes::Bytes;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Mutex};

use crate::local::mcp::{self, CLIENT_HEADER};

const NOT_RUNNING: &str = "The Pocketwire Bridge is not running on this computer. Start it with `pocketwire run` or `pocketwire service install`.";

struct Upstream {
    endpoint: String,
    token: String,
    session: Mutex<Option<String>>,
}

enum CallError {
    /// The Bridge isn't there, or forgot our session (it restarted).
    Gone,
}

impl Upstream {
    async fn post(&self, body: &Value, session: Option<&str>, client: &str) -> Result<(u16, Option<String>, Value), CallError> {
        let mut h = vec![
            ("authorization", format!("Bearer {}", self.token)),
            ("content-type", "application/json".to_string()),
            ("accept", "application/json, text/event-stream".to_string()),
        ];
        if let Some(s) = session {
            h.push(("mcp-session-id", s.to_string()));
        }
        if !client.is_empty() {
            h.push((CLIENT_HEADER, client.to_string()));
        }
        let r = crate::net::request("POST", &self.endpoint, &h, Bytes::from(body.to_string()), 4 << 20).await.map_err(|_| CallError::Gone)?;
        let sid = r.headers.get("mcp-session-id").and_then(|v| v.to_str().ok()).map(str::to_string);
        let v = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        Ok((r.status, sid, v))
    }

    async fn connect(&self) -> Result<String, CallError> {
        let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "pocketwire-stdio", "version": crate::net::version()}}});
        let (status, sid, _) = self.post(&init, None, "").await?;
        let sid = match (status, sid) {
            (200, Some(s)) => s,
            _ => return Err(CallError::Gone),
        };
        let _ = self.post(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), Some(&sid), "").await;
        Ok(sid)
    }

    /// Forwards tools/call; connects on first use and once more if the Bridge restarted.
    async fn call(&self, params: &Value, client: &str) -> Result<Value, CallError> {
        for _ in 0..2 {
            let sid = {
                let mut s = self.session.lock().await;
                if s.is_none() {
                    *s = Some(self.connect().await?);
                }
                s.clone().unwrap()
            };
            let req = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params});
            match self.post(&req, Some(&sid), client).await {
                Ok((200, _, v)) => return Ok(v),
                _ => {
                    let mut s = self.session.lock().await;
                    if s.as_deref() == Some(&sid) {
                        *s = None;
                    }
                }
            }
        }
        Err(CallError::Gone)
    }
}

pub async fn run(port: u16, token: String) -> Result<(), String> {
    let up = Arc::new(Upstream { endpoint: format!("http://127.0.0.1:{port}/mcp"), token, session: Mutex::new(None) });
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(v) = out_rx.recv().await {
            let mut line = v.to_string();
            line.push('\n');
            if stdout.write_all(line.as_bytes()).await.is_err() || stdout.flush().await.is_err() {
                break;
            }
        }
    });
    let client = Arc::new(std::sync::Mutex::new(String::new()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                let _ = out_tx.send(mcp::rpc_error(&Value::Null, -32700, &format!("parse error: {e}")));
                continue;
            }
        };
        let Some(id) = msg.get("id").cloned() else { continue };
        let Some(method) = msg.get("method").and_then(Value::as_str).map(str::to_string) else { continue };
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        match method.as_str() {
            "initialize" => {
                *client.lock().unwrap() = mcp::client_name_of(&params);
                let _ = out_tx.send(mcp::rpc_result(&id, mcp::initialize_result(&params)));
            }
            "ping" | "logging/setLevel" => {
                let _ = out_tx.send(mcp::rpc_result(&id, json!({})));
            }
            "tools/list" => {
                let _ = out_tx.send(mcp::rpc_result(&id, mcp::tools()));
            }
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                if let Err((code, m)) = mcp::validate_args(name, params.get("arguments").unwrap_or(&Value::Null)) {
                    let _ = out_tx.send(mcp::rpc_error(&id, code, &m));
                    continue;
                }
                let (up, out, c) = (up.clone(), out_tx.clone(), client.lock().unwrap().clone());
                tokio::spawn(async move {
                    let answer = match up.call(&params, &c).await {
                        Ok(v) => match (v.get("result"), v.get("error")) {
                            (Some(r), _) => mcp::rpc_result(&id, r.clone()),
                            (_, Some(e)) => json!({"jsonrpc": "2.0", "id": id, "error": e}),
                            _ => mcp::rpc_result(&id, json!({"content": [{"type": "text", "text": "unexpected answer from the Bridge"}], "isError": true})),
                        },
                        Err(CallError::Gone) => mcp::rpc_result(&id, json!({"content": [{"type": "text", "text": NOT_RUNNING}], "isError": true})),
                    };
                    let _ = out.send(answer);
                });
            }
            _ => {
                let _ = out_tx.send(mcp::rpc_error(&id, -32601, "method not found"));
            }
        }
    }
    drop(out_tx);
    // Let calls in flight finish writing their answers.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), writer).await;
    Ok(())
}
