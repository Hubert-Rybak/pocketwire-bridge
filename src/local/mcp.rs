//! The private MCP server: JSON-RPC over the Streamable HTTP transport (JSON answers, no SSE),
//! with the same four tools as the cloud endpoint.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::local::engine::{Engine, NOT_FOUND};
use crate::local::store::Message;
use crate::log::quote;
use crate::util;
use crate::web::{Req, Resp};

/// Lets the stdio proxy pass on the name of the AI app that started it.
pub const CLIENT_HEADER: &str = "x-pocketwire-client";

pub const INSTRUCTIONS: &str = "Pocketwire sends SMS from the user's own phone number through the Pocketwire Bridge on this computer. \
This is the private endpoint: the number and the text stay on the user's computer and are not sent to the Pocketwire server. \
Depending on the user's settings, a message may wait for their approval in a page Pocketwire opens in the browser; \
send_sms returns the current status and get_message_status reports later changes.";

const PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_PROTOCOL: &str = "2025-06-18";
const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MessageOut {
    pub message_id: String,
    pub device_id: String,
    pub to: String,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    pub approval: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_name: String,
    pub private: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body: String,
    pub body_length: usize,
    pub created_at: String,
    pub updated_at: String,
}

fn out(m: &Message, device_id: &str) -> MessageOut {
    MessageOut {
        message_id: m.id.clone(),
        device_id: device_id.to_string(),
        to: m.to.clone(),
        status: m.status.clone(),
        error: m.error.clone(),
        approval: m.approval.clone(),
        client_name: m.client_name.clone(),
        private: true,
        body: m.body.clone(),
        body_length: m.body.chars().count(),
        created_at: util::rfc3339(m.created_at, false),
        updated_at: util::rfc3339(m.updated_at, false),
    }
}

/// The text agents read, matching the cloud's wording.
pub fn describe(m: &MessageOut) -> String {
    match m.status.as_str() {
        "sent" => format!("Sent to {}.", m.to),
        "delivered" => format!("Delivered to {}.", m.to),
        "awaiting_approval" => format!(
            "Waiting for approval on the user's computer: Pocketwire opened an approval page in the browser. Ask the user to click Send there. Check later with get_message_status({}).",
            quote(&m.message_id)
        ),
        "queued" | "sending" => format!("Handed to the phone, not confirmed yet. Check later with get_message_status({}).", quote(&m.message_id)),
        "rejected" => "The user rejected this message. Nothing was sent.".into(),
        "expired" => "Not sent: nobody approved it in time.".into(),
        "failed" if !m.error.is_empty() => format!("Sending failed: {}.", m.error),
        "failed" => "Sending failed.".into(),
        s => s.to_string(),
    }
}

fn message_schema() -> Value {
    let s = json!({"type": "string"});
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "approval": s, "body": s, "body_length": {"type": "integer"}, "client_name": s, "created_at": s,
            "device_id": s, "error": s, "message_id": s, "private": {"type": "boolean"}, "status": s, "to": s, "updated_at": s
        },
        "required": ["message_id", "device_id", "to", "status", "approval", "private", "body_length", "created_at", "updated_at"]
    })
}

fn read_only() -> Value {
    json!({"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false})
}

/// The tool list, as the Go Bridge offered it.
pub fn tools() -> Value {
    let s = json!({"type": "string"});
    json!({"tools": [
        {
            "name": "get_message_status",
            "title": "Get message status",
            "description": "Get the current status of a message sent with send_sms.",
            "annotations": read_only(),
            "inputSchema": {"type": "object", "additionalProperties": false,
                "properties": {"message_id": {"type": "string", "description": "The message_id returned by send_sms"}},
                "required": ["message_id"]},
            "outputSchema": message_schema(),
        },
        {
            "name": "list_devices",
            "title": "List devices",
            "description": "List the device this private endpoint sends from: the Pocketwire Bridge on this computer and whether it is online.",
            "annotations": read_only(),
            "inputSchema": {"type": "object", "additionalProperties": false},
            "outputSchema": {"type": "object", "additionalProperties": false,
                "properties": {"devices": {"type": "array", "items": {"type": "object", "additionalProperties": false,
                    "properties": {"can_send_sms": {"type": "boolean"}, "device_id": s, "kind": s, "name": s, "online": {"type": "boolean"}, "platform": s},
                    "required": ["device_id", "name", "kind", "platform", "online", "can_send_sms"]}}},
                "required": ["devices"]},
        },
        {
            "name": "list_recent_messages",
            "title": "List recent messages",
            "description": "List recent messages sent from this computer, newest first, with recipient, text, status and time.",
            "annotations": read_only(),
            "inputSchema": {"type": "object", "additionalProperties": false,
                "properties": {"limit": {"type": "integer", "description": "How many messages, newest first (default 10, at most 50)"}}},
            "outputSchema": {"type": "object", "additionalProperties": false,
                "properties": {"messages": {"type": "array", "items": message_schema()}}, "required": ["messages"]},
        },
        {
            "name": "send_sms",
            "title": "Send SMS",
            "description": "Send a text message (SMS) from the user's own phone number through the Bridge on this computer. The number and the text stay on this computer. The user may have to approve it first. Returns the delivery status; if it is still pending, use get_message_status later. Recipient must be in international E.164 format (e.g. +48501234567).",
            // destructiveHint: a sent text cannot be taken back, so clients should confirm before calling.
            "annotations": {"destructiveHint": true, "openWorldHint": true},
            "inputSchema": {"type": "object", "additionalProperties": false,
                "properties": {
                    "body": {"type": "string", "description": "The exact text to send"},
                    "device_id": {"type": "string", "description": "Ignored here: this endpoint always sends from this computer"},
                    "to": {"type": "string", "description": "Recipient phone number in E.164 format, e.g. +48501234567"}},
                "required": ["to", "body"]},
            "outputSchema": message_schema(),
        },
    ]})
}

/// The answer to initialize.
pub fn initialize_result(params: &Value) -> Value {
    let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
    let version = PROTOCOL_VERSIONS.iter().find(|v| **v == asked).copied().unwrap_or(DEFAULT_PROTOCOL);
    json!({
        "capabilities": {"logging": {}, "tools": {"listChanged": true}},
        "instructions": INSTRUCTIONS,
        "protocolVersion": version,
        "serverInfo": {"name": "pocketwire", "title": "Pocketwire", "version": crate::net::version()},
    })
}

/// The client's title or name from initialize params.
pub fn client_name_of(params: &Value) -> String {
    let ci = params.get("clientInfo");
    let get = |k: &str| ci.and_then(|c| c.get(k)).and_then(Value::as_str).unwrap_or("").to_string();
    let t = get("title");
    if t.is_empty() {
        get("name")
    } else {
        t
    }
}

pub fn rpc_result(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub fn rpc_error(id: &Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

pub const INVALID_PARAMS: i64 = -32602;

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Checks tool arguments against the tool's input schema (flat objects of strings and integers).
pub fn validate_args(tool: &str, args: &Value) -> Result<Map<String, Value>, (i64, String)> {
    let list = tools();
    let Some(t) = list["tools"].as_array().and_then(|a| a.iter().find(|t| t["name"] == tool)) else {
        return Err((INVALID_PARAMS, format!("unknown tool {}", quote(tool))));
    };
    let schema = &t["inputSchema"];
    let obj = match args {
        Value::Null => Map::new(),
        Value::Object(o) => o.clone(),
        v => {
            return Err((
                INVALID_PARAMS,
                format!("invalid params: validating \"arguments\": validating root: type: {v} has type {}, want \"object\"", quote(type_name(v))),
            ))
        }
    };
    let props = schema["properties"].as_object().cloned().unwrap_or_default();
    let missing: Vec<&str> =
        schema["required"].as_array().map(|r| r.iter().filter_map(Value::as_str).filter(|k| !obj.contains_key(*k)).collect()).unwrap_or_default();
    if !missing.is_empty() {
        return Err((INVALID_PARAMS, format!("invalid params: validating \"arguments\": validating root: required: missing properties: {}", json!(missing))));
    }
    for (k, v) in &obj {
        let Some(p) = props.get(k) else {
            return Err((
                INVALID_PARAMS,
                format!("invalid params: validating \"arguments\": validating root: unexpected additional properties [{}]", quote(k)),
            ));
        };
        let want = p["type"].as_str().unwrap_or("");
        let ok = match want {
            "integer" => v.is_i64() || v.is_u64() || v.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false),
            w => type_name(v) == w,
        };
        if !ok {
            return Err((
                INVALID_PARAMS,
                format!(
                    "invalid params: validating \"arguments\": validating root: validating /properties/{k}: type: {v} has type {}, want {}",
                    quote(type_name(v)),
                    quote(want)
                ),
            ));
        }
    }
    Ok(obj)
}

/// A bearer token's grant, for calls that came through the relay (None for local calls).
#[derive(Clone, Debug)]
pub struct TokenInfo {
    pub scopes: Vec<String>,
    pub client_name: String,
}

struct Session {
    client: String,
    used: Instant,
}

pub struct Mcp {
    pub engine: Arc<Engine>,
    pub device_id: String,
    pub name: String,
    pub platform: String,
    /// How long send_sms waits for a final status (25 s).
    pub wait_for: Duration,
    sessions: Mutex<HashMap<String, Session>>,
}

fn tool_text(text: &str, structured: Option<Value>, is_error: bool) -> Value {
    let mut r = json!({"content": [{"type": "text", "text": text}]});
    if let Some(s) = structured {
        r["structuredContent"] = s;
    }
    if is_error {
        r["isError"] = json!(true);
    }
    r
}

impl Mcp {
    pub fn new(engine: Arc<Engine>, device_id: &str, name: &str, platform: &str) -> Arc<Mcp> {
        Arc::new(Mcp {
            engine,
            device_id: device_id.into(),
            name: name.into(),
            platform: platform.into(),
            wait_for: Duration::from_secs(25),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// Serves POST/GET/DELETE /mcp after authentication.
    pub async fn http(&self, r: &Req, token: Option<TokenInfo>) -> Resp {
        let sid = r.header("mcp-session-id").to_string();
        match r.method.as_str() {
            "GET" => return Resp::error(405, "method not allowed").with("allow", "POST, DELETE"),
            "DELETE" => {
                if sid.is_empty() {
                    return Resp::error(400, "Bad Request: missing session ID");
                }
                let gone = self.sessions.lock().unwrap().remove(&sid).is_some();
                return if gone { Resp::new(204) } else { Resp::error(404, "session not found") };
            }
            "POST" => {}
            _ => return Resp::error(405, "method not allowed").with("allow", "POST, DELETE"),
        }
        let msg: Value = match serde_json::from_slice(&r.body) {
            Ok(v) => v,
            Err(e) => return Resp::json(400, &rpc_error(&Value::Null, -32700, &format!("parse error: {e}"))),
        };
        let is_init = msg.get("method").and_then(Value::as_str) == Some("initialize");
        let mut new_sid = None;
        let client = if is_init {
            let id = util::random_hex(16).to_uppercase();
            let client = client_name_of(&msg["params"]);
            let mut s = self.sessions.lock().unwrap();
            let now = Instant::now();
            s.retain(|_, v| now.duration_since(v.used) < SESSION_TIMEOUT);
            s.insert(id.clone(), Session { client: client.clone(), used: now });
            new_sid = Some(id);
            client
        } else if sid.is_empty() {
            return Resp::error(400, "Bad Request: missing session ID");
        } else {
            let mut s = self.sessions.lock().unwrap();
            match s.get_mut(&sid) {
                Some(v) if v.used.elapsed() < SESSION_TIMEOUT => {
                    v.used = Instant::now();
                    v.client.clone()
                }
                _ => {
                    s.remove(&sid);
                    return Resp::error(404, "session not found");
                }
            }
        };
        let header_client = r.header(CLIENT_HEADER).trim().to_string();
        let answer = match &msg {
            Value::Array(list) => {
                let mut out = Vec::new();
                for m in list {
                    if let Some(a) = self.message(m, token.as_ref(), &header_client, &client).await {
                        out.push(a);
                    }
                }
                if out.is_empty() {
                    None
                } else {
                    Some(Value::Array(out))
                }
            }
            m => self.message(m, token.as_ref(), &header_client, &client).await,
        };
        let resp = match answer {
            None => Resp::new(202),
            Some(a) => Resp::json(200, &a),
        };
        match new_sid {
            Some(id) => resp.with("mcp-session-id", id),
            None => resp,
        }
    }

    /// Answers one JSON-RPC message; None for notifications and responses.
    pub async fn message(&self, m: &Value, token: Option<&TokenInfo>, header_client: &str, session_client: &str) -> Option<Value> {
        let id = m.get("id")?.clone();
        let method = m.get("method").and_then(Value::as_str)?;
        let params = m.get("params").cloned().unwrap_or(Value::Null);
        Some(match method {
            "initialize" => rpc_result(&id, initialize_result(&params)),
            "ping" | "logging/setLevel" => rpc_result(&id, json!({})),
            "tools/list" => rpc_result(&id, tools()),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                match validate_args(name, params.get("arguments").unwrap_or(&Value::Null)) {
                    Err((code, msg)) => rpc_error(&id, code, &msg),
                    Ok(args) => {
                        let client = token
                            .map(|t| t.client_name.clone())
                            .filter(|n| !n.is_empty())
                            .or_else(|| Some(header_client.to_string()).filter(|n| !n.is_empty()))
                            .unwrap_or_else(|| session_client.to_string());
                        rpc_result(&id, self.call(name, &args, token, &client).await)
                    }
                }
            }
            _ => rpc_error(&id, -32601, "method not found"),
        })
    }

    fn need(token: Option<&TokenInfo>, scope: &str) -> Result<(), String> {
        match token {
            Some(t) if !t.scopes.iter().any(|s| s == scope) => Err(format!("This connection was not granted \"{scope}\". Reconnect Pocketwire and allow it.")),
            _ => Ok(()),
        }
    }

    async fn call(&self, name: &str, args: &Map<String, Value>, token: Option<&TokenInfo>, client: &str) -> Value {
        match self.call_inner(name, args, token, client).await {
            Ok(v) => v,
            Err(e) => tool_text(&e, None, true),
        }
    }

    async fn call_inner(&self, name: &str, args: &Map<String, Value>, token: Option<&TokenInfo>, client: &str) -> Result<Value, String> {
        let s = |k: &str| args.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        match name {
            "list_devices" => {
                Self::need(token, "devices:read")?;
                let online = self.engine.up.connected();
                let state = if online { "online" } else { "offline" };
                let text = format!("• {} ({}, {state}) — {}", self.name, self.platform, self.device_id);
                let d = json!({"devices": [{"device_id": self.device_id, "name": self.name, "kind": "bridge", "platform": self.platform, "online": online, "can_send_sms": true}]});
                Ok(tool_text(&text, Some(d), false))
            }
            "send_sms" => {
                Self::need(token, "sms:send")?;
                let mut m = self.engine.send(&s("to"), &s("body"), client).await?;
                if m.status != "awaiting_approval" {
                    if let Some(w) = self.engine.wait(&m.id, self.wait_for).await {
                        m = w;
                    }
                }
                let o = out(&m, &self.device_id);
                let err = o.status == "failed" || o.status == "expired";
                Ok(tool_text(&describe(&o), Some(serde_json::to_value(&o).unwrap()), err))
            }
            "get_message_status" => {
                if Self::need(token, "messages:read").is_err() {
                    Self::need(token, "sms:send")?;
                }
                let m = self.engine.store.get(&s("message_id")).ok_or(NOT_FOUND)?;
                let o = out(&m, &self.device_id);
                Ok(tool_text(&format!("{}: {}", o.status, describe(&o)), Some(serde_json::to_value(&o).unwrap()), false))
            }
            "list_recent_messages" => {
                Self::need(token, "messages:read")?;
                let limit = args.get("limit").and_then(Value::as_f64).unwrap_or(0.0) as i64;
                let limit = if limit <= 0 { 10 } else { limit.min(50) } as usize;
                let list: Vec<MessageOut> = self.engine.store.recent(limit).iter().map(|m| out(m, &self.device_id)).collect();
                let mut lines: Vec<String> = list
                    .iter()
                    .map(|m| {
                        let mut l = format!("• {} → {}: {}", m.created_at, m.to, m.status);
                        if !m.client_name.is_empty() {
                            l.push_str(&format!(" (via {})", m.client_name));
                        }
                        l
                    })
                    .collect();
                if lines.is_empty() {
                    lines.push("No messages yet.".into());
                }
                Ok(tool_text(&lines.join("\n"), Some(json!({"messages": list})), false))
            }
            _ => Err(format!("unknown tool {}", quote(name))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::tests::engine;

    async fn call(m: &Mcp, tool: &str, args: Value, token: Option<&TokenInfo>) -> Value {
        let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}});
        m.message(&msg, token, "", "Test app").await.unwrap()
    }

    #[tokio::test]
    async fn tools_match_go() {
        let (e, _) = engine("none");
        let m = Mcp::new(e, "d1", "n", "linux");
        let r = call(&m, "list_devices", json!({}), None).await;
        assert_eq!(
            r["result"],
            json!({"content":[{"type":"text","text":"• n (linux, online) — d1"}],"structuredContent":{"devices":[{"can_send_sms":true,"device_id":"d1","kind":"bridge","name":"n","online":true,"platform":"linux"}]}})
        );
        let r = call(&m, "list_recent_messages", json!({}), None).await;
        assert_eq!(r["result"], json!({"content":[{"type":"text","text":"No messages yet."}],"structuredContent":{"messages":[]}}));
        let r = call(&m, "get_message_status", json!({"message_id": "x"}), None).await;
        assert_eq!(r["result"], json!({"content":[{"type":"text","text":"no such message on this computer"}],"isError":true}));
        let r = call(&m, "send_sms", json!({"body": "x"}), None).await;
        assert_eq!(r["error"]["code"], json!(-32602));
        assert!(r["error"]["message"].as_str().unwrap().contains(r#"missing properties: ["to"]"#));
        let r = call(&m, "send_sms", json!({"to": 5, "body": "x"}), None).await;
        assert!(r["error"]["message"].as_str().unwrap().contains(r#"want "string""#));
        let r = call(&m, "nope", json!({}), None).await;
        assert_eq!(r["error"]["message"], json!(r#"unknown tool "nope""#));

        let r = call(&m, "send_sms", json!({"to": "+48 501 234 567", "body": "Hi"}), None).await;
        let sc = &r["result"]["structuredContent"];
        assert_eq!(sc["status"], json!("sent"));
        assert_eq!(sc["client_name"], json!("Test app"));
        assert_eq!(r["result"]["content"][0]["text"], json!("Sent to +48501234567."));

        let ro = TokenInfo { scopes: vec!["devices:read".into()], client_name: "Test app".into() };
        let r = call(&m, "send_sms", json!({"to": "+48501234567", "body": "Hi"}), Some(&ro)).await;
        assert_eq!(r["result"]["isError"], json!(true));
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("sms:send"));
    }

    #[test]
    fn describes_like_go() {
        let mut o = out(&Message { id: "m1".into(), to: "+1".into(), status: "awaiting_approval".into(), ..Default::default() }, "d");
        assert_eq!(describe(&o), "Waiting for approval on the user's computer: Pocketwire opened an approval page in the browser. Ask the user to click Send there. Check later with get_message_status(\"m1\").");
        o.status = "failed".into();
        o.error = "x".into();
        assert_eq!(describe(&o), "Sending failed: x.");
        assert_eq!(initialize_result(&json!({"protocolVersion": "1999"}))["protocolVersion"], json!(DEFAULT_PROTOCOL));
    }
}
