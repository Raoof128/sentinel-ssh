//! Protocol transcripts against the real binary over stdio. No SSH is dispatched: every call here is answered before the
//! backend (inventory, capabilities, validation, policy), so the real OpenSSH backend serves them without a network.

use std::process::Stdio;
use std::time::Duration;

use sentinel_gateway::mcp::server::tool_schemas;
use sentinel_gateway::tools::TOOL_NAMES;
use sentinel_testkit::configs::{TestDirs, load_minimal};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

struct Server {
    _dirs: TestDirs,
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

fn spawn_server() -> Server {
    let dirs = TestDirs::new();
    let (_cfg, _) = load_minimal(&dirs);
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel-ssh"))
        .args(["serve", "--config"])
        .arg(dirs.state.path().join("config.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn sentinel-ssh");
    let stdin = child.stdin.take().unwrap();
    let lines = BufReader::new(child.stdout.take().unwrap()).lines();
    Server {
        _dirs: dirs,
        child,
        stdin,
        lines,
        next_id: 1,
    }
}

impl Server {
    async fn send(&mut self, v: Value) {
        let mut line = serde_json::to_vec(&v).unwrap();
        line.push(b'\n');
        self.stdin.write_all(&line).await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        loop {
            let line = tokio::time::timeout(Duration::from_secs(10), self.lines.next_line())
                .await
                .expect("server answered in time")
                .unwrap()
                .expect("server stdout open");
            let v: Value = serde_json::from_str(&line).unwrap_or_else(|e| panic!("non-JSON on stdout ({e}): {line}"));
            if v["id"] == id {
                return v;
            }
        }
    }

    async fn initialize(&mut self, version: &str) -> Value {
        let r = self
            .rpc(
                "initialize",
                json!({"protocolVersion": version, "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
            )
            .await;
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
        r
    }

    /// 2026-07-28 requests are self-contained: version and client capabilities ride in `_meta` (SEP-2567).
    async fn rpc_modern(&mut self, method: &str, mut params: Value) -> Value {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "0"}
        });
        self.rpc(method, params).await
    }

    async fn call(&mut self, name: &str, args: Value) -> Value {
        self.rpc("tools/call", json!({"name": name, "arguments": args})).await
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

#[tokio::test]
async fn modern_discover_and_catalogue() {
    let mut s = spawn_server();
    let d = s.rpc_modern("server/discover", json!({})).await;
    assert_eq!(d["result"]["supportedVersions"], json!(["2026-07-28", "2025-11-25"]), "{d}");
    assert!(
        d["result"]["instructions"].as_str().unwrap().contains("not a remote sandbox"),
        "{d}"
    );
    assert_eq!(
        d["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "sentinel-ssh",
        "{d}"
    );
    let tools = s.rpc_modern("tools/list", json!({})).await;
    let list = tools["result"]["tools"].as_array().unwrap_or_else(|| panic!("{tools}"));
    let names: Vec<&str> = list.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, TOOL_NAMES);
    assert_eq!(tools["result"]["cacheScope"], "private", "per-principal catalogue: {tools}");
    for t in list {
        assert!(t["inputSchema"].is_object(), "{t}");
        assert!(t["outputSchema"].is_object(), "{t}");
        assert!(t["description"].as_str().is_some_and(|d| !d.is_empty()), "{t}");
    }
    let r = s.rpc_modern("tools/call", json!({"name": "ssh_hosts_list", "arguments": {}})).await;
    assert_eq!(r["result"]["structuredContent"]["data"]["hosts"][0]["host_id"], "h1", "{r}");
}

/// A client that still sends `initialize` with 2026-07-28 is answered with the newest version that has an initialize
/// handshake (rmcp negotiation; 2026-07-28 removed the handshake).
#[tokio::test]
async fn initialize_with_modern_version_falls_back_to_legacy_lifecycle() {
    let mut s = spawn_server();
    let init = s.initialize("2026-07-28").await;
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
    assert_eq!(init["result"]["serverInfo"]["name"], "sentinel-ssh");
    assert!(init["result"]["instructions"].as_str().unwrap().contains("not a remote sandbox"));
}

#[tokio::test]
async fn legacy_initialize_negotiates_2025_11_25() {
    let mut s = spawn_server();
    let init = s.initialize("2025-11-25").await;
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
    let r = s.call("ssh_capabilities_get", json!({})).await;
    assert_eq!(r["result"]["structuredContent"]["schema_version"], "1", "{r}");
    assert!(
        r["result"]["content"][0]["text"].as_str().unwrap().contains("\"schema_version\""),
        "text fallback present: {r}"
    );
}

#[tokio::test]
async fn unknown_tool_and_bad_args_are_errors_not_crashes() {
    let mut s = spawn_server();
    s.initialize("2026-07-28").await;
    let r = s.call("ssh_exec", json!({"command": "id"})).await;
    assert!(r["error"].is_object(), "{r}");
    let r = s
        .call("ssh_file_read", json!({"host_id": "h1", "root": "app", "path": "x", "bogus": 1}))
        .await;
    assert!(r["error"].is_object() || r["result"]["isError"] == true, "{r}");
    let r = s
        .call("ssh_file_read", json!({"host_id": "h1", "root": "app", "path": "../etc/passwd"}))
        .await;
    assert!(
        r["error"].is_object(),
        "malformed path is a protocol-level invalid-params error: {r}"
    );
    let r = s.call("ssh_hosts_list", json!({})).await;
    assert_eq!(r["result"]["structuredContent"]["data"]["hosts"][0]["host_id"], "h1", "{r}");
}

#[tokio::test]
async fn policy_denial_surfaces_typed_error() {
    let mut s = spawn_server();
    s.initialize("2026-07-28").await;
    let r = s
        .call("ssh_transfer_download", json!({"host_id": "h1", "root": "logs", "path": "api.log"}))
        .await;
    assert!(r["error"].is_null(), "policy denial must be a result, not a protocol error: {r}");
    let sc = &r["result"]["structuredContent"];
    assert_eq!(sc["outcome"], "failed", "{r}");
    assert_eq!(sc["error"]["code"], "POLICY_DENIED");
    assert_eq!(sc["retry"]["strategy"], "never");
    assert!(sc["data"].is_null());
    assert!(sc["operation_id"].as_str().unwrap().starts_with("op_"));
}

#[tokio::test]
async fn output_schemas_are_typed() {
    let mut s = spawn_server();
    s.initialize("2026-07-28").await;
    let tools = s.rpc("tools/list", json!({})).await;
    let hosts = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "ssh_hosts_list")
        .unwrap()
        .clone();
    let text = hosts["outputSchema"].to_string();
    assert!(text.contains("\"hosts\""), "output schema names the data fields: {text}");
}

#[test]
fn tool_schema_snapshot() {
    let v = tool_schemas();
    assert_eq!(v.as_array().unwrap().len(), 17);
    insta::assert_json_snapshot!(v);
}
