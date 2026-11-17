//! Config fixtures shared by gateway tests.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// A syntactically valid ed25519 public key body (decodes as base64); not a real host key.
pub const TEST_HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample";

/// Per-test directories. The runtime dir lives under `/tmp` because macOS temp paths are too long for an SSH ControlPath socket.
pub struct TestDirs {
    pub state: tempfile::TempDir,
    pub run: tempfile::TempDir,
}

impl TestDirs {
    pub fn new() -> Self {
        crate::init_tracing();
        Self {
            state: tempfile::tempdir().expect("state tempdir"),
            run: tempfile::Builder::new()
                .prefix("snt")
                .tempdir_in("/tmp")
                .expect("short runtime tempdir"),
        }
    }
}

impl Default for TestDirs {
    fn default() -> Self {
        Self::new()
    }
}

/// Top-level settings: artefacts under `dirs.state`, SSH runtime files under `dirs.run`.
pub fn gateway_header(dirs: &TestDirs) -> String {
    format!(
        r#"schema_version = 1

[gateway]
artifact_dir = "{art}"
runtime_dir = "{run}"
ssh_binary = "/usr/bin/ssh"

[principal]
id = "raouf"
role = "observer"
"#,
        art = dirs.state.path().join("artifacts").display(),
        run = dirs.run.path().join("r").display(),
    )
}

/// One `[[hosts]]` block: roots app (read+export), logs (read only), secrets (no read); service api; log source api; health check api_http.
pub fn host_block(id: &str, address: &str, port: u16, user: &str, host_key: &str, identity: &Path) -> String {
    format!(
        r#"
[[hosts]]
id = "{id}"
environment = "staging"
address = "{address}"
port = {port}
user = "{user}"
host_key = "{host_key}"
auth = {{ method = "identity_file", path = "{identity}" }}

[hosts.roots.app]
path = "/srv/app"
read = true
export = true

[hosts.roots.logs]
path = "/srv/app/logs"
read = true
export = false

[hosts.roots.secrets]
path = "/srv/secrets"
read = false
export = false

[hosts.services.api]
unit = "app-api.service"
scope = "system"

[hosts.services.worker]
unit = "worker.service"
scope = "user"

[hosts.log_sources.api]
path = "/var/log/app/api.log"

[hosts.health_checks.api_http]
kind = "http"
url = "http://127.0.0.1:8080/health"
expect_status = 200
timeout_secs = 5

[hosts.health_checks.api_active]
kind = "service_active"
service = "api"

[hosts.health_checks.api_query]
kind = "http"
url = "http://127.0.0.1:8080/health?sig=synthetic-query-value#frag"
expect_status = 200
timeout_secs = 5
"#,
        identity = identity.display(),
    )
}

/// Minimal valid config: header plus host `h1` at 203.0.113.10:22 (TEST-NET-3, never routable).
pub fn minimal_config_toml(host_key: &str, identity: &Path, dirs: &TestDirs) -> String {
    gateway_header(dirs) + &host_block("h1", "203.0.113.10", 22, "sentinel-observer", host_key, identity)
}

/// Writes `contents` to `path` with mode 0600.
pub fn write_private(path: &Path, contents: &str) {
    let _ = fs::remove_file(path);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create private file");
    f.write_all(contents.as_bytes()).expect("write private file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
}

/// A fake identity file (mode 0600) in `dir`; contents are irrelevant to config validation.
pub fn fake_identity(dir: &Path) -> std::path::PathBuf {
    let p = dir.join("id_test");
    write_private(&p, "not a real key\n");
    p
}

/// Loads the minimal config through the real loader. Returns the config and the identity path.
pub fn load_minimal(dirs: &TestDirs) -> (sentinel_gateway::config::Config, std::path::PathBuf) {
    let identity = fake_identity(dirs.state.path());
    let path = dirs.state.path().join("config.toml");
    write_private(&path, &minimal_config_toml(TEST_HOST_KEY, &identity, dirs));
    (
        sentinel_gateway::config::load_config(&path).expect("minimal config loads"),
        identity,
    )
}

/// Writes `content` to `path` as an executable file (mode 0700) that can be executed the moment this returns.
///
/// The file is written by a child process, never by this one. On Linux, `execve` fails with ETXTBSY ("Text file busy")
/// while any process holds the file open for writing. Tests run on many threads, and a `fork` on another thread
/// copies every open descriptor into its child until that child reaches `exec`; if this process opened the script
/// for writing, such a child could still hold it after the write here had finished and closed, and the exec that
/// follows would fail at random. Close-on-exec does not help: the window is between `fork` and `exec`. A descriptor
/// this process never opened cannot be copied by its forks, and the writer has exited (so the kernel has closed its
/// descriptors) before this returns.
pub fn write_executable(path: &Path, content: &str) {
    use std::process::{Command, Stdio};
    let mut writer = Command::new("/bin/sh")
        .arg("-c")
        .arg("umask 077 && cat > \"$1\" && chmod 700 \"$1\"")
        .arg("write-executable")
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("start the script writer");
    writer
        .stdin
        .take()
        .expect("script writer stdin")
        .write_all(content.as_bytes())
        .expect("send the script to the writer");
    // Taking stdin above dropped it, so `cat` has seen end of input.
    let status = writer.wait().expect("wait for the script writer");
    assert!(status.success(), "script writer failed for {}: {status}", path.display());
}

/// Writes an executable shell script (mode 0700) used as a stand-in `ssh_binary`. `ssh -G` (effective-config query)
/// is passed through to the real `/usr/bin/ssh` so the backend's configuration check still runs against real OpenSSH.
pub fn fake_ssh_script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    let passthrough = "case \" $* \" in *\" -G \"*) exec /usr/bin/ssh \"$@\";; esac";
    write_executable(&p, &format!("#!/bin/sh\n{passthrough}\n{body}\n"));
    p
}

/// As [`fake_ssh_script`] without the `ssh -G` passthrough: the script answers every invocation itself.
pub fn raw_ssh_script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    write_executable(&p, &format!("#!/bin/sh\n{body}\n"));
    p
}
