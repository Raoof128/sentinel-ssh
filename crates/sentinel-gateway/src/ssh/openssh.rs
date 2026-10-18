//! Native OpenSSH backend (spec §1, §5.3, §9.2): spawns the installed client with a fully controlled argument vector,
//! a generated per-host known_hosts file and a cleared environment.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::identity::HostId;
use sentinel_core::operation::RemoteTermination;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{AuthConfig, GatewaySettings, HostConfig, check_private_file, check_trusted_executable, ensure_private_dir};
use crate::ssh::backend::{BackendCapabilities, ExitKind, RunBudget, RunOutcome, SshBackend, StreamBudget, StreamOutcome};
use crate::ssh::command::RemoteCommand;

/// How long to keep reading after the client exits. A ControlPersist master can inherit and hold the stderr pipe open.
const DRAIN_GRACE: Duration = Duration::from_millis(250);
const STDERR_CAP: usize = 16 * 1024;

/// Digest of everything a connection's trust rests on: host id, address, port, user, pinned key and credential. For an
/// identity file that includes the file's content, so a key rotated at the same path never reuses a master
/// authenticated with the old one (red team M3).
pub fn trust_digest(host: &HostConfig) -> String {
    use sha2::{Digest, Sha256};
    let cred = match &host.auth {
        AuthConfig::IdentityFile { path } => {
            let content = std::fs::read(path).map(|b| hex::encode(Sha256::digest(b))).unwrap_or_default();
            format!("identity_file:{}:{content}", path.display())
        }
        AuthConfig::Agent { public_key } => {
            let pinned = public_key
                .as_ref()
                .map(|p| std::fs::read(p).map(|b| hex::encode(Sha256::digest(b))).unwrap_or_default());
            format!("agent:{}", pinned.unwrap_or_default())
        }
    };
    let material = [
        host.id.as_str(),
        &host.address,
        &host.port.to_string(),
        &host.user,
        &host.host_key.to_string(),
        &cred,
    ]
    .join("\0");
    hex::encode(Sha256::digest(material.as_bytes()))
}

#[derive(Debug)]
pub struct OpenSshBackend {
    ssh_binary: PathBuf,
    runtime_dir: PathBuf,
    /// (device, inode) of the runtime directory at start; re-checked before every spawn.
    runtime_identity: (u64, u64),
    /// Reuse connections through a ControlMaster. Off for `doctor`, which must prove the pin on a fresh handshake.
    multiplex: bool,
    connect_timeout_secs: u64,
    verified_hosts: Mutex<BTreeSet<HostId>>,
}

impl HostConfig {
    /// The identity file path for `IdentityFile` auth.
    pub fn auth_identity(&self) -> Option<&Path> {
        match &self.auth {
            AuthConfig::IdentityFile { path } => Some(path),
            AuthConfig::Agent { .. } => None,
        }
    }
}

fn exit_kind(s: ExitStatus) -> ExitKind {
    use std::os::unix::process::ExitStatusExt;
    // On Unix a finished child has either an exit code or a terminating signal.
    s.code().map_or_else(|| ExitKind::Signal(s.signal().unwrap_or(0)), ExitKind::Code)
}

type Shared = Arc<Mutex<(Vec<u8>, bool)>>;

/// Reads to EOF, keeping at most `cap` bytes and discarding the rest so the child never blocks on a full pipe.
fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(mut r: R, cap: usize) -> (Shared, JoinHandle<()>) {
    let buf: Shared = Arc::new(Mutex::new((Vec::new(), false)));
    let b2 = buf.clone();
    let task = tokio::spawn(async move {
        let mut chunk = vec![0u8; 8192];
        loop {
            match r.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut g = b2.lock().expect("reader buffer");
                    let room = cap.saturating_sub(g.0.len());
                    let take = room.min(n);
                    g.0.extend_from_slice(&chunk[..take]);
                    if take < n {
                        g.1 = true;
                    }
                }
            }
        }
    });
    (buf, task)
}

fn take(buf: &Shared) -> (Vec<u8>, bool) {
    std::mem::take(&mut *buf.lock().expect("reader buffer"))
}

async fn drain(tasks: Vec<JoinHandle<()>>) {
    let aborts: Vec<_> = tasks.iter().map(|t| t.abort_handle()).collect();
    let _ = tokio::time::timeout(DRAIN_GRACE, async {
        for t in tasks {
            let _ = t.await;
        }
    })
    .await;
    for a in aborts {
        a.abort();
    }
}

/// Kills the client's whole process group, then reaps it. The remote command is not confirmed stopped.
async fn kill(child: &mut Child) {
    if let Some(pid) = child.id().and_then(|p| rustix::process::Pid::from_raw(p as i32)) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
}

fn stopped(timeout: bool, what: &str) -> SentinelError {
    let e = if timeout {
        SentinelError::new(ErrorCode::Timeout, format!("{what} exceeded its time budget"))
    } else {
        SentinelError::new(ErrorCode::Timeout, "cancelled").with_detail("cancelled", true)
    };
    e.with_detail("remote_termination", "unconfirmed")
}

impl OpenSshBackend {
    pub fn new(settings: &GatewaySettings) -> Result<Self> {
        ensure_private_dir(&settings.runtime_dir)?;
        // Run the resolved file that was checked, not a path that could be re-pointed afterwards.
        let ssh_binary = check_trusted_executable(&settings.ssh_binary)?;
        let meta = std::fs::metadata(&settings.runtime_dir).map_err(|e| SentinelError::new(ErrorCode::ConfigInvalid, e.to_string()))?;
        Ok(Self {
            runtime_identity: (meta.dev(), meta.ino()),
            multiplex: true,
            ssh_binary,
            runtime_dir: settings.runtime_dir.clone(),
            connect_timeout_secs: settings.budgets.connect_timeout_secs,
            verified_hosts: Mutex::new(BTreeSet::new()),
        })
    }

    /// A backend that never uses a ControlMaster: every call is a full handshake against the pinned key (red team L2).
    pub fn unmultiplexed(settings: &GatewaySettings) -> Result<Self> {
        Ok(Self {
            multiplex: false,
            ..Self::new(settings)?
        })
    }

    /// Keyed by the trust identity, never the host id alone: two configs pinning different keys for the same id must
    /// not overwrite each other's file (red team H1).
    pub fn known_hosts_path(&self, host: &HostConfig) -> PathBuf {
        self.runtime_dir.join(format!("kh-{}", &trust_digest(host)[..20]))
    }

    fn known_hosts_line(host: &HostConfig) -> String {
        format!("{} {}\n", host.id, host.host_key)
    }

    /// Rewrites the pinned key file if anything changed it since the last spawn.
    fn ensure_known_hosts(&self, host: &HostConfig) -> Result<()> {
        let current = std::fs::read_to_string(self.known_hosts_path(host)).unwrap_or_default();
        if current != Self::known_hosts_line(host) {
            self.write_known_hosts(host)?;
        }
        Ok(())
    }

    /// `<host_id> <type> <base64>`; the argv sets `HostKeyAlias=<host_id>` so the address never needs to match.
    pub fn write_known_hosts(&self, host: &HostConfig) -> Result<PathBuf> {
        let p = self.known_hosts_path(host);
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = self.runtime_dir.join(format!(".kh-{}.{}.{n}", host.id, std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let io = |e: std::io::Error| SentinelError::new(ErrorCode::Internal, format!("cannot write known_hosts: {e}"));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io)?;
        f.write_all(Self::known_hosts_line(host).as_bytes()).map_err(io)?;
        std::fs::rename(&tmp, &p).map_err(io)?;
        Ok(p)
    }

    /// One multiplexing socket per trust identity (spec §9.2): see [`trust_digest`].
    pub fn control_path(&self, host: &HostConfig) -> PathBuf {
        self.runtime_dir.join(format!("c-{}", &trust_digest(host)[..20]))
    }

    fn options(&self, host: &HostConfig) -> Vec<OsString> {
        let kh = self.known_hosts_path(host);
        let mut o: Vec<OsString> = vec!["-F".into(), "/dev/null".into()];
        let mut opt = |s: String| {
            o.push("-o".into());
            o.push(s.into());
        };
        opt("BatchMode=yes".into());
        opt("StrictHostKeyChecking=yes".into());
        opt(format!("UserKnownHostsFile={}", kh.display()));
        opt("GlobalKnownHostsFile=/dev/null".into());
        opt(format!("HostKeyAlias={}", host.id));
        opt("CheckHostIP=no".into());
        opt("UpdateHostKeys=no".into());
        opt(format!("ConnectTimeout={}", self.connect_timeout_secs));
        opt("ServerAliveInterval=15".into());
        opt("ServerAliveCountMax=2".into());
        opt("ClearAllForwardings=yes".into());
        opt("ForwardAgent=no".into());
        opt("ForwardX11=no".into());
        opt("PermitLocalCommand=no".into());
        opt("ProxyCommand=none".into());
        opt("RequestTTY=no".into());
        if self.multiplex {
            opt("ControlMaster=auto".into());
            opt(format!("ControlPath={}", self.control_path(host).display()));
            opt("ControlPersist=60".into());
        } else {
            opt("ControlMaster=no".into());
        }
        opt("LogLevel=ERROR".into());
        match &host.auth {
            AuthConfig::IdentityFile { path } => {
                opt("IdentitiesOnly=yes".into());
                opt("IdentityAgent=none".into());
                o.push("-i".into());
                o.push(path.into());
            }
            // Agent keys only: without this OpenSSH also tries ~/.ssh/id_* from the passwd home (spec §4.4).
            AuthConfig::Agent { public_key: Some(p) } => {
                // Offer only this agent key (red team L3).
                opt("IdentitiesOnly=yes".into());
                opt(format!("IdentityFile={}", p.display()));
            }
            AuthConfig::Agent { public_key: None } => opt("IdentityFile=none".into()),
        }
        o.push("-p".into());
        o.push(host.port.to_string().into());
        o.push("-l".into());
        o.push(host.user.clone().into());
        o
    }

    /// `limit` also bounds the command on the host: `timeout` kills its whole process group there, so a call blocked on
    /// the host (a FIFO, a stalled read) cannot outlive its budget after the client gives up.
    pub fn build_argv(&self, host: &HostConfig, cmd: &RemoteCommand, limit: Duration) -> Vec<OsString> {
        let mut a = self.options(host);
        a.push("--".into());
        a.push(host.address.clone().into());
        // GNU stat %F and every error message we classify are translated under other locales.
        let secs = limit.as_secs() + u64::from(limit.subsec_nanos() > 0);
        a.push(
            format!(
                "LC_ALL=C; export LC_ALL; exec timeout -k 5 {secs} sh -c {}",
                sentinel_core::scope::shell_quote(&cmd.render())
            )
            .into(),
        );
        a
    }

    fn base_command(&self, args: Vec<OsString>, host: &HostConfig) -> Command {
        let mut c = Command::new(&self.ssh_binary);
        c.args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.runtime_dir)
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        if matches!(host.auth, AuthConfig::Agent { .. })
            && let Some(sock) = std::env::var_os("SSH_AUTH_SOCK")
        {
            c.env("SSH_AUTH_SOCK", sock);
        }
        c
    }

    /// `ssh -G`: the configuration the client would actually use, after the system config and our options.
    pub fn effective_config(&self, host: &HostConfig) -> Result<BTreeMap<String, Vec<String>>> {
        self.write_known_hosts(host)?;
        let mut args = self.options(host);
        args.push("-G".into());
        args.push(host.address.clone().into());
        let out = std::process::Command::new(&self.ssh_binary)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.runtime_dir)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| SentinelError::new(ErrorCode::ConfigInvalid, format!("cannot run {}: {e}", self.ssh_binary.display())))?;
        if !out.status.success() {
            return Err(SentinelError::new(
                ErrorCode::ConfigInvalid,
                format!("ssh -G failed: {}", String::from_utf8_lossy(&out.stderr).trim()),
            ));
        }
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some((k, v)) = line.split_once(' ') {
                m.entry(k.to_owned()).or_default().push(v.to_owned());
            }
        }
        Ok(m)
    }

    /// Refuses to dispatch if the effective client configuration weakens host trust, forwards anything, runs a proxy or
    /// local command, or would offer identities other than the configured one.
    pub fn check_effective_config(&self, host: &HostConfig) -> Result<()> {
        let eff = self.effective_config(host)?;
        let get = |k: &str| eff.get(k).map(|v| v.join(",")).unwrap_or_default();
        let mut bad = Vec::new();
        let expect = [
            ("stricthostkeychecking", "true"),
            ("globalknownhostsfile", "/dev/null"),
            ("forwardagent", "no"),
            ("clearallforwardings", "yes"),
            ("permitlocalcommand", "no"),
            ("batchmode", "yes"),
        ];
        for (k, v) in expect {
            if get(k) != v {
                bad.push(format!("{k}={} (expected {v})", get(k)));
            }
        }
        if get("userknownhostsfile") != self.known_hosts_path(host).display().to_string() {
            bad.push(format!("userknownhostsfile={}", get("userknownhostsfile")));
        }
        for k in [
            "proxycommand",
            "proxyjump",
            "localcommand",
            "remoteforward",
            "localforward",
            "dynamicforward",
        ] {
            let v = get(k);
            if !v.is_empty() && v != "none" {
                bad.push(format!("{k}={v}"));
            }
        }
        let ids = eff.get("identityfile").cloned().unwrap_or_default();
        match host.auth_identity() {
            Some(id) => {
                if ids != [id.display().to_string()] || get("identitiesonly") != "yes" {
                    bad.push(format!("identityfile={} (expected only {})", ids.join(","), id.display()));
                }
            }
            None if matches!(&host.auth, AuthConfig::Agent { public_key: Some(_) }) => {
                let AuthConfig::Agent { public_key: Some(p) } = &host.auth else {
                    unreachable!()
                };
                if ids != [p.display().to_string()] || get("identitiesonly") != "yes" {
                    bad.push(format!(
                        "identityfile={} (expected only the agent key {})",
                        ids.join(","),
                        p.display()
                    ));
                }
            }
            None => {
                if !ids.iter().all(|x| x == "none") {
                    bad.push(format!("identityfile={} (agent auth must not offer on-disk keys)", ids.join(",")));
                }
            }
        }
        if bad.is_empty() {
            Ok(())
        } else {
            Err(SentinelError::new(
                ErrorCode::ConfigInvalid,
                format!("effective SSH configuration for host '{}' is unsafe: {}", host.id, bad.join("; ")),
            ))
        }
    }

    /// Checks done before every spawn. A missing identity file would make OpenSSH fall back to ~/.ssh default keys.
    /// The first call for a host writes its known_hosts and verifies the effective config while holding the lock, so
    /// concurrent first calls neither race on the file nor skip the check.
    fn preflight(&self, host: &HostConfig) -> Result<()> {
        // Red team M1: a runtime dir renamed and recreated after start could hold a planted known_hosts file or mux socket.
        let still_ours = std::fs::symlink_metadata(&self.runtime_dir)
            .is_ok_and(|m| m.is_dir() && (m.dev(), m.ino()) == self.runtime_identity && m.mode() & 0o077 == 0);
        if !still_ours {
            return Err(SentinelError::new(
                ErrorCode::ConfigInvalid,
                "the runtime directory changed since the gateway started; restart the gateway",
            ));
        }
        if let Some(id) = host.auth_identity() {
            check_private_file(id, "identity file")?;
        }
        let mut verified = self.verified_hosts.lock().expect("verified hosts");
        if !verified.contains(&host.id) {
            self.check_effective_config(host)?;
            verified.insert(host.id.clone());
        }
        self.ensure_known_hosts(host)
    }

    fn spawn(&self, host: &HostConfig, cmd: &RemoteCommand, limit: Duration) -> Result<Child> {
        self.preflight(host)?;
        tracing::debug!(host = %host.id, cmd = %cmd.render(), "ssh dispatch");
        self.base_command(self.build_argv(host, cmd, limit), host)
            .spawn()
            .map_err(|e| SentinelError::new(ErrorCode::ConnectionFailed, format!("cannot start ssh client: {e}")))
    }
}

#[async_trait]
impl SshBackend for OpenSshBackend {
    async fn run(&self, host: &HostConfig, cmd: &RemoteCommand, budget: &RunBudget, cancel: CancellationToken) -> Result<RunOutcome> {
        let start = Instant::now();
        let mut child = self.spawn(host, cmd, budget.timeout)?;
        let (out, t1) = spawn_reader(child.stdout.take().expect("piped stdout"), budget.max_stdout_bytes);
        let (err, t2) = spawn_reader(child.stderr.take().expect("piped stderr"), budget.max_stderr_bytes);
        let waited = tokio::select! {
            s = child.wait() => Ok(s),
            _ = tokio::time::sleep(budget.timeout) => Err(true),
            _ = cancel.cancelled() => Err(false),
        };
        match waited {
            Ok(status) => {
                let status = status?;
                drain(vec![t1, t2]).await;
                let (stdout, stdout_truncated) = take(&out);
                let (stderr, stderr_truncated) = take(&err);
                Ok(RunOutcome {
                    exit: exit_kind(status),
                    stdout,
                    stdout_truncated,
                    stderr,
                    stderr_truncated,
                    duration: start.elapsed(),
                })
            }
            Err(timeout) => {
                kill(&mut child).await;
                t1.abort();
                t2.abort();
                Err(stopped(timeout, "remote command"))
            }
        }
    }

    async fn stream_stdout(
        &self,
        host: &HostConfig,
        cmd: &RemoteCommand,
        budget: &StreamBudget,
        cancel: CancellationToken,
        sink: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<StreamOutcome> {
        let start = Instant::now();
        let mut child = self.spawn(host, cmd, budget.total_timeout)?;
        let mut stdout = child.stdout.take().expect("piped stdout");
        let (err, t2) = spawn_reader(child.stderr.take().expect("piped stderr"), STDERR_CAP);
        let total = tokio::time::sleep(budget.total_timeout);
        tokio::pin!(total);
        let mut bytes = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        let copied: Result<()> = loop {
            tokio::select! {
                r = tokio::time::timeout(budget.idle_timeout, stdout.read(&mut buf)) => match r {
                    Err(_) => break Err(SentinelError::new(ErrorCode::TransferTimeoutIdle, "no data received within the idle timeout")),
                    Ok(Err(e)) => break Err(SentinelError::new(ErrorCode::RemoteFailure, format!("reading transfer stream: {e}"))),
                    Ok(Ok(0)) => break Ok(()),
                    Ok(Ok(n)) => {
                        bytes += n as u64;
                        if bytes > budget.max_bytes {
                            break Err(SentinelError::new(ErrorCode::BudgetExceeded, format!("stream exceeded {} bytes", budget.max_bytes)));
                        }
                        if let Err(e) = sink.write_all(&buf[..n]).await {
                            let code = if e.kind() == std::io::ErrorKind::StorageFull { ErrorCode::DiskFull } else { ErrorCode::Internal };
                            break Err(SentinelError::new(code, format!("writing transfer data: {e}")));
                        }
                    }
                },
                _ = &mut total => break Err(SentinelError::new(ErrorCode::TransferTimeoutTotal, "transfer exceeded its total time budget")),
                _ = cancel.cancelled() => break Err(stopped(false, "transfer")),
            }
        };
        if let Err(e) = copied {
            kill(&mut child).await;
            t2.abort();
            return Err(e.with_detail("bytes_received", bytes));
        }
        let status = match tokio::time::timeout(budget.idle_timeout, child.wait()).await {
            Ok(Ok(s)) => s,
            _ => {
                kill(&mut child).await;
                t2.abort();
                return Err(SentinelError::new(
                    ErrorCode::TransferTimeoutIdle,
                    "ssh did not exit after end of stream",
                ));
            }
        };
        drain(vec![t2]).await;
        let _ = sink.flush().await;
        Ok(StreamOutcome {
            exit: exit_kind(status),
            bytes,
            stderr: take(&err).0,
            duration: start.elapsed(),
        })
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "openssh".into(),
            host_key_pinning: true,
            remote_termination: RemoteTermination::Unconfirmed,
            connection_reuse: true,
        }
    }
}
