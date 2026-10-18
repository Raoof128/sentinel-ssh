//! `ssh_process_list` (spec §7.1 #5): bounded process summaries with command-line secrets redacted.

use std::sync::OnceLock;

use regex::Regex;
use schemars::JsonSchema;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::policy::ResourceRef;
use sentinel_core::scope::display_escape;
use serde::{Deserialize, Serialize};

use crate::mcp::results::Detail;
use crate::ssh::command::{Marker, RemoteCommand};
use crate::tools::pipeline::read_tool;
use crate::tools::{AppContext, UNTRUSTED, bounded};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessSort {
    #[default]
    Cpu,
    Mem,
    Pid,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessListParams {
    pub host_id: String,
    /// 1-200, default 50.
    pub limit: Option<u32>,
    /// cpu (default), mem or pid.
    pub sort: Option<ProcessSort>,
    /// Only processes of this user.
    pub user: Option<String>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct ProcessSummary {
    pub pid: u32,
    pub ppid: u32,
    pub user: String,
    pub cpu_percent: f32,
    pub mem_percent: f32,
    pub elapsed_seconds: u64,
    pub command: String,
    pub args_redacted: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct ProcessListData {
    pub processes: Vec<ProcessSummary>,
    pub content_trust: &'static str,
}

const REDACTED: &str = "[REDACTED]";

struct Redactors {
    bearer: Regex,
    header: Regex,
    single_header: Regex,
    signed_query: Regex,
    shaped: Regex,
    assign: Regex,
    keyword_flag: Regex,
    url: Regex,
    key_like: Regex,
    mysql_p: Regex,
}

/// Credential-ish words, matched anywhere inside a flag or variable name (`DB_PASSWORD`, `--github-token`).
const KW: &str = r"(?:password|passwd|pwd|pass|token|secret|credential|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth)";

fn redactors() -> &'static Redactors {
    static R: OnceLock<Redactors> = OnceLock::new();
    R.get_or_init(|| Redactors {
        bearer: Regex::new(r"(?i)\b(bearer|basic)(\s+)(\S+)").unwrap(),
        // The scheme word and the credential both go: `Authorization: token X`.
        header: Regex::new(r"(?i)\b((?:proxy-)?authorization)(:\s*)(\S+(?:\s+[^\s-]\S*)?)").unwrap(),
        single_header: Regex::new(r"(?i)\b(x-api-key|api-key|cookie|set-cookie|x-auth-token|x-access-token)(:\s*)(\S+)").unwrap(),
        // Signed-URL parameters (S3, GCS, Azure SAS) and OAuth codes, which carry no credential keyword.
        signed_query: Regex::new(
            r"(?i)([?&](?:sig|signature|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential|access_token|code))(=)([^&\s#]+)",
        )
        .unwrap(),
        // Self-identifying credential formats, wherever they appear: JWTs, GitHub and Slack tokens.
        shaped: Regex::new(r"\beyJ[\w-]{4,}\.[\w-]{4,}\.[\w-]{4,}|\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{8,}|\bxox[abposr]-[A-Za-z0-9-]{6,}").unwrap(),
        assign: Regex::new(&format!(r"(?i)([^\s=:&?]*{KW}[^\s=:&?]*)(=)([^\s&]+)")).unwrap(),
        // A whole token that is a credential-ish flag (`--db-password`, `-token`); its value is the next token.
        keyword_flag: Regex::new(&format!(r"(?i)^-{{1,2}}[\w.-]*{KW}[\w.-]*$")).unwrap(),
        // Userinfo up to the token's last '@': an empty user, or a raw '/' or '@' in the password, still hides it.
        url: Regex::new(r"(://[^/\s:@]*:)\S*@").unwrap(),
        key_like: Regex::new(r"(?i)([\w-]*key[\w-]*)(=)(\S{8,})").unwrap(),
        mysql_p: Regex::new(r"(\s-p)(\S+)").unwrap(),
    })
}

fn keep_redacted(c: &regex::Captures) -> String {
    if &c[3] == REDACTED {
        c[0].to_owned()
    } else {
        format!("{}{}{REDACTED}", &c[1], &c[2])
    }
}

/// Best-effort redaction of credentials in a command line. It cannot catch every secret (spec §9.7); the enforceable
/// boundary is which processes and fields are returned, not this filter. Errs towards over-redaction.
pub fn redact_args(args: &str) -> String {
    let r = redactors();
    let mut s = args.to_owned();
    let program = s
        .split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_owned();
    if program.starts_with("mysql") || program.starts_with("mariadb") {
        s = r.mysql_p.replace_all(&s, format!("${{1}}{REDACTED}")).into_owned();
    }
    s = r.url.replace_all(&s, format!("${{1}}{REDACTED}@")).into_owned();
    s = r.shaped.replace_all(&s, REDACTED).into_owned();
    for re in [&r.bearer, &r.header, &r.single_header, &r.signed_query, &r.assign, &r.key_like] {
        s = re.replace_all(&s, keep_redacted).into_owned();
    }
    redact_flag_values(&s, &r.keyword_flag)
}

/// Bare words that announce a following secret (exact, case-insensitive). `tokenizer` is not one.
const BARE_KEYWORDS: [&str; 17] = [
    "password",
    "passwd",
    "pwd",
    "pass",
    "token",
    "secret",
    "credential",
    "credentials",
    "apikey",
    "api_key",
    "api-key",
    "access_key",
    "access-key",
    "accesskey",
    "private_key",
    "private-key",
    "auth",
];

fn env_style_keyword() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Upper case as environment variables are written, or lower case joined by underscores (`db_password`); a
        // plain lower-case word that merely contains a keyword (`compass`, `author`) is not one.
        Regex::new(
            r"^[A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|PASS|TOKEN|SECRET|CREDENTIALS?|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH)[A-Z0-9_]*$|^(?:[a-z0-9]+_)+(?:password|passwd|pwd|pass|token|secret|credentials?|api_?key|access_?key|private_?key|auth)(?:_[a-z0-9]+)*$|^(?:password|passwd|pass|token|secret|credentials?|auth)(?:_[a-z0-9]+)+$",
        )
        .unwrap()
    })
}

/// Flags whose value is a secret only for one program (`-p` is a port for most, a password for sshpass).
const PROGRAM_SECRET_FLAGS: [(&str, &[&str]); 3] = [
    ("curl", &["-u", "--user", "-U", "--proxy-user", "-E", "--cert", "--oauth2-bearer"]),
    ("sshpass", &["-p"]),
    ("openssl", &["-k"]),
];

/// Whether `tok` announces that the next token is a secret: a credential flag (`--db-password`), an exact keyword
/// (`password:`), or an env-style name (`DB_PASSWORD`). Paths and file names (`/etc/token.d`, `auth_server.py`) never are.
fn is_keyword_token(tok: &str, keyword_flag: &Regex) -> bool {
    let t = tok.trim_end_matches([':', ',', ';']);
    if keyword_flag.is_match(t) {
        return true;
    }
    if t.contains('/') || t.contains('.') {
        return false;
    }
    BARE_KEYWORDS.contains(&t.to_ascii_lowercase().as_str()) || env_style_keyword().is_match(t)
}

/// Redacts the token after every keyword token, whatever it looks like (a value may start with `--`). If the redacted
/// token was itself a keyword, the one after it is redacted too: `--auth --password x` hides both. Errs towards
/// over-redaction.
fn redact_flag_values(s: &str, keyword_flag: &Regex) -> String {
    let mut out = String::with_capacity(s.len());
    let mut redact_next = false;
    // The most recent program word seen, so `sudo curl -u x` and `env A=1 sshpass -p x` are covered too.
    let mut program_flags: &[&str] = &[];
    let mut rest = s;
    while !rest.is_empty() {
        let ws = rest.len() - rest.trim_start().len();
        out.push_str(&rest[..ws]);
        rest = &rest[ws..];
        if rest.is_empty() {
            break;
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let tok = &rest[..end];
        rest = &rest[end..];
        if redact_next {
            out.push_str(REDACTED);
        } else {
            out.push_str(tok);
        }
        let base = tok.rsplit('/').next().unwrap_or(tok);
        if let Some((_, flags)) = PROGRAM_SECRET_FLAGS.iter().find(|(p, _)| *p == base) {
            program_flags = flags;
        }
        redact_next = tok != REDACTED && (is_keyword_token(tok, keyword_flag) || program_flags.contains(&tok));
    }
    out
}

/// Extra rows requested so that hiding the gateway's own processes does not shorten the list.
const OWN_PROCESS_SLACK: u64 = 16;

/// Drops the gateway's own processes (red team L2): the remote shell and everything it started (`ps`, `head`), the
/// `timeout` wrapper above it, and the session's sshd with every channel under it (other gateway commands sharing the
/// multiplexed connection). The walk up stops at anything else, so the host's own processes are never swept in.
fn without_own(procs: Vec<ProcessSummary>, shell: u32) -> Vec<ProcessSummary> {
    let by_pid: HashMap<u32, &ProcessSummary> = procs.iter().map(|p| (p.pid, p)).collect();
    let mut roots = vec![shell];
    let mut own: HashSet<u32> = HashSet::from([shell]);
    let mut cur = by_pid.get(&shell).map(|p| p.ppid);
    while let Some(parent) = cur.and_then(|pid| by_pid.get(&pid)) {
        if parent.command == "timeout" {
            own.insert(parent.pid);
            cur = Some(parent.ppid);
        } else {
            if parent.command.starts_with("sshd") && parent.pid != 1 {
                roots.push(parent.pid);
                own.insert(parent.pid);
            }
            break;
        }
    }
    // Descendants of the shell and of the session, to any depth, whatever order the list is in.
    let mut reached: HashSet<u32> = roots.into_iter().collect();
    let mut grown = true;
    while grown {
        grown = false;
        for p in &procs {
            if reached.contains(&p.ppid) && reached.insert(p.pid) {
                own.insert(p.pid);
                grown = true;
            }
        }
    }
    procs.into_iter().filter(|p| !own.contains(&p.pid)).collect()
}

fn valid_user(u: &str) -> bool {
    let b = u.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Seven fixed columns, then the full argument string with its spacing preserved.
pub fn parse_ps(text: &str) -> Vec<ProcessSummary> {
    text.lines()
        .filter_map(|line| {
            let mut rest = line.trim_start();
            let mut cols = Vec::with_capacity(7);
            for _ in 0..7 {
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                if end == 0 {
                    return None;
                }
                cols.push(&rest[..end]);
                rest = rest[end..].trim_start();
            }
            Some(ProcessSummary {
                pid: cols[0].parse().ok()?,
                ppid: cols[1].parse().ok()?,
                user: display_escape(cols[2]),
                cpu_percent: cols[3].parse().unwrap_or(0.0),
                mem_percent: cols[4].parse().unwrap_or(0.0),
                elapsed_seconds: cols[5].parse().unwrap_or(0),
                command: display_escape(cols[6]),
                args_redacted: display_escape(&redact_args(rest)),
            })
        })
        .collect()
}

pub async fn ssh_process_list(ctx: &AppContext, p: ProcessListParams) -> Result<ResultEnvelope<ProcessListData>> {
    let limit = bounded(p.limit, 50, 200, "limit")?;
    if let Some(u) = &p.user
        && !valid_user(u)
    {
        return Err(SentinelError::new(ErrorCode::InvalidInput, "user must match ^[a-z_][a-z0-9_-]{0,31}$").with_detail("field", "user"));
    }
    read_tool(
        ctx,
        "ssh_process_list",
        &p.host_id,
        ResourceRef::Host,
        Effect::Read,
        |run| async move {
            let ps = RemoteCommand::new("ps");
            let ps = match &p.user {
                Some(u) => ps.flag("-u").arg(u).flag("-o"),
                None => ps.flag("-eo"),
            };
            let sort = match p.sort.unwrap_or_default() {
                ProcessSort::Cpu => "--sort=-pcpu",
                ProcessSort::Mem => "--sort=-pmem",
                ProcessSort::Pid => "--sort=pid",
            };
            let mk = Marker::new();
            let cmd = RemoteCommand::shell_pid().then(mk.cmd()).then(
                ps.flag("pid=,ppid=,user=,pcpu=,pmem=,etimes=,comm=,args=")
                    .flag(sort)
                    .pipe(RemoteCommand::new("head").flag("-n").num(limit as u64 + OWN_PROCESS_SLACK)),
            );
            let out = run.run(&cmd).await?;
            let text = run.text_lossy(&out.stdout);
            let (shell, rest) = mk
                .split_header(text.as_bytes())
                .ok_or_else(|| SentinelError::new(ErrorCode::RemoteFailure, "unexpected remote output: process list"))?;
            let shell: u32 = shell
                .parse()
                .map_err(|_| SentinelError::new(ErrorCode::RemoteFailure, "unexpected remote output: shell pid"))?;
            let mut processes = without_own(parse_ps(&String::from_utf8_lossy(rest)), shell);
            processes.truncate(limit as usize);
            Ok(ProcessListData {
                processes,
                content_trust: UNTRUSTED,
            })
        },
    )
    .await
}
