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
use crate::ssh::command::RemoteCommand;
use crate::tools::pipeline::read_tool;
use crate::tools::{AppContext, UNTRUSTED, bounded};

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
        header: Regex::new(r"(?i)\b((?:proxy-)?authorization|x-api-key|api-key)(:\s*)(\S+(?:\s+[^\s-]\S*)?)").unwrap(),
        assign: Regex::new(&format!(r"(?i)([^\s=:&?]*{KW}[^\s=:&?]*)(=)([^\s&]+)")).unwrap(),
        // A whole token that is a credential-ish flag (`--db-password`, `-token`); its value is the next token.
        keyword_flag: Regex::new(&format!(r"(?i)^-{{1,2}}[\w.-]*{KW}[\w.-]*$")).unwrap(),
        url: Regex::new(r"(://[^/\s:@]+:)[^@\s/]+@").unwrap(),
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
    for re in [&r.bearer, &r.header, &r.assign, &r.key_like] {
        s = re.replace_all(&s, keep_redacted).into_owned();
    }
    redact_flag_values(&s, &r.keyword_flag)
}

/// Bare words that announce a following secret. Exact match only: `tokenizer` or `auth_server.py` are not keywords.
const BARE_KEYWORDS: [&str; 10] = [
    "password",
    "passwd",
    "pwd",
    "pass",
    "token",
    "secret",
    "apikey",
    "api_key",
    "api-key",
    "credentials",
];

/// Redacts the token after a credential flag or bare keyword. A following long flag (`--x`) is never taken as the value,
/// so `--auth --password hunter2` still reaches `--password`; a single-dash value (`--password -abc`) is.
fn redact_flag_values(s: &str, keyword_flag: &Regex) -> String {
    let mut out = String::with_capacity(s.len());
    let mut redact_next = false;
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
        if redact_next && !tok.starts_with("--") {
            out.push_str(if tok == REDACTED { tok } else { REDACTED });
            redact_next = false;
            continue;
        }
        out.push_str(tok);
        redact_next = keyword_flag.is_match(tok) || BARE_KEYWORDS.contains(&tok.to_ascii_lowercase().as_str());
    }
    out
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
            let cmd = ps
                .flag("pid=,ppid=,user=,pcpu=,pmem=,etimes=,comm=,args=")
                .flag(sort)
                .pipe(RemoteCommand::new("head").flag("-n").num(limit as u64));
            let out = run.run(&cmd).await?;
            Ok(ProcessListData {
                processes: parse_ps(&run.text_lossy(&out.stdout)),
                content_trust: UNTRUSTED,
            })
        },
    )
    .await
}
