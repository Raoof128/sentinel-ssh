//! `ssh_logs_search` (spec §7.1 #7): fixed-string search of a registered log source with match and window limits.

use schemars::JsonSchema;
use sentinel_core::effect::Effect;
use sentinel_core::envelope::ResultEnvelope;
use sentinel_core::error::{ErrorCode, Result, SentinelError};
use sentinel_core::policy::ResourceRef;
use sentinel_core::scope::display_escape;
use serde::{Deserialize, Serialize};

use crate::mcp::results::Detail;
use crate::ssh::backend::ExitKind;
use crate::ssh::command::{RemoteCommand, exact_file};
use crate::tools::files::not_found_or_failure;
use crate::tools::pipeline::{has_io_error, read_tool};
use crate::tools::{AppContext, UNTRUSTED, bounded};

pub const MAX_PATTERN_CHARS: usize = 256;
pub const MAX_LAST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LINE_CHARS: usize = 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PatternMode {
    #[default]
    Fixed,
    /// Not available in v0.1.
    Regex,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogsSearchParams {
    pub host_id: String,
    /// A log source id from `ssh_hosts_list`.
    pub source_id: String,
    /// Fixed string, 1-256 characters, no control characters.
    pub pattern: String,
    /// 1-200, default 50.
    pub max_matches: Option<u32>,
    /// Search only the final N bytes (at most 64 MiB). Line numbers are then relative to that window.
    pub last_bytes: Option<u64>,
    pub pattern_mode: Option<PatternMode>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct LogMatch {
    pub line_no: u64,
    /// Control characters escaped; cut at 1024 characters.
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct LogsSearchData {
    pub source_id: String,
    pub matches: Vec<LogMatch>,
    pub match_limit_reached: bool,
    pub line_numbers_relative_to_tail: bool,
    pub content_trust: &'static str,
}

fn invalid(msg: &str, field: &str) -> SentinelError {
    SentinelError::new(ErrorCode::InvalidInput, msg).with_detail("field", field)
}

pub async fn ssh_logs_search(ctx: &AppContext, p: LogsSearchParams) -> Result<ResultEnvelope<LogsSearchData>> {
    if p.pattern_mode == Some(PatternMode::Regex) {
        return Err(SentinelError::new(
            ErrorCode::CapabilityUnsupported,
            "regex search is not available in v0.1; use a fixed string",
        ));
    }
    let n = p.pattern.chars().count();
    if n == 0 || n > MAX_PATTERN_CHARS {
        return Err(invalid("pattern must be 1-256 characters", "pattern"));
    }
    // A newline would make grep -F search for several patterns.
    if p.pattern.chars().any(|c| c.is_control()) {
        return Err(invalid("pattern must not contain control characters", "pattern"));
    }
    if let Some(b) = p.last_bytes
        && (b == 0 || b > MAX_LAST_BYTES)
    {
        return Err(invalid("last_bytes must be between 1 and 67108864", "last_bytes"));
    }
    let max = bounded(p.max_matches, 50, 200, "max_matches")? as usize;
    let source = p.source_id.clone();
    read_tool(
        ctx,
        "ssh_logs_search",
        &p.host_id,
        ResourceRef::LogSource(&source),
        Effect::Read,
        |run| async move {
            let path = run
                .host
                .log_sources
                .get(&p.source_id)
                .map(|l| l.path.clone())
                .ok_or_else(|| SentinelError::new(ErrorCode::PolicyDenied, format!("unknown log source '{}'", p.source_id)))?;
            // -a: a NUL byte must not turn the log into "binary" and hide every match (red team).
            let grep = RemoteCommand::new("grep")
                .flag("-a")
                .flag("-F")
                .flag("-n")
                .flag("-m")
                .num(max as u64 + 1)
                .flag("--")
                .arg(&p.pattern);
            let main = match p.last_bytes {
                Some(b) => RemoteCommand::new("tail").flag("-c").num(b).stdin_fd3().pipe(grep),
                None => grep.stdin_fd3(),
            };
            // The log is read through a pinned descriptor: a symlink, hardlink or FIFO planted at its path is refused.
            let cmd = exact_file(&path, main);
            let out = run.run(&cmd).await?;
            match out.exit {
                ExitKind::Code(0) | ExitKind::Code(1) => {}
                _ => return Err(not_found_or_failure(&out.stderr)),
            }
            // With `tail | grep`, an unreadable log makes tail fail and grep exit 1 ("no match"); only stderr tells.
            if has_io_error(&out.stderr) {
                return Err(not_found_or_failure(&out.stderr));
            }
            if String::from_utf8_lossy(&out.stderr).contains("binary file matches") {
                run.warn("binary_content_skipped");
            }
            let text = run.text_lossy(&out.stdout);
            let mut matches = Vec::new();
            for line in text.lines() {
                if let Some((no, rest)) = line.split_once(':')
                    && let Ok(line_no) = no.parse::<u64>()
                {
                    let shown: String = rest.chars().take(MAX_LINE_CHARS).collect();
                    matches.push(LogMatch {
                        line_no,
                        text: display_escape(&shown),
                    });
                } else if line.starts_with("Binary file") || line.starts_with("grep: (standard input): binary file") {
                    run.warn("binary_content_skipped");
                }
            }
            let match_limit_reached = matches.len() > max;
            matches.truncate(max);
            Ok(LogsSearchData {
                source_id: p.source_id,
                matches,
                match_limit_reached,
                line_numbers_relative_to_tail: p.last_bytes.is_some(),
                content_trust: UNTRUSTED,
            })
        },
    )
    .await
}
