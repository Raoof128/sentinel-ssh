//! Every remote command the tools can send, rendered with hostile inputs and checked as text.
//!
//! The gateway's safety rests on two properties of the one string it hands to the remote shell: a caller's value can
//! only ever be data inside single quotes, and the fixed text around it can only read. The tests here drive each tool
//! through the scripted backend, collect what it would have sent, and check both properties without a host:
//!
//! - **Same skeleton.** With every single-quoted word blanked out, the command for a hostile value is identical to
//!   the command for a harmless one. Nothing a caller (or an operator's registered path, unit or URL) supplies can
//!   add a word, an operator, a redirection or a substitution.
//! - **Read-only shape.** Each program is called only with the options listed for it here, every redirection is one
//!   of four known forms, and nothing outside the allowlist is run at all. `find` never sees `-delete`, `-exec` or
//!   `-fprintf`; `curl` writes only to `/dev/null`.
//! - **No value is an option or stdin.** A quoted value that starts with `-` comes after `--` or is the argument of
//!   an option, and a file operand is never exactly `-` (which GNU tools read as standard input).

use std::collections::BTreeSet;
use std::sync::Arc;

use regex::Regex;
use sentinel_core::scope::shell_quote;
use sentinel_gateway::ssh::command::PROGRAMS;
use sentinel_gateway::tools::AppContext;
use sentinel_gateway::tools::artifacts::{ArtifactReadParams, ssh_artifact_read};
use sentinel_gateway::tools::batch::{BatchInspectParams, BatchItem, ssh_batch_inspect};
use sentinel_gateway::tools::capabilities::{CapabilitiesParams, ssh_capabilities_get};
use sentinel_gateway::tools::disk::{DiskUsageParams, ssh_disk_usage};
use sentinel_gateway::tools::files::{
    FileHashParams, FileReadParams, FileStatParams, FilesListParams, ssh_file_hash, ssh_file_read, ssh_file_stat, ssh_files_list,
};
use sentinel_gateway::tools::health::{HealthCheckParams, ssh_health_check};
use sentinel_gateway::tools::hosts::{HostInspectParams, HostsListParams, ssh_host_inspect, ssh_hosts_list};
use sentinel_gateway::tools::logs::{LogsSearchParams, ssh_logs_search};
use sentinel_gateway::tools::operations::{OperationCancelParams, OperationGetParams, ssh_operation_cancel, ssh_operation_get};
use sentinel_gateway::tools::processes::{ProcessListParams, ProcessSort, ssh_process_list};
use sentinel_gateway::tools::services::{ServiceStatusParams, ssh_service_status};
use sentinel_gateway::tools::transfers::{TransferDownloadParams, ssh_transfer_download};
use sentinel_testkit::configs::{TEST_HOST_KEY, TestDirs, fake_identity, minimal_config_toml, write_private};
use sentinel_testkit::fake_backend::FakeBackend;

const H: &str = "h1";

/// Values a hostile caller might send for any free-text parameter.
const HOSTILE: &[&str] = &[
    "-",
    "--",
    "-rf",
    "--help",
    "-delete",
    "-exec",
    "-fprintf",
    "-o",
    "--output",
    "-T",
    "-exec sh -c reboot ;",
    "x -delete",
    "$(reboot)",
    "`reboot`",
    "${IFS}reboot",
    "$HOME",
    "a; reboot",
    "a && reboot",
    "a || reboot",
    "a | sh",
    "a & reboot",
    "a > /etc/passwd",
    "a >> /etc/passwd",
    "a < /etc/shadow",
    "2>&1",
    "<&3",
    "it's",
    "'",
    "''",
    "'; reboot; '",
    "' -delete '",
    "'\\''; reboot; '\\''",
    "a\\",
    "a\\'; reboot; '",
    "\"; reboot; \"",
    "\"$(reboot)\"",
    "*",
    "?",
    "[a-z]*",
    "{a,b}",
    "~",
    "~root",
    "!!",
    "#x",
    "a b",
    "  ",
    "(",
    ")",
    "x=1",
    "%s%n",
    "--SENTINEL--",
    "a\nreboot",
    "a\treboot",
    "a\rreboot",
    "\u{202e}gnp.exe",
    "é/ü",
];

/// The tools that reach a host, with the one free-text value each takes. `Fixed` tools take none.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Tool {
    FilesList,
    FileRead,
    FileStat,
    FileHash,
    Download,
    DiskUsage,
    LogsSearch,
    ProcessList,
    ServiceStatus,
    HealthHttp,
    HealthQuery,
    HealthService,
    HostInspect,
    Batch,
}

const PATH_TOOLS: [Tool; 6] = [
    Tool::FilesList,
    Tool::FileRead,
    Tool::FileStat,
    Tool::FileHash,
    Tool::Download,
    Tool::DiskUsage,
];
const ALL_TOOLS: [Tool; 14] = [
    Tool::FilesList,
    Tool::FileRead,
    Tool::FileStat,
    Tool::FileHash,
    Tool::Download,
    Tool::DiskUsage,
    Tool::LogsSearch,
    Tool::ProcessList,
    Tool::ServiceStatus,
    Tool::HealthHttp,
    Tool::HealthQuery,
    Tool::HealthService,
    Tool::HostInspect,
    Tool::Batch,
];

/// A gateway over the minimal config (after `edit`) whose backend records every command and answers each with empty
/// output, except the digest step of a download, which gets a well-formed answer so that the stream step follows.
struct Rig {
    ctx: AppContext,
    fake: FakeBackend,
    _dirs: TestDirs,
}

fn rig(edit: impl Fn(String) -> String) -> Rig {
    let dirs = TestDirs::new();
    let identity = fake_identity(dirs.state.path());
    let path = dirs.state.path().join("config.toml");
    write_private(&path, &edit(minimal_config_toml(TEST_HOST_KEY, &identity, &dirs)));
    let cfg = sentinel_gateway::config::load_config(&path).expect("config loads");
    let fake = FakeBackend::new()
        .on("sha256sum", format!("5\n\n--SENTINEL--\n{}  -\n", "a".repeat(64)))
        .on("", "");
    let ctx = AppContext::new(cfg, Arc::new(fake.clone())).expect("context");
    Rig { ctx, fake, _dirs: dirs }
}

/// Runs `tool` with `value` as its free-text parameter and returns what it sent. The tool's own result is ignored:
/// most calls fail on the empty scripted output, after the command has been recorded.
async fn sent(rig: &Rig, tool: Tool, value: &str) -> Vec<String> {
    let (ctx, fake) = (&rig.ctx, &rig.fake);
    let before = fake.calls().len();
    let (h, root, v) = (H.to_owned(), "app".to_owned(), value.to_owned());
    match tool {
        Tool::FilesList => drop(
            ssh_files_list(
                ctx,
                FilesListParams {
                    host_id: h,
                    root,
                    path: v,
                    ..Default::default()
                },
            )
            .await,
        ),
        Tool::FileRead => drop(
            ssh_file_read(
                ctx,
                FileReadParams {
                    host_id: h,
                    root,
                    path: v,
                    offset: Some(7),
                    ..Default::default()
                },
            )
            .await,
        ),
        Tool::FileStat => drop(
            ssh_file_stat(
                ctx,
                FileStatParams {
                    host_id: h,
                    root,
                    path: v,
                    ..Default::default()
                },
            )
            .await,
        ),
        Tool::FileHash => drop(
            ssh_file_hash(
                ctx,
                FileHashParams {
                    host_id: h,
                    root,
                    path: v,
                    ..Default::default()
                },
            )
            .await,
        ),
        Tool::Download => drop(
            ssh_transfer_download(
                ctx,
                TransferDownloadParams {
                    host_id: h,
                    root,
                    path: v,
                    ..Default::default()
                },
            )
            .await,
        ),
        Tool::DiskUsage => drop(
            ssh_disk_usage(
                ctx,
                DiskUsageParams {
                    host_id: h,
                    root,
                    path: Some(v),
                    depth: Some(3),
                    ..Default::default()
                },
            )
            .await,
        ),
        Tool::LogsSearch => {
            for last_bytes in [None, Some(4096)] {
                drop(
                    ssh_logs_search(
                        ctx,
                        LogsSearchParams {
                            host_id: H.into(),
                            source_id: "api".into(),
                            pattern: v.clone(),
                            last_bytes,
                            ..Default::default()
                        },
                    )
                    .await,
                );
            }
        }
        Tool::ProcessList => {
            for sort in [ProcessSort::Cpu, ProcessSort::Mem, ProcessSort::Pid] {
                drop(
                    ssh_process_list(
                        ctx,
                        ProcessListParams {
                            host_id: H.into(),
                            user: Some(v.clone()),
                            sort: Some(sort),
                            ..Default::default()
                        },
                    )
                    .await,
                );
            }
            drop(
                ssh_process_list(
                    ctx,
                    ProcessListParams {
                        host_id: H.into(),
                        ..Default::default()
                    },
                )
                .await,
            );
        }
        Tool::ServiceStatus => {
            for service_id in ["api", "worker", value] {
                drop(
                    ssh_service_status(
                        ctx,
                        ServiceStatusParams {
                            host_id: H.into(),
                            service_id: service_id.into(),
                            ..Default::default()
                        },
                    )
                    .await,
                );
            }
        }
        Tool::HealthHttp | Tool::HealthQuery | Tool::HealthService => {
            let check_id = match tool {
                Tool::HealthHttp => "api_http",
                Tool::HealthQuery => "api_query",
                _ => "api_active",
            };
            for check_id in [check_id, value] {
                drop(
                    ssh_health_check(
                        ctx,
                        HealthCheckParams {
                            host_id: H.into(),
                            check_id: check_id.into(),
                            ..Default::default()
                        },
                    )
                    .await,
                );
            }
        }
        Tool::HostInspect => drop(
            ssh_host_inspect(
                ctx,
                HostInspectParams {
                    host_id: h,
                    ..Default::default()
                },
            )
            .await,
        ),
        Tool::Batch => {
            let item = |id: &str, tool: &str, params: serde_json::Value| BatchItem {
                id: id.into(),
                tool: tool.into(),
                params,
            };
            let items = vec![
                item(
                    "a",
                    "ssh_file_stat",
                    serde_json::json!({"host_id": H, "root": "app", "path": value}),
                ),
                item(
                    "b",
                    "ssh_logs_search",
                    serde_json::json!({"host_id": H, "source_id": "api", "pattern": value}),
                ),
                item("c", "ssh_process_list", serde_json::json!({"host_id": H, "user": value})),
                item(
                    "d",
                    "ssh_files_list",
                    serde_json::json!({"host_id": H, "root": "app", "path": value}),
                ),
            ];
            drop(
                ssh_batch_inspect(
                    ctx,
                    BatchInspectParams {
                        items,
                        ..Default::default()
                    },
                )
                .await,
            );
        }
    }
    fake.calls().split_off(before)
}

fn same(s: String) -> String {
    s
}

// ---------------------------------------------------------------------------------------------------------------------
// Reading a rendered command.

/// Stands in for one single-quoted word in a skeleton. A control character, so it cannot occur in the fixed text.
const Q: char = '\u{1}';

/// Exactly the words `shell_quote` can produce: `'…'` runs joined by `\'`.
fn quoted_word() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"'[^']*'(?:\\''[^']*')*").unwrap())
}

/// The command with each single-quoted word replaced by `Q<index>Q`, and the values those words hold.
fn split_quoted(cmd: &str) -> (String, Vec<String>) {
    let mut values = Vec::new();
    let text = quoted_word()
        .replace_all(cmd, |c: &regex::Captures| {
            let raw = &c[0];
            let value = raw[1..raw.len() - 1].replace("'\\''", "'");
            assert_eq!(shell_quote(&value), raw, "a quoted word that shell_quote did not write, in: {cmd}");
            values.push(value);
            format!("{Q}{}{Q}", values.len() - 1)
        })
        .into_owned();
    (text, values)
}

/// The fixed text of a command: every single-quoted word blanked out.
fn skeleton(cmd: &str) -> String {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let index = RE.get_or_init(|| Regex::new("\u{1}[0-9]+\u{1}").unwrap());
    index.replace_all(&split_quoted(cmd).0, Q.to_string()).into_owned()
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    /// Fixed text: a word the gateway wrote, possibly with a double-quoted part (`"$f"`, `"regular file|1"`).
    Fixed(String),
    /// A single-quoted word, by its value.
    Quoted(String),
    /// `;`, `;;`, `|`, `||`, `&&`, `&`, `$(`, `(`, `)`.
    Op(String),
    /// A redirection operator with its descriptor numbers and any attached target: `2>/dev/null`, `>&2`, `<&3`, `3<`.
    Redir(String),
}

/// A small POSIX-shell lexer for the text the gateway writes. Single-quoted words are already placeholders. A double
/// quote groups its content into one word, except that a `$(…)` inside it is lexed as commands again, as the shell does.
fn lex(cmd: &str) -> Vec<Tok> {
    let (text, values) = split_quoted(cmd);
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    // Open constructs: '"' for a double quote, '(' for a command substitution.
    let mut open: Vec<char> = Vec::new();
    fn flush(cur: &mut String, out: &mut Vec<Tok>) {
        if !cur.is_empty() {
            out.push(Tok::Fixed(std::mem::take(cur)));
        }
    }
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        let in_dq = open.last() == Some(&'"');
        if ch == Q {
            let end = (i + 1..c.len()).find(|&j| c[j] == Q).expect("placeholder end");
            let index: usize = c[i + 1..end].iter().collect::<String>().parse().expect("placeholder index");
            assert!(!in_dq, "a single-quoted value inside double quotes is not quoted at all: {cmd}");
            assert!(
                cur.is_empty() || cur.ends_with('/') || cur.ends_with('='),
                "a quoted value glued to '{cur}' in: {cmd}"
            );
            let glued_after = c.get(end + 1).is_some_and(|n| !n.is_whitespace() && !";|&)".contains(*n));
            assert!(!glued_after, "text glued after a quoted value in: {cmd}");
            flush(&mut cur, &mut out);
            out.push(Tok::Quoted(values[index].clone()));
            i = end + 1;
        } else if ch == '\\' {
            cur.push(ch);
            cur.push(c[i + 1]);
            i += 2;
        } else if ch == '"' {
            if in_dq {
                open.pop();
            } else {
                open.push('"');
            }
            cur.push(ch);
            i += 1;
        } else if ch == '$' && c.get(i + 1) == Some(&'(') {
            flush(&mut cur, &mut out);
            open.push('(');
            out.push(Tok::Op("$(".into()));
            i += 2;
        } else if in_dq {
            cur.push(ch);
            i += 1;
        } else if ch == ')' {
            flush(&mut cur, &mut out);
            if open.last() == Some(&'(') {
                open.pop();
            }
            out.push(Tok::Op(")".into()));
            i += 1;
        } else if ch.is_whitespace() {
            flush(&mut cur, &mut out);
            i += 1;
        } else if ch == '<' || ch == '>' {
            // Leading digits are the descriptor number.
            let fd = if !cur.is_empty() && cur.chars().all(|d| d.is_ascii_digit()) {
                std::mem::take(&mut cur)
            } else {
                flush(&mut cur, &mut out);
                String::new()
            };
            let mut r = format!("{fd}{ch}");
            i += 1;
            while i < c.len() && !c[i].is_whitespace() && !";|)".contains(c[i]) && c[i] != Q {
                r.push(c[i]);
                i += 1;
            }
            out.push(Tok::Redir(r));
        } else if ";|&(".contains(ch) {
            flush(&mut cur, &mut out);
            let double = c.get(i + 1) == Some(&ch) && ch != '(';
            out.push(Tok::Op(if double { format!("{ch}{ch}") } else { ch.to_string() }));
            i += if double { 2 } else { 1 };
        } else {
            cur.push(ch);
            i += 1;
        }
    }
    flush(&mut cur, &mut out);
    assert!(open.is_empty(), "unbalanced quoting in: {cmd}");
    out
}

// ---------------------------------------------------------------------------------------------------------------------
// What a command may contain.

/// Utilities the commands may run: the allowlist in `ssh::command` and the two the containment prologue adds.
fn external() -> BTreeSet<&'static str> {
    PROGRAMS.iter().copied().chain(["realpath", "readlink"]).collect()
}

/// What one utility may be given. Nothing listed here writes a file, deletes anything or starts a program.
struct Spec {
    program: &'static str,
    options: &'static [&'static str],
    /// The options whose next word is their argument.
    with_value: &'static [&'static str],
    /// Other fixed words (numbers are always allowed).
    words: &'static [&'static str],
    /// How many quoted operands it may take, not counting option arguments.
    max_operands: usize,
}

const PS_FORMAT: &str = "pid=,ppid=,user=,pcpu=,pmem=,etimes=,comm=,args=";
const SHOW_PROPERTIES: &str = "Id,ActiveState,SubState,LoadState,Result,MainPID,NRestarts,ActiveEnterTimestamp";
const FIND_FORMAT: &str = r"%y\t%s\t%T@\t%m\t%f\0";

#[rustfmt::skip]
const SPECS: &[Spec] = &[
    Spec { program: "cat", options: &[], with_value: &[], words: &[], max_operands: 1 },
    Spec { program: "curl", options: &["-q", "-g", "-sS", "-o", "-w", "--max-time", "--"], with_value: &["-o", "-w", "--max-time"], words: &[], max_operands: 1 },
    Spec { program: "df", options: &["-B1", "-P", "--"], with_value: &[], words: &[], max_operands: 1 },
    Spec { program: "du", options: &["-x", "-P", "-a", "-0", "-B1", "-d", "--"], with_value: &["-d"], words: &[], max_operands: 1 },
    Spec { program: "find", options: &["-mindepth", "-maxdepth", "-printf"], with_value: &["-mindepth", "-maxdepth", "-printf"], words: &["\"$@\""], max_operands: 1 },
    Spec { program: "free", options: &["-b"], with_value: &[], words: &[], max_operands: 0 },
    Spec { program: "grep", options: &["-a", "-F", "-n", "-m", "--"], with_value: &["-m"], words: &[], max_operands: 1 },
    Spec { program: "head", options: &["-c", "-n", "-z"], with_value: &["-c", "-n"], words: &[], max_operands: 0 },
    Spec { program: "hostname", options: &[], with_value: &[], words: &[], max_operands: 0 },
    Spec { program: "nproc", options: &[], with_value: &[], words: &[], max_operands: 0 },
    Spec { program: "printf", options: &[], with_value: &[], words: &["\"$o\"", "\"$$\""], max_operands: 1 },
    Spec { program: "ps", options: &["-eo", "-u", "-o", "--sort=-pcpu", "--sort=-pmem", "--sort=pid"], with_value: &["-eo", "-u", "-o"], words: &[], max_operands: 0 },
    Spec { program: "readlink", options: &[], with_value: &[], words: &["/dev/fd/3"], max_operands: 0 },
    Spec { program: "realpath", options: &["-e", "--"], with_value: &[], words: &["\"$1\""], max_operands: 0 },
    Spec { program: "sha256sum", options: &[], with_value: &[], words: &[], max_operands: 0 },
    Spec { program: "sort", options: &["-z", "-rn", "-t", "-k5"], with_value: &["-t"], words: &[], max_operands: 0 },
    Spec { program: "stat", options: &["-L", "-c", "--"], with_value: &["-c"], words: &["/dev/fd/3", "\"$f\""], max_operands: 1 },
    Spec { program: "systemctl", options: &["--user", "--no-pager", "-p", "--"], with_value: &["-p"], words: &["show", "is-active"], max_operands: 1 },
    Spec { program: "tail", options: &["-c"], with_value: &["-c"], words: &[], max_operands: 0 },
    Spec { program: "true", options: &[], with_value: &[], words: &[], max_operands: 0 },
    Spec { program: "uname", options: &["-srm"], with_value: &[], words: &[], max_operands: 0 },
];

/// Options that would let `find` or `curl` write, delete, upload or run something. The specs above already exclude
/// them (they list what is allowed); this names them so the intent is checked directly as well.
const FIND_WRITES_OR_RUNS: &[&str] = &[
    "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls",
];
const CURL_WRITES_OR_SENDS: &[&str] = &[
    "--output",
    "-O",
    "--remote-name",
    "--remote-name-all",
    "--output-dir",
    "-T",
    "--upload-file",
    "-D",
    "--dump-header",
    "-c",
    "--cookie-jar",
    "-K",
    "--config",
    "--trace",
    "--trace-ascii",
    "--stderr",
    "--libcurl",
    "--etag-save",
    "--hsts",
    "--alt-svc",
    "-d",
    "--data",
    "--data-binary",
    "-F",
    "--form",
    "-X",
    "--request",
    "-L",
    "--location",
];

/// Every fixed word the gateway writes that is not a number. A new word (a utility, an option, a shell keyword) has
/// to be added here by hand, next to the specs it must also satisfy.
#[rustfmt::skip]
const VOCABULARY: &[&str] = &[
    // shell syntax and builtins
    "!", "\"", "*", "--", "=", "[", "]", "case", "cd", "echo", "esac", "exec", "exit", "fi", "if", "in", "return", "set", "then", "{", "}",
    "-P", "-d", "-e", "-le", "-samefile", ".", "/", "x", "directory",
    // the prologue's functions, variables and patterns
    "deny", "enter", "inside", "rp", "NL=", "e=\"$w\"/", "f=", "l=", "l=${l%\"$NL\"}", "l=${l%x}", "o=", "o=${o%\"$NL\"}", "o=${o%x}", "r=", "w=", "x=",
    "\"$$\"", "\"$1\"", "\"$1/\"", "\"$2\"", "\"$2\"/*", "\"$@\"", "\"$e\"", "\"$f\"", "\"$l\"", "\"$o\"", "\"$r\"", "\"$w\"", "\"$x\"", "$l", "$o",
    "\"regular empty file\"", "\"regular empty file|\"*", "\"regular empty file|1\"", "\"regular file\"", "\"regular file|\"*", "\"regular file|1\"",
    "*\" (deleted)\"", "*\"$NL\"*", "%F", "%d:%i", "%s", "/dev/fd/3",
    "SENTINEL_EXCLUDED", "SENTINEL_HARDLINK", "SENTINEL_KIND_MISMATCH", "SENTINEL_MISSING", "SENTINEL_NESTED_EXCLUDED", "SENTINEL_NO_ACCESS",
    "SENTINEL_ROOT_MISSING", "SENTINEL_SCOPE_ESCAPE", "SENTINEL_TOO_LARGE",
    // utilities and their options
    "cat", "curl", "df", "du", "find", "free", "grep", "head", "hostname", "nproc", "printf", "ps", "readlink", "realpath", "sha256sum", "sort",
    "stat", "systemctl", "tail", "true", "uname",
    "--max-time", "--no-pager", "--sort=-pcpu", "--sort=-pmem", "--sort=pid", "--user", "-0", "-B1", "-F", "-L", "-a", "-b", "-c", "-eo", "-g", "-k5",
    "-m", "-maxdepth", "-mindepth", "-n", "-o", "-p", "-printf", "-q", "-rn", "-sS", "-srm", "-t", "-u", "-w", "-x", "-z",
    "is-active", "show", PS_FORMAT, SHOW_PROPERTIES,
];

/// The only redirections: errors to stderr, a failed `cd` silenced, the pinned file opened on descriptor 3, and
/// commands reading that descriptor. None of them can create or change a file on the host.
const REDIRECTIONS: &[&str] = &[">&2", "2>/dev/null", "3<", "<&3"];

fn is_number(w: &str) -> bool {
    !w.is_empty() && w.chars().all(|c| c.is_ascii_digit())
}

/// Whether a word at `i` is where the shell reads a command name.
fn at_command_position(toks: &[Tok], i: usize) -> bool {
    match i.checked_sub(1).map(|p| &toks[p]) {
        None | Some(Tok::Op(_)) => true,
        Some(Tok::Fixed(w)) => ["then", "else", "do", "{", "if", "!"].contains(&w.as_str()),
        _ => false,
    }
}

/// Every run of an external utility: its name and its arguments up to the next operator.
fn invocations(toks: &[Tok]) -> Vec<(String, Vec<Tok>)> {
    let ext = external();
    let mut found = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        let Tok::Fixed(w) = t else { continue };
        if !ext.contains(w.as_str()) {
            continue;
        }
        assert!(at_command_position(toks, i), "'{w}' appears as an argument at token {i}: {toks:?}");
        let args = toks[i + 1..].iter().take_while(|t| !matches!(t, Tok::Op(_))).cloned().collect();
        found.push((w.clone(), args));
    }
    found
}

fn option_argument(program: &str, option: &str, value: &Tok) {
    let ok = match (program, option, value) {
        ("curl", "-o", Tok::Quoted(v)) => v == "/dev/null",
        ("curl", "-w", Tok::Quoted(v)) => v == "%{http_code}",
        ("find", "-printf", Tok::Quoted(v)) => v == FIND_FORMAT,
        ("find", "-mindepth" | "-maxdepth", Tok::Fixed(v)) => v == "1",
        ("ps", "-u", Tok::Quoted(v)) => Regex::new("^[a-z_][a-z0-9_-]{0,31}$").unwrap().is_match(v),
        ("ps", "-eo" | "-o", Tok::Fixed(v)) => v == PS_FORMAT,
        ("stat", "-c", Tok::Fixed(v)) => ["%F", "%s", "%d:%i"].contains(&v.as_str()),
        ("stat", "-c", Tok::Quoted(v)) => ["%F|%h", "%F|%s|%a|%U|%G|%Y|%h"].contains(&v.as_str()),
        ("tail", "-c", Tok::Quoted(v)) => v.strip_prefix('+').is_some_and(is_number),
        ("sort", "-t", Tok::Quoted(v)) => v == "\t",
        ("systemctl", "-p", Tok::Fixed(v)) => v == SHOW_PROPERTIES,
        ("curl", "--max-time", Tok::Fixed(v))
        | ("tail" | "head", "-c", Tok::Fixed(v))
        | ("head", "-n", Tok::Fixed(v))
        | ("grep", "-m", Tok::Fixed(v))
        | ("du", "-d", Tok::Fixed(v)) => is_number(v),
        _ => false,
    };
    assert!(ok, "{program} {option} is given {value:?}");
}

fn check_invocation(program: &str, args: &[Tok], cmd: &str) {
    let spec = SPECS
        .iter()
        .find(|s| s.program == program)
        .unwrap_or_else(|| panic!("{program} has no entry in SPECS"));
    let mut after_double_dash = false;
    let mut operands: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match &args[i] {
            Tok::Redir(_) => {}
            Tok::Op(o) => unreachable!("arguments stop at an operator, found {o}"),
            Tok::Fixed(w) if w == "--" => {
                assert!(spec.options.contains(&"--"), "{program} is given --, in: {cmd}");
                after_double_dash = true;
            }
            Tok::Fixed(w) if w.starts_with('-') => {
                assert!(
                    !after_double_dash && spec.options.contains(&w.as_str()),
                    "{program} is given {w}, which is not one of its read-only options, in: {cmd}"
                );
                if spec.with_value.contains(&w.as_str()) {
                    i += 1;
                    let value = args.get(i).unwrap_or_else(|| panic!("{program} {w} has no argument, in: {cmd}"));
                    option_argument(program, w, value);
                }
            }
            Tok::Fixed(w) => assert!(
                spec.words.contains(&w.as_str()) || is_number(w),
                "{program} is given the word {w}, in: {cmd}"
            ),
            Tok::Quoted(v) => {
                if v.starts_with('-') {
                    // A search pattern and a registered unit name may be anything; both come after `--`.
                    assert!(
                        after_double_dash && matches!(program, "grep" | "systemctl"),
                        "{program} is given the value {v:?}, which it could read as an option, in: {cmd}"
                    );
                }
                operands.push(v);
            }
        }
        i += 1;
    }
    assert!(
        operands.len() <= spec.max_operands,
        "{program} is given {} operands ({operands:?}), in: {cmd}",
        operands.len()
    );
    let marker = Regex::new("^\n--SENTINEL-[0-9a-f]{32}--\n$").unwrap();
    for v in &operands {
        let ok = match program {
            "grep" | "systemctl" => after_double_dash,
            "curl" => after_double_dash && (v.starts_with("http://") || v.starts_with("https://")),
            "cat" => ["/etc/os-release", "/proc/loadavg", "/proc/uptime"].contains(v),
            "df" | "du" | "find" => *v == ".",
            "printf" => ["%s", "%s\n"].contains(v) || marker.is_match(v),
            // A file operand is a path that cannot be read as an option or as standard input (`-`).
            "stat" => *v == "." || v.starts_with("./") || v.starts_with('/'),
            _ => false,
        };
        assert!(ok, "{program} is given the operand {v:?}, in: {cmd}");
    }
    let named: &[&str] = match program {
        "find" => FIND_WRITES_OR_RUNS,
        "curl" => CURL_WRITES_OR_SENDS,
        _ => &[],
    };
    for a in args {
        if let Tok::Fixed(w) = a {
            assert!(!named.contains(&w.as_str()), "{program} is given {w}, in: {cmd}");
        }
    }
}

/// Every check that needs only the command itself.
fn check(cmd: &str) {
    let toks = lex(cmd);
    for (i, t) in toks.iter().enumerate() {
        match t {
            Tok::Fixed(w) => assert!(
                VOCABULARY.contains(&w.as_str()) || is_number(w),
                "the word {w:?} is not in the vocabulary, in: {cmd}"
            ),
            Tok::Redir(r) => {
                assert!(REDIRECTIONS.contains(&r.as_str()), "redirection {r:?} in: {cmd}");
                if r == "3<" {
                    let target = toks.get(i + 1);
                    assert!(
                        matches!(target, Some(Tok::Quoted(v)) if v == "." || v.starts_with("./")),
                        "descriptor 3 is opened on {target:?}, in: {cmd}"
                    );
                }
            }
            // No background job and no subshell; `(` only ever opens a function definition's `()`.
            Tok::Op(o) if o == "&" => panic!("a background job in: {cmd}"),
            Tok::Op(o) if o == "(" => assert_eq!(toks.get(i + 1), Some(&Tok::Op(")".into())), "a subshell in: {cmd}"),
            _ => {}
        }
    }
    for (program, args) in invocations(&toks) {
        check_invocation(&program, &args, cmd);
    }
}

fn programs_in(cmd: &str) -> BTreeSet<String> {
    invocations(&lex(cmd)).into_iter().map(|(p, _)| p).collect()
}

// ---------------------------------------------------------------------------------------------------------------------
// The tests.

/// The value in each position a path can take: alone, as the last component, and as a directory on the way.
fn shapes(tool: Tool, value: &str) -> Vec<String> {
    if PATH_TOOLS.contains(&tool) {
        vec![value.to_owned(), format!("dir/{value}"), format!("{value}/leaf")]
    } else {
        vec![value.to_owned()]
    }
}

#[tokio::test]
async fn hostile_values_never_change_the_shape_of_a_command() {
    for tool in ALL_TOOLS {
        let rig = rig(same);
        let mut harmless = BTreeSet::new();
        for v in shapes(tool, "plain") {
            for c in sent(&rig, tool, &v).await {
                check(&c);
                harmless.insert(skeleton(&c));
            }
        }
        assert!(!harmless.is_empty(), "{tool:?} sent nothing for a harmless value");
        let mut reached = 0;
        for hostile in HOSTILE {
            for v in shapes(tool, hostile) {
                for c in sent(&rig, tool, &v).await {
                    check(&c);
                    assert!(
                        harmless.contains(&skeleton(&c)),
                        "{tool:?} with {v:?} sent a command whose fixed text differs from a harmless call:\n{c}"
                    );
                    reached += usize::from(split_quoted(&c).1.iter().any(|q| q.contains(hostile)));
                }
            }
        }
        // The comparison above must not pass only because every hostile value was refused before dispatch.
        if PATH_TOOLS.contains(&tool) || matches!(tool, Tool::LogsSearch | Tool::Batch) {
            assert!(reached > 100, "{tool:?}: only {reached} commands carried a hostile value");
        }
    }
}

#[tokio::test]
async fn a_name_that_looks_like_an_option_or_stdin_is_passed_as_a_path() {
    for tool in [Tool::FileRead, Tool::FileStat, Tool::FileHash, Tool::Download] {
        let rig = rig(same);
        for name in ["-", "--", "-rf", "--help", "-delete"] {
            let sent = sent(&rig, tool, name).await;
            assert!(!sent.is_empty(), "{tool:?} refused {name:?} before dispatch");
            for c in sent {
                let values = split_quoted(&c).1;
                assert!(values.contains(&format!("./{name}")), "{tool:?} {name:?}: {c}");
                check(&c);
            }
        }
    }
}

/// Paths, units and URLs an operator registers are quoted exactly like a caller's values, whatever they contain.
#[tokio::test]
async fn operator_registered_values_are_quoted_like_any_other() {
    const UNIT: &str = "--help";
    const USER_UNIT: &str = "-.mount";
    const LOG: &str = "/var/log/app/-";
    const URL: &str = "http://127.0.0.1:8080/-o/tmp/x';reboot;'$(id)`id`{a,b}[1-9]";
    const ROOT: &str = "/srv/-x 'q' $(id);reboot";
    let edge = |toml: String| {
        toml.replace("unit = \"app-api.service\"", &format!("unit = \"{UNIT}\""))
            .replace("unit = \"worker.service\"", &format!("unit = \"{USER_UNIT}\""))
            .replace("path = \"/var/log/app/api.log\"", &format!("path = \"{LOG}\""))
            .replace("url = \"http://127.0.0.1:8080/health\"", &format!("url = \"{URL}\""))
            .replace("\"/srv/app", &format!("\"{ROOT}"))
    };
    let mut carried = BTreeSet::new();
    for tool in ALL_TOOLS {
        let (plain, edged) = (rig(same), rig(edge));
        for v in shapes(tool, "plain") {
            let expected: BTreeSet<String> = sent(&plain, tool, &v).await.iter().map(|c| skeleton(c)).collect();
            let got = sent(&edged, tool, &v).await;
            assert!(!got.is_empty(), "{tool:?} sent nothing with the edge config");
            for c in got {
                check(&c);
                assert!(
                    expected.contains(&skeleton(&c)),
                    "{tool:?}: the registered values changed the fixed text:\n{c}"
                );
                carried.extend(split_quoted(&c).1);
            }
        }
    }
    for registered in [UNIT, USER_UNIT, "./-", URL, ROOT] {
        assert!(carried.contains(registered), "{registered:?} never reached a command");
    }
}

#[tokio::test]
async fn every_allowlisted_program_is_exercised_and_every_command_is_read_only() {
    let mut seen = BTreeSet::new();
    for tool in ALL_TOOLS {
        let rig = rig(same);
        for v in shapes(tool, "plain") {
            for c in sent(&rig, tool, &v).await {
                check(&c);
                seen.extend(programs_in(&c));
            }
        }
    }
    // `true` is the connectivity probe of `doctor --connect`, not a tool command.
    let expected: BTreeSet<String> = external().into_iter().filter(|p| *p != "true").map(String::from).collect();
    assert_eq!(
        seen, expected,
        "a program in the allowlist is not covered by this test, or the reverse"
    );
    check(&sentinel_gateway::ssh::command::RemoteCommand::new("true").render());
}

/// The largest numbers each tool accepts still render as plain digits in the same places.
#[tokio::test]
async fn numeric_limits_render_as_numbers() {
    let rig = rig(same);
    let (h, root) = (H.to_owned(), "app".to_owned());
    drop(
        ssh_file_read(
            &rig.ctx,
            FileReadParams {
                host_id: h.clone(),
                root: root.clone(),
                path: "f".into(),
                offset: Some(i64::MAX as u64),
                length: Some(65536),
                ..Default::default()
            },
        )
        .await,
    );
    drop(
        ssh_files_list(
            &rig.ctx,
            FilesListParams {
                host_id: h.clone(),
                root: root.clone(),
                path: "d".into(),
                max_entries: Some(500),
                ..Default::default()
            },
        )
        .await,
    );
    drop(
        ssh_disk_usage(
            &rig.ctx,
            DiskUsageParams {
                host_id: h.clone(),
                root,
                path: None,
                depth: Some(3),
                max_entries: Some(200),
                ..Default::default()
            },
        )
        .await,
    );
    drop(
        ssh_process_list(
            &rig.ctx,
            ProcessListParams {
                host_id: h.clone(),
                limit: Some(200),
                ..Default::default()
            },
        )
        .await,
    );
    drop(
        ssh_logs_search(
            &rig.ctx,
            LogsSearchParams {
                host_id: h,
                source_id: "api".into(),
                pattern: "x".into(),
                max_matches: Some(200),
                last_bytes: Some(67_108_864),
                ..Default::default()
            },
        )
        .await,
    );
    let sent = rig.fake.calls();
    assert_eq!(sent.len(), 5, "{sent:?}");
    assert!(
        sent[0].ends_with("tail -c '+9223372036854775808' <&3 | head -c 65536"),
        "{}",
        sent[0]
    );
    assert!(
        sent[4].contains("tail -c 67108864 <&3 | grep -a -F -n -m 201 -- 'x'"),
        "{}",
        sent[4]
    );
    for c in &sent {
        check(c);
    }
}

/// A host id, root alias or registered id that is not known is refused before anything is sent, and the tools that
/// work on local state never reach a host at all.
#[tokio::test]
async fn unknown_ids_and_local_tools_send_nothing() {
    let rig = rig(same);
    let ctx = &rig.ctx;
    for v in HOSTILE.iter().copied().chain(["h2", "nope"]) {
        let (h, root, p) = (v.to_owned(), "app".to_owned(), "plain".to_owned());
        drop(
            ssh_files_list(
                ctx,
                FilesListParams {
                    host_id: h.clone(),
                    root: root.clone(),
                    path: p.clone(),
                    ..Default::default()
                },
            )
            .await,
        );
        drop(
            ssh_file_read(
                ctx,
                FileReadParams {
                    host_id: H.into(),
                    root: v.into(),
                    path: p.clone(),
                    ..Default::default()
                },
            )
            .await,
        );
        drop(
            ssh_transfer_download(
                ctx,
                TransferDownloadParams {
                    host_id: H.into(),
                    root: v.into(),
                    path: p,
                    ..Default::default()
                },
            )
            .await,
        );
        drop(
            ssh_host_inspect(
                ctx,
                HostInspectParams {
                    host_id: h.clone(),
                    ..Default::default()
                },
            )
            .await,
        );
        drop(
            ssh_process_list(
                ctx,
                ProcessListParams {
                    host_id: h.clone(),
                    ..Default::default()
                },
            )
            .await,
        );
        drop(
            ssh_logs_search(
                ctx,
                LogsSearchParams {
                    host_id: H.into(),
                    source_id: v.into(),
                    pattern: "x".into(),
                    ..Default::default()
                },
            )
            .await,
        );
        drop(
            ssh_capabilities_get(
                ctx,
                CapabilitiesParams {
                    host_id: Some(h),
                    ..Default::default()
                },
            )
            .await,
        );
        drop(
            ssh_artifact_read(
                ctx,
                ArtifactReadParams {
                    artifact_id: v.into(),
                    ..Default::default()
                },
            )
            .await,
        );
        drop(
            ssh_operation_get(
                ctx,
                OperationGetParams {
                    operation_id: v.into(),
                    ..Default::default()
                },
            )
            .await,
        );
        drop(
            ssh_operation_cancel(
                ctx,
                OperationCancelParams {
                    operation_id: v.into(),
                    ..Default::default()
                },
            )
            .await,
        );
    }
    ssh_hosts_list(ctx, HostsListParams::default()).await.unwrap();
    ssh_capabilities_get(
        ctx,
        CapabilitiesParams {
            host_id: Some(H.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(rig.fake.calls(), Vec::<String>::new());
}

/// The checks above are only worth something if they fail on a bad command. Each of these must be rejected.
#[test]
fn the_checks_reject_what_they_claim_to() {
    let rejected = |cmd: &str| std::panic::catch_unwind(|| check(cmd)).is_err();
    for bad in [
        "find '.' -mindepth 1 -delete",
        "find '.' -exec rm {} +",
        "find '.' -fprintf '/tmp/x' '%p'",
        "find '/etc' -maxdepth 1 -printf '%p'",
        "curl -q -sS -o '/tmp/out' -- 'http://127.0.0.1/'",
        "curl -q -sS --output '/dev/null' -- 'http://127.0.0.1/'",
        "curl -q -sS -T '/etc/passwd' -- 'http://127.0.0.1/'",
        "curl -q -sS -o '/dev/null' 'http://127.0.0.1/'",
        "curl -q -sS -o '/dev/null' -- 'file:///etc/passwd'",
        "stat -c %F -- '-'",
        "stat -c %F -- '-rf'",
        "stat -c %F '-L'",
        "ps -u '-e' -o pid=,ppid=,user=,pcpu=,pmem=,etimes=,comm=,args=",
        "grep -a -F -n -m 51 '-f/etc/shadow'",
        "grep -a -F -n -m 51 -- 'x' '/etc/shadow'",
        "grep -a -F -n -m 51 -- 'x' > '/tmp/out'",
        "grep -a -F -n -m 51 -- 'x' >/tmp/out",
        "cat <&3 | sh",
        "cat <&3; rm -rf /",
        "cat '/etc/shadow'",
        "exec 3< '-'",
        "exec 3< '/etc/shadow'",
        "nproc &",
        "(nproc)",
        "hostname; eval x",
        "sort -z -o '/tmp/x'",
        "systemctl stop -- 'app.service'",
        "systemctl show --no-pager -p Id 'app.service'",
        "tail -c '+1; reboot' <&3",
        "head -n 5 '/etc/shadow'",
        "tee '/tmp/x'",
    ] {
        assert!(rejected(bad), "the checks accepted: {bad}");
    }
    // Text that escapes its quotes shows up as fixed text, and a value inside double quotes is not quoted at all.
    assert_ne!(
        skeleton("grep -a -F -n -m 51 -- 'a'; reboot; ''"),
        skeleton("grep -a -F -n -m 51 -- 'plain'")
    );
    assert_eq!(
        skeleton("grep -a -F -n -m 51 -- 'a'\\''; reboot; '\\'''"),
        skeleton("grep -a -F -n -m 51 -- 'plain'")
    );
    assert!(std::panic::catch_unwind(|| lex("stat -c %F -- \"'$(reboot)'\"")).is_err());
    assert!(std::panic::catch_unwind(|| lex("stat -c %F -- x'./plain'")).is_err());
    assert!(std::panic::catch_unwind(|| lex("stat -c %F -- './plain'x")).is_err());
}
