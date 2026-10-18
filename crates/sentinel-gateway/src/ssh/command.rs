//! The only constructor of remote command strings (spec §5.1).
//!
//! OpenSSH sends the remote command as one string interpreted by the account's login shell, so arguments are single-quoted
//! here and programs come from a fixed allowlist. The target account's login shell must be POSIX `sh` compatible.

use sentinel_core::scope::shell_quote;

/// Remote programs the observer adapters may invoke.
pub const PROGRAMS: &[&str] = &[
    "cat",
    "curl",
    "df",
    "du",
    "find",
    "free",
    "grep",
    "head",
    "hostname",
    "nproc",
    "printf",
    "ps",
    "sha256sum",
    "sort",
    "stat",
    "systemctl",
    "tail",
    "true",
    "uname",
];

/// Separates sections of multi-command output.
pub const MARKER: &str = "--SENTINEL--";
/// `kind_guard` refusal: stderr token and exit status.
pub const KIND_MISMATCH: &str = "SENTINEL_KIND_MISMATCH";
pub const KIND_MISMATCH_EXIT: i32 = 97;
/// `scope_guard` refusals: the target's parent resolves outside the root, or the root itself is missing.
pub const SCOPE_ESCAPE: &str = "SENTINEL_SCOPE_ESCAPE";
pub const SCOPE_ESCAPE_EXIT: i32 = 96;
pub const ROOT_MISSING: &str = "SENTINEL_ROOT_MISSING";
pub const ROOT_MISSING_EXIT: i32 = 95;
/// `size_guard` refusal: stderr token and exit status.
pub const TOO_LARGE: &str = "SENTINEL_TOO_LARGE";
pub const TOO_LARGE_EXIT: i32 = 98;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommand {
    text: String,
    programs: Vec<&'static str>,
}

fn is_safe_flag(f: &str) -> bool {
    !f.is_empty() && f.chars().all(|c| c.is_ascii_alphanumeric() || "-=,._%:+/".contains(c))
}

impl RemoteCommand {
    /// Panics if `program` is not in [`PROGRAMS`]: a programming error, never reachable from agent input.
    pub fn new(program: &'static str) -> Self {
        assert!(PROGRAMS.contains(&program), "remote program '{program}' is not allowlisted");
        Self {
            text: program.to_owned(),
            programs: vec![program],
        }
    }

    /// A static flag. Panics on characters with shell meaning.
    pub fn flag(mut self, f: &'static str) -> Self {
        assert!(is_safe_flag(f), "unsafe flag literal '{f}'");
        self.text.push(' ');
        self.text.push_str(f);
        self
    }

    /// A numeric argument, rendered unquoted.
    pub fn num(mut self, n: u64) -> Self {
        self.text.push(' ');
        self.text.push_str(&n.to_string());
        self
    }

    /// Any value, single-quoted.
    pub fn arg(mut self, a: &str) -> Self {
        self.text.push(' ');
        self.text.push_str(&shell_quote(a));
        self
    }

    pub fn pipe(self, next: RemoteCommand) -> Self {
        self.join(" | ", next)
    }

    pub fn then(self, next: RemoteCommand) -> Self {
        self.join("; ", next)
    }

    fn join(mut self, sep: &str, next: RemoteCommand) -> Self {
        self.text.push_str(sep);
        self.text.push_str(&next.text);
        self.programs.extend(next.programs);
        self
    }

    pub fn render(&self) -> String {
        self.text.clone()
    }

    /// Allowlisted programs this command invokes, in order (for capability error messages).
    pub fn programs(&self) -> &[&'static str] {
        &self.programs
    }

    /// `printf '\n--SENTINEL--\n'`
    pub fn marker() -> Self {
        RemoteCommand::new("printf").arg(&format!("\n{MARKER}\n"))
    }

    fn wrap(prefix: String, main: RemoteCommand, suffix: &str) -> Self {
        let mut programs = vec!["stat"];
        programs.extend(main.programs);
        Self {
            text: format!("{prefix}{}{suffix}", main.text),
            programs,
        }
    }
}

/// Runs `main` only if `stat -c %F` (which does not follow a final symlink) reports `expected` for `absolute_path`
/// ("regular file" also accepts GNU's "regular empty file"). Otherwise prints [`KIND_MISMATCH`] to stderr and exits
/// [`KIND_MISMATCH_EXIT`].
pub fn kind_guard(expected: &'static str, absolute_path: &str, main: RemoteCommand) -> RemoteCommand {
    let pattern = if expected == "regular file" {
        "\"regular file\"|\"regular empty file\")".to_owned()
    } else {
        format!("\"{expected}\")")
    };
    RemoteCommand::wrap(
        format!("case \"$(stat -c %F -- {})\" in {pattern} ", shell_quote(absolute_path)),
        main,
        &format!(";; *) echo {KIND_MISMATCH} >&2; exit {KIND_MISMATCH_EXIT};; esac"),
    )
}

/// Containment for root-scoped paths (spec §7.1 #8-10, §9.4). Resolves the root and the target's parent directory with
/// `realpath -e` on the host and runs the rest only if the parent is the root or inside it, so a symlinked parent
/// directory cannot lead outside. The final component is then checked with [`kind_guard`] when `expected` is given
/// (a final symlink is refused there). Check and use are separate commands: a concurrent rename on the host can still
/// race them, which only the Stage 2 broker's descriptor-relative opens close.
pub fn scope_guard(root: &str, target: &str, expected: Option<&'static str>, main: RemoteCommand) -> RemoteCommand {
    let inner = match expected {
        Some(kind) => kind_guard(kind, target, main),
        None => main,
    };
    let mut prefix = format!(
        "r=$(realpath -e -- {}) || {{ echo {ROOT_MISSING} >&2; exit {ROOT_MISSING_EXIT}; }}; ",
        shell_quote(root)
    );
    if target != root {
        let parent = target.rsplit_once('/').map(|(p, _)| p).filter(|p| !p.is_empty()).unwrap_or("/");
        prefix.push_str(&format!(
            "p=$(realpath -e -- {}) || {{ echo {KIND_MISMATCH} >&2; exit {KIND_MISMATCH_EXIT}; }}; \
             case \"$p/\" in \"$r\"/*) ;; *) echo {SCOPE_ESCAPE} >&2; exit {SCOPE_ESCAPE_EXIT};; esac; ",
            shell_quote(parent)
        ));
    }
    let mut programs = vec!["realpath"];
    programs.extend(inner.programs);
    RemoteCommand {
        text: format!("{prefix}{}", inner.text),
        programs,
    }
}

/// Runs `main` only if the file is at most `max_bytes`. Otherwise prints [`TOO_LARGE`] and exits [`TOO_LARGE_EXIT`].
pub fn size_guard(absolute_path: &str, max_bytes: u64, main: RemoteCommand) -> RemoteCommand {
    RemoteCommand::wrap(
        format!("if [ \"$(stat -c %s -- {})\" -le {max_bytes} ]; then ", shell_quote(absolute_path)),
        main,
        &format!("; else echo {TOO_LARGE} >&2; exit {TOO_LARGE_EXIT}; fi"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_quoted() {
        assert_eq!(
            RemoteCommand::new("grep")
                .flag("-F")
                .flag("-n")
                .arg("it's")
                .arg("/srv/app/x y.log")
                .render(),
            "grep -F -n 'it'\\''s' '/srv/app/x y.log'"
        );
    }

    /// GNU stat reports a zero-byte file as "regular empty file"; a guard on "regular file" must accept it.
    #[test]
    fn regular_file_guard_accepts_empty_files() {
        let r = kind_guard("regular file", "/srv/app/e", RemoteCommand::new("true")).render();
        assert!(r.contains("\"regular file\"|\"regular empty file\")"), "{r}");
        let d = kind_guard("directory", "/srv/app", RemoteCommand::new("true")).render();
        assert!(!d.contains("empty"), "{d}");
    }

    #[test]
    fn kind_guard_shape() {
        let r = kind_guard("regular file", "/srv/app/a", RemoteCommand::new("cat").flag("--").arg("/srv/app/a")).render();
        assert!(
            r.starts_with("case \"$(stat -c %F -- '/srv/app/a')\" in \"regular file\"|\"regular empty file\") cat -- '/srv/app/a';; *)"),
            "{r}"
        );
        assert!(r.ends_with("exit 97;; esac"), "{r}");
    }

    #[test]
    #[should_panic(expected = "not allowlisted")]
    fn unlisted_program_panics() {
        let _ = RemoteCommand::new("rm");
    }

    #[test]
    #[should_panic(expected = "unsafe flag")]
    fn unsafe_flag_panics() {
        let _ = RemoteCommand::new("ps").flag("-e; reboot");
    }

    #[test]
    fn programs_are_tracked() {
        let c = RemoteCommand::new("du")
            .flag("-x")
            .pipe(RemoteCommand::new("sort"))
            .then(RemoteCommand::marker());
        assert_eq!(c.programs(), ["du", "sort", "printf"]);
    }
}
