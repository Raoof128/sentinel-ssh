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

/// Runs `main` only if `stat -c %F` (which does not follow a final symlink) reports `expected` for `absolute_path`.
/// Otherwise prints [`KIND_MISMATCH`] to stderr and exits [`KIND_MISMATCH_EXIT`].
pub fn kind_guard(expected: &'static str, absolute_path: &str, main: RemoteCommand) -> RemoteCommand {
    RemoteCommand::wrap(
        format!("if [ \"$(stat -c %F -- {})\" = \"{expected}\" ]; then ", shell_quote(absolute_path)),
        main,
        &format!("; else echo {KIND_MISMATCH} >&2; exit {KIND_MISMATCH_EXIT}; fi"),
    )
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

    #[test]
    fn kind_guard_shape() {
        let r = kind_guard("regular file", "/srv/app/a", RemoteCommand::new("cat").flag("--").arg("/srv/app/a")).render();
        assert!(
            r.starts_with("if [ \"$(stat -c %F -- '/srv/app/a')\" = \"regular file\" ]; then cat -- '/srv/app/a'; else"),
            "{r}"
        );
        assert!(r.ends_with("exit 97; fi"), "{r}");
    }

    #[test]
    fn guards_behave_in_sh() {
        let d = std::env::temp_dir().join(format!("snt-guard-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("f");
        std::fs::write(&f, "hello").unwrap();
        let link = d.join("l");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&f, &link).unwrap();
        let run = |c: RemoteCommand| std::process::Command::new("/bin/sh").arg("-c").arg(c.render()).output().unwrap();
        // GNU stat is required for -c; skip the shell part where it is absent (macOS BSD stat).
        let gnu = std::process::Command::new("stat")
            .args(["-c", "%F", "/"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if gnu {
            let ok = run(kind_guard(
                "regular file",
                f.to_str().unwrap(),
                RemoteCommand::new("cat").flag("--").arg(f.to_str().unwrap()),
            ));
            assert_eq!(ok.stdout, b"hello");
            let bad = run(kind_guard(
                "regular file",
                link.to_str().unwrap(),
                RemoteCommand::new("cat").flag("--").arg(link.to_str().unwrap()),
            ));
            assert_eq!(bad.status.code(), Some(97));
            let big = run(size_guard(f.to_str().unwrap(), 2, RemoteCommand::new("true")));
            assert_eq!(big.status.code(), Some(98));
        }
        std::fs::remove_dir_all(&d).unwrap();
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
