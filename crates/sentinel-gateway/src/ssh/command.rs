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

/// Refusals printed by the containment prologue: stderr token and exit status.
pub const KIND_MISMATCH: &str = "SENTINEL_KIND_MISMATCH";
pub const KIND_MISMATCH_EXIT: i32 = 97;
pub const SCOPE_ESCAPE: &str = "SENTINEL_SCOPE_ESCAPE";
pub const SCOPE_ESCAPE_EXIT: i32 = 96;
pub const ROOT_MISSING: &str = "SENTINEL_ROOT_MISSING";
pub const ROOT_MISSING_EXIT: i32 = 95;
pub const HARDLINK: &str = "SENTINEL_HARDLINK";
pub const HARDLINK_EXIT: i32 = 94;
pub const EXCLUDED: &str = "SENTINEL_EXCLUDED";
pub const EXCLUDED_EXIT: i32 = 93;
pub const NESTED_EXCLUDED: &str = "SENTINEL_NESTED_EXCLUDED";
pub const NESTED_EXCLUDED_EXIT: i32 = 90;
pub const MISSING: &str = "SENTINEL_MISSING";
pub const MISSING_EXIT: i32 = 91;
pub const NO_ACCESS: &str = "SENTINEL_NO_ACCESS";
pub const NO_ACCESS_EXIT: i32 = 92;
pub const TOO_LARGE: &str = "SENTINEL_TOO_LARGE";
pub const TOO_LARGE_EXIT: i32 = 98;

/// A per-call section separator. The nonce is random, so remote content (a file or directory name, a log line) cannot
/// contain it and cannot split or hide sections (red team: marker spoofing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker(String);

impl Marker {
    pub fn new() -> Self {
        Self(format!("--SENTINEL-{}--", uuid::Uuid::new_v4().simple()))
    }

    /// `printf '\n<marker>\n'`
    pub fn cmd(&self) -> RemoteCommand {
        RemoteCommand::new("printf").arg(&format!("\n{}\n", self.0))
    }

    fn separator(&self) -> String {
        format!("\n{}\n", self.0)
    }

    /// Splits text into sections, trimming surrounding newlines.
    pub fn sections<'a>(&self, text: &'a str) -> Vec<&'a str> {
        text.split(&self.separator()).map(|s| s.trim_matches('\n')).collect()
    }

    /// Splits at the first marker, leaving the bytes after it exact. `None` if the marker is absent.
    pub fn split_header<'a>(&self, out: &'a [u8]) -> Option<(String, &'a [u8])> {
        let sep = self.separator();
        let pos = out.windows(sep.len()).position(|w| w == sep.as_bytes())?;
        Some((String::from_utf8_lossy(&out[..pos]).trim().to_owned(), &out[pos + sep.len()..]))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Marker {
    fn default() -> Self {
        Self::new()
    }
}

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

    /// Appends the `! -samefile <root>` tests a [`Pin::Dir`] prologue collected; only for a `find` expression.
    pub fn skip_excluded(mut self) -> Self {
        self.text.push_str(" \"$@\"");
        self
    }

    /// `printf '%s\n' "$$"`: the remote shell's own pid, so its processes can be told apart from the host's.
    pub fn shell_pid() -> Self {
        let mut c = RemoteCommand::new("printf").arg("%s\n");
        c.text.push_str(" \"$$\"");
        c
    }

    /// Reads standard input from descriptor 3, the file a [`Pin::File`] prologue opened and verified.
    pub fn stdin_fd3(mut self) -> Self {
        self.text.push_str(" <&3");
        self
    }

    fn prefixed(prefix: String, extra: &[&'static str], main: RemoteCommand) -> Self {
        let mut programs = extra.to_vec();
        programs.extend(main.programs);
        Self {
            text: format!("{prefix}{}", main.text),
            programs,
        }
    }
}

/// How a contained command reaches its target once [`contained`] has pinned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin {
    /// The target directory becomes the working directory; the command names it `.`. Excluded roots inside it are
    /// collected as `! -samefile <root>` in the positional parameters, for a `find` built with
    /// [`RemoteCommand::skip_excluded`] to drop (red team: nested excluded roots).
    Dir,
    /// As [`Pin::Dir`] for commands that recurse (`du`): refused outright when an excluded root lies inside the
    /// target, because the command cannot skip a subtree exactly.
    Tree,
    /// The target entry itself, not followed; the command runs in its parent and names it by [`entry_name`].
    Entry,
    /// The target regular file, opened once on descriptor 3; the command reads only `<&3` or `/dev/fd/3`.
    File,
}

/// Shell helpers shared by every contained command. `rp` is `realpath -e` that keeps a trailing newline in a name
/// (command substitution would strip it, letting `/srv/app<NL>` pass as `/srv/app`) and refuses names containing one.
const PRELUDE: &str = "NL='\n'; \
rp() { o=$(realpath -e -- \"$1\" && echo x) || return 1; o=${o%x}; o=${o%\"$NL\"}; \
case $o in *\"$NL\"*) return 1;; esac; printf '%s' \"$o\"; }; \
deny() { echo \"$1\" >&2; exit \"$2\"; }; \
inside() { [ \"$2\" = / ] && return 0; case \"$1/\" in \"$2\"/*) return 0;; esac; return 1; }; \
enter() { cd -P -- \"$1\" 2>/dev/null && return 0; [ -e \"$1\" ] || deny SENTINEL_MISSING 91; \
[ -d \"$1\" ] && deny SENTINEL_NO_ACCESS 92; deny SENTINEL_KIND_MISMATCH 97; }; ";

/// The name a [`Pin::Entry`] or [`Pin::File`] command uses for its target: the last path component, or `.` for the root.
pub fn entry_name(root: &str, target: &str) -> String {
    if target == root {
        ".".to_owned()
    } else {
        target.rsplit('/').next().unwrap_or(".").to_owned()
    }
}

fn deny(token: &str, code: i32) -> String {
    format!("deny {token} {code}")
}

fn exclusions(var: &str, excluded: &[String]) -> String {
    excluded
        .iter()
        .map(|x| {
            format!(
                "if x=$(rp {}); then if inside \"${var}\" \"$x\"; then {}; fi; fi; ",
                shell_quote(x),
                deny(EXCLUDED, EXCLUDED_EXIT)
            )
        })
        .collect()
}

/// Containment for root-scoped paths (spec §7.1 #8-10, §7.3.6 "no scope escape", §9.4).
///
/// The target is resolved and pinned on the host before `main` runs, so `main` never resolves the path again:
/// * the root is resolved with `realpath -e`;
/// * the shell `cd -P`s into the target directory ([`Pin::Dir`]) or the target's parent, and `pwd -P` must be inside
///   the resolved root and outside every `excluded` root (roots this call may not read or export);
/// * for [`Pin::File`] the entry must be a regular file (not a symlink, FIFO or device), is opened once on fd 3, and the
///   open descriptor itself must resolve inside the root, outside excluded roots, and have exactly one link.
///
/// A rename on the host after these checks cannot redirect `main`: directories are used through the working directory
/// and files through the already-open descriptor.
pub fn contained(root: &str, target: &str, pin: Pin, excluded: &[String], main: RemoteCommand) -> RemoteCommand {
    let mut p = String::from(PRELUDE);
    p.push_str(&format!(
        "r=$(rp {}) || {}; ",
        shell_quote(root),
        deny(ROOT_MISSING, ROOT_MISSING_EXIT)
    ));
    let (dir, entry) = match pin {
        Pin::Dir | Pin::Tree => (target.to_owned(), None),
        _ if target == root => (root.to_owned(), Some(".".to_owned())),
        _ => (
            target
                .rsplit_once('/')
                .map(|(d, _)| d)
                .filter(|d| !d.is_empty())
                .unwrap_or("/")
                .to_owned(),
            Some(entry_name(root, target)),
        ),
    };
    if matches!(pin, Pin::Dir | Pin::Tree) {
        // lstat first: refuse a final symlink and report a missing or non-directory target clearly.
        p.push_str(&format!(
            "[ \"$(stat -c %F -- {})\" = directory ] || {}; ",
            shell_quote(target),
            deny(KIND_MISMATCH, KIND_MISMATCH_EXIT)
        ));
    }
    p.push_str(&format!(
        "enter {}; w=$(rp .) || {}; inside \"$w\" \"$r\" || {}; ",
        shell_quote(&dir),
        deny(SCOPE_ESCAPE, SCOPE_ESCAPE_EXIT),
        deny(SCOPE_ESCAPE, SCOPE_ESCAPE_EXIT)
    ));
    p.push_str(&exclusions("w", excluded));
    match pin {
        Pin::Dir => {
            p.push_str("set --; ");
            // Every excluded root, nested or not: `-samefile` only ever matches that root's own inode.
            for x in excluded {
                p.push_str(&format!(
                    "if x=$(rp {}); then set -- \"$@\" ! -samefile \"$x\"; fi; ",
                    shell_quote(x)
                ));
            }
        }
        Pin::Tree => {
            for x in excluded {
                p.push_str(&format!(
                    "if x=$(rp {}); then if inside \"$x\" \"$w\"; then {}; fi; fi; ",
                    shell_quote(x),
                    deny(NESTED_EXCLUDED, NESTED_EXCLUDED_EXIT)
                ));
            }
        }
        Pin::Entry if entry.as_deref() != Some(".") => {
            // The entry is a plain name in the resolved directory, so `$w/<name>` is its real path unless it is a
            // symlink, which is described rather than followed. It must not be an excluded root itself.
            p.push_str(&format!("e=\"$w\"/{}; ", shell_quote(entry.as_deref().unwrap_or("."))));
            p.push_str(&exclusions("e", excluded));
        }
        _ => {}
    }
    if pin == Pin::File {
        let e = shell_quote(entry.as_deref().unwrap_or("."));
        p.push_str(&format!(
            "case \"$(stat -c %F -- {e})\" in \"regular file\"|\"regular empty file\") ;; *) {};; esac; exec 3< {e}; ",
            deny(KIND_MISMATCH, KIND_MISMATCH_EXIT),
        ));
        let fd_inside = format!(
            "{}inside \"$f\" \"$r\" || {}; {}",
            fd_path(),
            deny(SCOPE_ESCAPE, SCOPE_ESCAPE_EXIT),
            exclusions("f", excluded)
        );
        p.push_str(&fd_inside);
        p.push_str(&link_count_is_one());
        // Again after the link count: see `fd_path`.
        p.push_str(&fd_inside);
    }
    RemoteCommand::prefixed(p, &["realpath", "stat"], main)
}

/// Sets `$f` to the real path of the file open on descriptor 3, refusing a name the kernel reports as deleted.
///
/// Run both before and after [`link_count_is_one`]. A hard link to a secret, opened while the attacker's in-root name
/// existed, passes the first path check; the attacker then unlinks that name, the link count drops to 1, and the
/// count check passes too. An unlinked name never comes back, so a second check that still finds a live path inside
/// the root proves that name existed, and was the only one, when the count was taken. Linux shows an unlinked
/// descriptor's path with a " (deleted)" suffix; a real file named that way is refused as well, so a decoy cannot pose
/// as the live name (red team: swap race).
fn fd_path() -> String {
    format!(
        "f=$(rp /dev/fd/3) || {s}; case \"$f\" in *\" (deleted)\") {s};; esac; ",
        s = deny(SCOPE_ESCAPE, SCOPE_ESCAPE_EXIT)
    )
}

/// The file on descriptor 3 is a regular file with exactly one name.
fn link_count_is_one() -> String {
    format!(
        "case \"$(stat -L -c '%F|%h' /dev/fd/3)\" in \"regular file|1\"|\"regular empty file|1\") ;; \
         \"regular file|\"*|\"regular empty file|\"*) {};; *) {};; esac; ",
        deny(HARDLINK, HARDLINK_EXIT),
        deny(KIND_MISMATCH, KIND_MISMATCH_EXIT)
    )
}

/// A registered file outside any root (a log source): it must resolve to exactly the configured path, be a regular
/// file with one link, and is read only through descriptor 3 (red team: log source symlink).
pub fn exact_file(path: &str, main: RemoteCommand) -> RemoteCommand {
    let (dir, name) = path
        .rsplit_once('/')
        .map(|(d, n)| (if d.is_empty() { "/" } else { d }, n))
        .unwrap_or(("/", path));
    let mut p = String::from(PRELUDE);
    p.push_str(&format!(
        "enter {d}; w=$(rp .) || {s}; [ \"$w\" = {d} ] || {s}; \
         case \"$(stat -c %F -- {n})\" in \"regular file\"|\"regular empty file\") ;; *) {k};; esac; \
         exec 3< {n}; {fd}[ \"$f\" = {full} ] || {s}; {one}{fd}[ \"$f\" = {full} ] || {s}; ",
        d = shell_quote(dir),
        n = shell_quote(name),
        full = shell_quote(path),
        k = deny(KIND_MISMATCH, KIND_MISMATCH_EXIT),
        s = deny(SCOPE_ESCAPE, SCOPE_ESCAPE_EXIT),
        fd = fd_path(),
        one = link_count_is_one(),
    ));
    RemoteCommand::prefixed(p, &["realpath", "stat"], main)
}

/// Refuses unless the file open on descriptor 3 is at most `max_bytes` ([`TOO_LARGE`], exit [`TOO_LARGE_EXIT`]).
pub fn fd3_size_limit(max_bytes: u64, main: RemoteCommand) -> RemoteCommand {
    RemoteCommand::prefixed(
        format!(
            "[ \"$(stat -L -c %s /dev/fd/3)\" -le {max_bytes} ] || {}; ",
            deny(TOO_LARGE, TOO_LARGE_EXIT)
        ),
        &["stat"],
        main,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `inside` is plain POSIX sh, so its semantics are checked against the local /bin/sh.
    fn inside_sh(a: &str, b: &str) -> bool {
        let script = format!("{PRELUDE}inside {} {}", shell_quote(a), shell_quote(b));
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .status()
            .unwrap()
            .success()
    }

    /// Red team (swap race, found by e2e): a hard link opened while the attacker's in-root name existed passes the path
    /// check; unlinking that name then drops the link count to 1 before it is checked. The descriptor's path must be
    /// re-resolved after the link-count check, and a name the kernel reports as " (deleted)" refused.
    #[test]
    fn descriptor_path_is_rechecked_after_the_link_count() {
        let main = || RemoteCommand::new("cat").stdin_fd3();
        for c in [
            contained("/srv/app", "/srv/app/data/race", Pin::File, &["/srv/secrets".to_owned()], main()).render(),
            exact_file("/var/log/app/api.log", main()).render(),
        ] {
            let nlink = c.find("%F|%h").expect("link-count check");
            let last_rp = c.rfind("rp /dev/fd/3").expect("descriptor path check");
            assert!(last_rp > nlink, "path not re-checked after the link count: {c}");
            assert!(c.contains("*\" (deleted)\")"), "deleted names not refused: {c}");
        }
    }

    #[test]
    fn every_marker_has_its_own_nonce() {
        assert_ne!(Marker::default(), Marker::default());
    }

    #[test]
    fn inside_treats_the_filesystem_root_as_containing_everything() {
        assert!(inside_sh("/srv/app", "/srv/app"));
        assert!(inside_sh("/srv/app/x", "/srv/app"));
        assert!(!inside_sh("/srv/apple", "/srv/app"));
        assert!(!inside_sh("/srv", "/srv/app"));
        assert!(inside_sh("/srv/app", "/"));
        assert!(inside_sh("/", "/"));
        assert!(!inside_sh("/", "/srv"));
    }

    #[test]
    fn nested_exclusion_checks_use_inside() {
        let ex = vec!["/srv/app/vault".to_owned()];
        let dir = contained("/srv/app", "/srv/app", Pin::Dir, &ex, RemoteCommand::new("find").skip_excluded()).render();
        assert!(
            dir.contains("if x=$(rp '/srv/app/vault'); then set -- \"$@\" ! -samefile \"$x\"; fi;"),
            "{dir}"
        );
        let tree = contained("/srv/app", "/srv/app", Pin::Tree, &ex, RemoteCommand::new("du")).render();
        assert!(
            tree.contains("if inside \"$x\" \"$w\"; then deny SENTINEL_NESTED_EXCLUDED 90; fi;"),
            "{tree}"
        );
        assert!(
            !dir.contains("\"$w\"/*") && !tree.contains("\"$w\"/*"),
            "raw prefix patterns remain"
        );
    }

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
    fn file_pins_verify_the_open_descriptor() {
        let c = contained("/srv/app", "/srv/app/a/b", Pin::File, &[], RemoteCommand::new("cat").stdin_fd3()).render();
        assert!(c.contains("r=$(rp '/srv/app')"), "{c}");
        assert!(c.contains("enter '/srv/app/a'; w=$(rp .)"), "{c}");
        assert!(c.contains("exec 3< 'b'; f=$(rp /dev/fd/3)"), "{c}");
        assert!(c.contains("\"regular file|1\"|\"regular empty file|1\")"), "{c}");
        assert!(c.ends_with("cat <&3"), "{c}");
    }

    #[test]
    fn excluded_roots_are_checked_on_the_resolved_paths() {
        let c = contained(
            "/srv/app",
            "/srv/app/x",
            Pin::File,
            &["/srv/app/logs".into()],
            RemoteCommand::new("true"),
        )
        .render();
        assert!(
            c.contains("if x=$(rp '/srv/app/logs'); then if inside \"$w\" \"$x\"; then deny SENTINEL_EXCLUDED 93"),
            "{c}"
        );
        assert!(c.contains("if inside \"$f\" \"$x\""), "{c}");
    }

    #[test]
    fn the_root_itself_is_its_own_entry() {
        assert_eq!(entry_name("/srv/app", "/srv/app"), ".");
        assert_eq!(entry_name("/srv/app", "/srv/app/a/b"), "b");
        let c = contained("/srv/app", "/srv/app", Pin::Entry, &[], RemoteCommand::new("stat").arg(".")).render();
        assert!(c.contains("enter '/srv/app';"), "{c}");
    }

    #[test]
    fn markers_are_unique_and_split_exactly() {
        let (a, b) = (Marker::new(), Marker::new());
        assert_ne!(a, b);
        let text = format!("one\n\n{}\n\ntwo\n", a.as_str());
        assert_eq!(a.sections(&text), ["one", "two"]);
        assert_eq!(b.sections(&text).len(), 1, "another call's marker is just text");
        let out = format!("3\n{}\nab\n", a.as_str());
        let (head, body) = a.split_header(out.as_bytes()).unwrap();
        assert_eq!((head.as_str(), body), ("3", &b"ab\n"[..]));
        assert!(a.split_header(b"no marker").is_none());
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
            .then(Marker::new().cmd());
        assert_eq!(c.programs(), ["du", "sort", "printf"]);
    }
}
