use proptest::prelude::*;
use sentinel_core::error::ErrorCode;
use sentinel_core::policy::RootPolicy;
use sentinel_core::scope::{display_escape, resolve_scoped, shell_quote};

fn app() -> RootPolicy {
    RootPolicy {
        alias: "app".into(),
        path: "/srv/app".into(),
        read: true,
        export: true,
    }
}

#[test]
fn resolves_relative_paths() {
    let p = resolve_scoped(&app(), "config/app.toml").unwrap();
    assert_eq!(p.absolute, "/srv/app/config/app.toml");
    assert_eq!(p.relative, "config/app.toml");
    assert_eq!(p.root_alias, "app");
    assert_eq!(resolve_scoped(&app(), "").unwrap().absolute, "/srv/app");
    assert_eq!(resolve_scoped(&app(), ".").unwrap().absolute, "/srv/app");
    assert_eq!(resolve_scoped(&app(), "logs/").unwrap().relative, "logs");
}

#[test]
fn rejects_escapes() {
    for bad in [
        "/etc/passwd",
        "../etc",
        "a/../../etc",
        "a//b",
        "a/./b",
        "a\0b",
        "a\nb",
        "\u{7f}",
        "..",
        "a/..",
    ] {
        assert_eq!(resolve_scoped(&app(), bad).unwrap_err().code, ErrorCode::InvalidInput, "{bad:?}");
    }
}

#[test]
fn preserves_unicode() {
    assert_eq!(resolve_scoped(&app(), "données ünï.txt").unwrap().relative, "données ünï.txt");
}

#[test]
fn quote_examples() {
    assert_eq!(shell_quote("a b"), "'a b'");
    assert_eq!(shell_quote("it's"), "'it'\\''s'");
    assert_eq!(shell_quote(""), "''");
    assert_eq!(shell_quote("-rf"), "'-rf'");
}

proptest! {
    #[test]
    fn quote_roundtrips_through_sh(s in "[^\0]{0,40}") {
        let out = std::process::Command::new("/bin/sh").arg("-c").arg(format!("printf %s {}", shell_quote(&s))).output().unwrap();
        prop_assert_eq!(String::from_utf8_lossy(&out.stdout), s);
    }
}

#[test]
fn display_escapes_controls_and_bidi() {
    assert_eq!(display_escape("a\u{202e}b\x1b[0m"), "a\\u{202E}b\\u{1B}[0m");
    assert_eq!(display_escape("plain/ünï"), "plain/ünï");
    assert_eq!(display_escape("new\nline"), "new\\u{A}line");
    assert_eq!(display_escape("\u{200b}\u{2066}\u{9b}"), "\\u{200B}\\u{2066}\\u{9B}");
}

#[test]
fn display_escapes_all_format_and_separator_chars() {
    // Zl, Zp and Cf characters (security review 2026-10-18): separators, Arabic letter mark, BOM, invisible operators,
    // deprecated format chars, soft hyphen, interlinear annotation and Unicode tag characters.
    for c in [
        '\u{2028}',
        '\u{2029}',
        '\u{061C}',
        '\u{FEFF}',
        '\u{2060}',
        '\u{2064}',
        '\u{206A}',
        '\u{206F}',
        '\u{00AD}',
        '\u{180E}',
        '\u{FFF9}',
        '\u{E0001}',
        '\u{E0041}',
    ] {
        let shown = display_escape(&format!("a{c}b"));
        assert_eq!(shown, format!("a\\u{{{:X}}}b", c as u32), "U+{:04X} not escaped", c as u32);
    }
}

/// Hardening: a literal backslash is escaped too, so a real file named `a\u{202E}b` cannot display like an escaped U+202E.
#[test]
fn display_escape_is_unambiguous() {
    assert_eq!(display_escape("a\\b"), "a\\\\b");
    assert_ne!(display_escape("a\\u{202E}b"), display_escape("a\u{202e}b"));
}
