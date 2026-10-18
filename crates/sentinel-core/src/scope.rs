//! Path scoping, remote-shell quoting and display escaping (spec §5.1, §9.4).
//!
//! Paths are always `root alias + relative path`. A relative path is validated, never rewritten: a name that would need
//! "sanitising" is rejected instead (spec §9.4 last paragraph).

use crate::error::{ErrorCode, Result, SentinelError};
use crate::policy::RootPolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedPath {
    pub root_alias: String,
    /// The registered root's absolute path.
    pub root_path: String,
    /// Empty for the root itself.
    pub relative: String,
    pub absolute: String,
}

fn invalid(msg: &str) -> SentinelError {
    SentinelError::new(ErrorCode::InvalidInput, msg).with_detail("field", "path")
}

pub fn resolve_scoped(root: &RootPolicy, relative: &str) -> Result<ScopedPath> {
    if relative.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
        return Err(invalid("path contains control characters"));
    }
    // Linux PATH_MAX and NAME_MAX: anything longer fails remotely anyway, after costing a round trip.
    if relative.len() > 4096 {
        return Err(invalid("path exceeds 4096 bytes"));
    }
    if relative.split('/').any(|c| c.len() > 255) {
        return Err(invalid("a path component exceeds 255 bytes"));
    }
    if relative.starts_with('/') {
        return Err(invalid("path must be relative to the root alias"));
    }
    let trimmed = if relative == "." {
        ""
    } else {
        relative.strip_suffix('/').unwrap_or(relative)
    };
    if !trimmed.is_empty() {
        for comp in trimmed.split('/') {
            match comp {
                "" => return Err(invalid("path contains an empty component")),
                "." | ".." => return Err(invalid("path contains '.' or '..' components")),
                _ => {}
            }
        }
    }
    let absolute = if trimmed.is_empty() {
        root.path.clone()
    } else {
        format!("{}/{}", root.path, trimmed)
    };
    Ok(ScopedPath {
        root_alias: root.alias.clone(),
        root_path: root.path.clone(),
        relative: trimmed.to_owned(),
        absolute,
    })
}

/// POSIX single-quote quoting. The result is one shell word whatever the input contains.
pub fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Cc (controls), Cf (format), Zl and Zp characters. Cf is listed explicitly from the Unicode 16 general-category table
/// rather than pulling in a Unicode-data crate.
fn needs_escape(c: char) -> bool {
    let u = c as u32;
    matches!(
        u,
        0x00..=0x1f
            | 0x7f..=0x9f
            | 0xad
            | 0x0600..=0x0605
            | 0x061c
            | 0x06dd
            | 0x070f
            | 0x0890..=0x0891
            | 0x08e2
            | 0x180e
            | 0x200b..=0x200f
            | 0x2028..=0x202e
            | 0x2060..=0x2064
            | 0x2066..=0x206f
            | 0xfeff
            | 0xfff9..=0xfffb
            | 0x110bd
            | 0x110cd
            | 0x13430..=0x1343f
            | 0x1bca0..=0x1bca3
            | 0x1d173..=0x1d17a
            | 0xe0001
            | 0xe0020..=0xe007f
    )
}

/// Escapes control, format (zero-width, bidirectional, tag), line- and paragraph-separator characters so a displayed name cannot mislead (spec §9.4, §9.7).
pub fn display_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' {
            // Escaped too, so a literal "\u{202E}" in a name never looks like an escaped U+202E.
            out.push_str("\\\\");
        } else if needs_escape(c) {
            out.push_str(&format!("\\u{{{:X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
