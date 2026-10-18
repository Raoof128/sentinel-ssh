//! Path scoping, remote-shell quoting and display escaping (spec §5.1, §9.4).
//!
//! Paths are always `root alias + relative path`. A relative path is validated, never rewritten: a name that would need
//! "sanitising" is rejected instead (spec §9.4 last paragraph).

use crate::error::{ErrorCode, Result, SentinelError};
use crate::policy::RootPolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedPath {
    pub root_alias: String,
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

fn needs_escape(c: char) -> bool {
    let u = c as u32;
    u < 0x20
        || (0x7f..=0x9f).contains(&u)
        || (0x200b..=0x200f).contains(&u)
        || (0x202a..=0x202e).contains(&u)
        || (0x2066..=0x2069).contains(&u)
}

/// Escapes control, C1, zero-width and bidirectional-override characters so a displayed name cannot mislead (spec §9.4, §9.7).
pub fn display_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if needs_escape(c) {
            out.push_str(&format!("\\u{{{:X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
