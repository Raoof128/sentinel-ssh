use std::time::Duration;

use sentinel_core::error::ErrorCode;
use sentinel_gateway::tools::files::{
    Encoding, EntryKind, FileHashParams, FileReadParams, FileStatParams, FilesListParams, ssh_file_hash, ssh_file_read, ssh_file_stat,
    ssh_files_list,
};
use sentinel_gateway::tools::logs::{LogsSearchParams, PatternMode, ssh_logs_search};
use sentinel_testkit::ctx::ctx_with;
use sentinel_testkit::fake_backend::{FakeBackend, Script};

fn list(h: &str, root: &str, path: &str) -> FilesListParams {
    FilesListParams {
        host_id: h.into(),
        root: root.into(),
        path: path.into(),
        ..Default::default()
    }
}
fn read(h: &str, root: &str, path: &str, offset: Option<u64>, length: Option<u32>, encoding: Option<Encoding>) -> FileReadParams {
    FileReadParams {
        host_id: h.into(),
        root: root.into(),
        path: path.into(),
        offset,
        length,
        encoding,
        ..Default::default()
    }
}
fn stat(h: &str, root: &str, path: &str) -> FileStatParams {
    FileStatParams {
        host_id: h.into(),
        root: root.into(),
        path: path.into(),
        ..Default::default()
    }
}
fn hash(h: &str, root: &str, path: &str) -> FileHashParams {
    FileHashParams {
        host_id: h.into(),
        root: root.into(),
        path: path.into(),
        ..Default::default()
    }
}
fn search(h: &str, source: &str, pattern: &str) -> LogsSearchParams {
    LogsSearchParams {
        host_id: h.into(),
        source_id: source.into(),
        pattern: pattern.into(),
        ..Default::default()
    }
}
fn script(matches: &str, stdout: &[u8], stderr: &[u8], exit: i32) -> Script {
    Script {
        matches: matches.into(),
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
        exit,
        delay: Duration::ZERO,
        error: None,
    }
}

#[tokio::test]
async fn files_list_parses_newline_in_name() {
    let fake = FakeBackend::new().on(
        "find",
        b"f\t12\t1760745600.0\t644\tnew\nline.txt\0d\t4096\t1760745600.5\t755\tsub\0l\t4\t1760745600\t777\tesc\0".to_vec(),
    );
    let ctx = ctx_with(fake.clone());
    let e = ssh_files_list(&ctx, list("h1", "app", "")).await.unwrap();
    assert_eq!(e.data.entries.len(), 3);
    assert_eq!(e.data.entries[0].name, "esc");
    assert_eq!(e.data.entries[0].kind, EntryKind::Symlink);
    assert_eq!(e.data.entries[1].name, "new\\u{A}line.txt");
    assert_eq!(e.data.entries[1].bytes, 12);
    assert_eq!(e.data.entries[1].mode_octal, "644");
    assert_eq!(e.data.entries[2].kind, EntryKind::Dir);
    assert_eq!(e.data.content_trust, "untrusted");
    assert!(
        fake.calls()[0].contains("case \"$(stat -c %F -- '/srv/app')\" in \"directory\")"),
        "{}",
        fake.calls()[0]
    );
}

#[tokio::test]
async fn files_list_paginates_by_raw_name() {
    let fake = FakeBackend::new().on("find", b"f\t1\t1\t644\tc\0f\t1\t1\t644\ta\0f\t1\t1\t644\tb\0".to_vec());
    let ctx = ctx_with(fake);
    let e = ssh_files_list(
        &ctx,
        FilesListParams {
            max_entries: Some(2),
            ..list("h1", "app", "")
        },
    )
    .await
    .unwrap();
    assert_eq!(e.data.entries.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(e.next_cursor.as_deref(), Some("b"));
    let e = ssh_files_list(
        &ctx,
        FilesListParams {
            cursor: Some("b".into()),
            ..list("h1", "app", "")
        },
    )
    .await
    .unwrap();
    assert_eq!(e.data.entries.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["c"]);
    assert!(e.next_cursor.is_none());
}

#[tokio::test]
async fn files_list_without_gnu_find_is_capability_unsupported() {
    let fake = FakeBackend::new().on_script(script("find", b"", b"find: unrecognized: -printf\n", 1));
    let e = ssh_files_list(&ctx_with(fake), list("h1", "app", "")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::CapabilityUnsupported);
    assert!(e.message.contains("find"), "{}", e.message);
}

#[tokio::test]
async fn files_list_rejects_symlink_dir_via_guard() {
    let fake = FakeBackend::new().on_script(script("find", b"", b"SENTINEL_KIND_MISMATCH\n", 97));
    let e = ssh_files_list(&ctx_with(fake), list("h1", "app", "escape")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(e.message.contains("not a directory"), "{}", e.message);
}

#[tokio::test]
async fn missing_path_is_not_found() {
    let fake = FakeBackend::new().on_script(script(
        "find",
        b"",
        b"stat: cannot statx '/srv/app/nope': No such file or directory\nSENTINEL_KIND_MISMATCH\n",
        97,
    ));
    assert_eq!(
        ssh_files_list(&ctx_with(fake), list("h1", "app", "nope")).await.unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn file_read_returns_range_and_eof() {
    let fake = FakeBackend::new().on("tail -c", b"1234\n--SENTINEL--\nhello world".to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_file_read(&ctx, read("h1", "app", "config/app.toml", Some(0), Some(11), None))
        .await
        .unwrap();
    assert_eq!(e.data.content, "hello world");
    assert_eq!(e.data.total_bytes, 1234);
    assert_eq!(e.data.bytes_returned, 11);
    assert!(!e.data.eof);
    assert!(
        fake.calls()[0].contains("tail -c '+1' -- '/srv/app/config/app.toml' | head -c 11"),
        "{}",
        fake.calls()[0]
    );
}

#[tokio::test]
async fn file_read_preserves_exact_bytes_including_newlines() {
    let fake = FakeBackend::new().on("tail -c", b"6\n\n--SENTINEL--\n\na\nb\n\n".to_vec());
    let e = ssh_file_read(&ctx_with(fake), read("h1", "app", "x", None, None, None))
        .await
        .unwrap();
    assert_eq!(e.data.content, "\na\nb\n\n");
    assert!(e.data.eof);
}

#[tokio::test]
async fn file_read_binary_requires_base64() {
    let fake = FakeBackend::new().on("tail -c", b"3\n--SENTINEL--\n\x00\xff\x01".to_vec());
    let ctx = ctx_with(fake);
    assert_eq!(
        ssh_file_read(&ctx, read("h1", "app", "data/blob.bin", None, None, None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotUtf8
    );
    let e = ssh_file_read(&ctx, read("h1", "app", "data/blob.bin", None, None, Some(Encoding::Base64)))
        .await
        .unwrap();
    assert_eq!(e.data.content, "AP8B");
}

#[tokio::test]
async fn file_read_length_capped_and_unreadable_root_denied() {
    let fake = FakeBackend::new();
    let ctx = ctx_with(fake.clone());
    assert_eq!(
        ssh_file_read(&ctx, read("h1", "app", "x", None, Some(65537), None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        ssh_file_read(&ctx, read("h1", "secrets", "x", None, None, None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        ssh_file_read(&ctx, read("h1", "app", "../secrets/key", None, None, None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn file_stat_symlink_reports_kind_only() {
    let fake = FakeBackend::new().on("stat -c", b"symbolic link|4|777|app|app|1760745600|1\n".to_vec());
    let e = ssh_file_stat(&ctx_with(fake), stat("h1", "app", "escape")).await.unwrap();
    assert_eq!(e.data.kind, EntryKind::Symlink);
    assert_eq!(e.data.owner, "app");
    assert_eq!(e.data.nlink, 1);
    assert!(!serde_json::to_string(&e).unwrap().contains("/etc"));
}

#[tokio::test]
async fn file_hash_parses_digest() {
    let digest = "ab".repeat(32);
    let fake = FakeBackend::new().on(
        "sha256sum",
        format!("1048576\n\n--SENTINEL--\n{digest}  /srv/app/data/blob.bin\n").into_bytes(),
    );
    let ctx = ctx_with(fake.clone());
    let e = ssh_file_hash(&ctx, hash("h1", "app", "data/blob.bin")).await.unwrap();
    assert_eq!(e.data.digest, digest);
    assert_eq!(e.data.bytes, 1_048_576);
    assert!(fake.calls()[0].contains("-le 268435456"), "{}", fake.calls()[0]);
}

#[tokio::test]
async fn file_hash_too_large_is_budget_exceeded() {
    let fake = FakeBackend::new().on_script(script("sha256sum", b"", b"SENTINEL_TOO_LARGE\n", 98));
    assert_eq!(
        ssh_file_hash(&ctx_with(fake), hash("h1", "app", "big")).await.unwrap_err().code,
        ErrorCode::BudgetExceeded
    );
}

#[tokio::test]
async fn logs_search_fixed_string_and_no_match() {
    let fake = FakeBackend::new().on_script(script("grep -F", b"", b"", 1));
    let ctx = ctx_with(fake.clone());
    let e = ssh_logs_search(&ctx, search("h1", "api", "a.*b")).await.unwrap();
    assert!(e.data.matches.is_empty());
    assert!(
        fake.calls()[0].contains("grep -F -n -m 51 -- 'a.*b' '/var/log/app/api.log'"),
        "{}",
        fake.calls()[0]
    );
}

#[tokio::test]
async fn logs_search_tail_window() {
    let fake = FakeBackend::new().on("grep -F", b"3:x\n".to_vec());
    let ctx = ctx_with(fake.clone());
    let e = ssh_logs_search(
        &ctx,
        LogsSearchParams {
            last_bytes: Some(1000),
            ..search("h1", "api", "x")
        },
    )
    .await
    .unwrap();
    assert!(e.data.line_numbers_relative_to_tail);
    assert!(
        fake.calls()[0].starts_with("tail -c 1000 -- '/var/log/app/api.log' | grep -F -n -m 51 -- 'x'"),
        "{}",
        fake.calls()[0]
    );
}

#[tokio::test]
async fn logs_search_latin1_line_is_replaced_with_warning() {
    let fake = FakeBackend::new().on("grep -F", b"12:caf\xe9 error\n".to_vec());
    let e = ssh_logs_search(&ctx_with(fake), search("h1", "api", "error")).await.unwrap();
    assert_eq!(e.data.matches[0].line_no, 12);
    assert_eq!(e.data.matches[0].text, "caf\u{FFFD} error");
    assert!(e.warnings.contains(&"non_utf8_replaced".to_string()));
}

#[tokio::test]
async fn logs_search_escapes_terminal_controls_and_caps_matches() {
    let mut out = String::new();
    for i in 1..=51 {
        out.push_str(&format!("{i}:line \x1b[31m{i}\n"));
    }
    let fake = FakeBackend::new().on("grep -F", out.into_bytes());
    let e = ssh_logs_search(&ctx_with(fake), search("h1", "api", "line")).await.unwrap();
    assert_eq!(e.data.matches.len(), 50);
    assert!(e.data.match_limit_reached);
    assert_eq!(e.data.matches[0].text, "line \\u{1B}[31m1");
}

#[tokio::test]
async fn logs_search_rejects_bad_patterns_and_unknown_sources() {
    let fake = FakeBackend::new();
    let ctx = ctx_with(fake.clone());
    assert_eq!(
        ssh_logs_search(
            &ctx,
            LogsSearchParams {
                pattern_mode: Some(PatternMode::Regex),
                ..search("h1", "api", "x")
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::CapabilityUnsupported
    );
    assert_eq!(
        ssh_logs_search(&ctx, search("h1", "api", "")).await.unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        ssh_logs_search(&ctx, search("h1", "api", "a\nb")).await.unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        ssh_logs_search(&ctx, search("h1", "api", &"x".repeat(257))).await.unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        ssh_logs_search(&ctx, search("h1", "auth", "x")).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert!(fake.calls().is_empty());
}

/// Final review #3: a path through a symlinked parent (escape -> /etc) must not leave the root. Every root-scoped tool
/// resolves the root and the target's parent with realpath before acting.
#[tokio::test]
async fn scope_escape_through_parent_symlink_is_denied() {
    let fake = FakeBackend::new().on_script(script("realpath", b"", b"SENTINEL_SCOPE_ESCAPE\n", 96));
    let ctx = ctx_with(fake.clone());
    let e = ssh_file_read(&ctx, read("h1", "app", "escape/passwd", None, None, None))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(e.message.contains("outside the registered root"), "{}", e.message);
    let c = &fake.calls()[0];
    assert!(c.starts_with("r=$(realpath -e -- '/srv/app') || "), "{c}");
    assert!(c.contains("p=$(realpath -e -- '/srv/app/escape') || "), "{c}");
    assert!(c.contains("case \"$p/\" in \"$r\"/*) ;;"), "{c}");
    for (name, res) in [
        ("files_list", ssh_files_list(&ctx, list("h1", "app", "escape/x")).await.map(|_| ())),
        (
            "file_stat",
            ssh_file_stat(&ctx, stat("h1", "app", "escape/passwd")).await.map(|_| ()),
        ),
        (
            "file_hash",
            ssh_file_hash(&ctx, hash("h1", "app", "escape/passwd")).await.map(|_| ()),
        ),
    ] {
        assert_eq!(res.unwrap_err().code, ErrorCode::PolicyDenied, "{name}");
    }
    assert!(
        fake.calls().iter().all(|c| c.starts_with("r=$(realpath -e -- '/srv/app')")),
        "{:?}",
        fake.calls()
    );
}

#[tokio::test]
async fn root_itself_needs_no_parent_check() {
    let fake = FakeBackend::new().on("find", b"".to_vec());
    let ctx = ctx_with(fake.clone());
    ssh_files_list(&ctx, list("h1", "app", "")).await.unwrap();
    let c = &fake.calls()[0];
    assert!(c.starts_with("r=$(realpath -e -- '/srv/app') || "), "{c}");
    assert!(!c.contains("p=$(realpath"), "{c}");
}

#[tokio::test]
async fn missing_root_on_host_is_reported() {
    let fake = FakeBackend::new().on_script(script(
        "realpath",
        b"",
        b"realpath: /srv/app: No such file or directory\nSENTINEL_ROOT_MISSING\n",
        95,
    ));
    let e = ssh_files_list(&ctx_with(fake), list("h1", "app", "")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::RemoteFailure);
    assert!(e.message.contains("registered root does not exist"), "{}", e.message);
}

/// Final review #2: a permission failure must not become an empty successful result.
#[tokio::test]
async fn unreadable_paths_are_errors_not_empty_results() {
    let ls = FakeBackend::new().on_script(script("find", b"", b"find: '/srv/app/private': Permission denied\n", 1));
    let e = ssh_files_list(&ctx_with(ls), list("h1", "app", "private")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::RemoteFailure);
    assert!(e.message.contains("permission denied"), "{}", e.message);
    let rd = FakeBackend::new().on_script(script(
        "tail -c",
        b"523\n\n--SENTINEL--\n",
        b"tail: cannot open '/srv/app/x' for reading: Permission denied\n",
        0,
    ));
    assert_eq!(
        ssh_file_read(&ctx_with(rd), read("h1", "app", "x", None, None, None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::RemoteFailure
    );
    let hs = FakeBackend::new().on_script(script(
        "sha256sum",
        b"523\n\n--SENTINEL--\n",
        b"sha256sum: /srv/app/x: Permission denied\n",
        1,
    ));
    assert_eq!(
        ssh_file_hash(&ctx_with(hs), hash("h1", "app", "x")).await.unwrap_err().code,
        ErrorCode::RemoteFailure
    );
    let lg = FakeBackend::new().on_script(script(
        "grep -F",
        b"",
        b"tail: cannot open '/var/log/app/api.log' for reading: Permission denied\n",
        1,
    ));
    let e = ssh_logs_search(
        &ctx_with(lg),
        LogsSearchParams {
            last_bytes: Some(100),
            ..search("h1", "api", "x")
        },
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::RemoteFailure);
}

/// Final review #7: errors never echo remote paths or stderr verbatim.
#[tokio::test]
async fn failure_messages_do_not_echo_remote_paths() {
    let fake = FakeBackend::new().on_script(script("find", b"", b"find: '/srv/app/secret-dir': Input/output error\n", 1));
    let e = ssh_files_list(&ctx_with(fake), list("h1", "app", "secret-dir")).await.unwrap_err();
    assert!(!e.message.contains("/srv/app"), "{}", e.message);
    assert!(!serde_json::to_string(&e).unwrap().contains("/srv/app"));
}

/// Final review #5: a default page must fit the default 8 KiB result inline, even as base64.
#[tokio::test]
async fn default_read_page_fits_the_default_result() {
    let fake = FakeBackend::new().on("tail -c", b"9999\n--SENTINEL--\nx".to_vec());
    let ctx = ctx_with(fake.clone());
    ssh_file_read(&ctx, read("h1", "app", "x", None, None, None)).await.unwrap();
    assert!(fake.calls()[0].contains("head -c 4096"), "{}", fake.calls()[0]);
}

/// Final review #6: a page that ends inside a multi-byte character is trimmed, not rejected.
#[tokio::test]
async fn utf8_page_boundary_is_trimmed_not_rejected() {
    let fake = FakeBackend::new().on("tail -c", b"3\n--SENTINEL--\na\xc3".to_vec());
    let e = ssh_file_read(&ctx_with(fake), read("h1", "app", "x", Some(0), Some(2), None))
        .await
        .unwrap();
    assert_eq!(e.data.content, "a");
    assert_eq!(e.data.bytes_returned, 1);
    assert!(!e.data.eof);
    // At end of file an incomplete sequence is genuinely invalid.
    let fake = FakeBackend::new().on("tail -c", b"2\n--SENTINEL--\na\xc3".to_vec());
    assert_eq!(
        ssh_file_read(&ctx_with(fake), read("h1", "app", "x", Some(0), Some(2), None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotUtf8
    );
}

/// Final review #10: a listing cut by the output cap is Partial, and no cut-off name is reported as an entry.
#[tokio::test]
async fn truncated_listing_is_partial_without_fabricated_names() {
    let mut out = Vec::new();
    for i in 0..12_000 {
        out.extend_from_slice(format!("f\t1\t1\t644\tfile-{i:05}-{}\0", "n".repeat(30)).as_bytes());
    }
    let fake = FakeBackend::new().on("find", out);
    let e = ssh_files_list(
        &ctx_with(fake),
        FilesListParams {
            max_entries: Some(500),
            ..list("h1", "app", "")
        },
    )
    .await
    .unwrap();
    assert_eq!(e.outcome, sentinel_core::envelope::Outcome::Partial);
    assert!(e.warnings.iter().any(|w| w == "listing_truncated"), "{:?}", e.warnings);
    assert!(
        e.data.entries.iter().all(|x| x.name.len() == "file-00000-".len() + 30),
        "a cut-off name was reported"
    );
}
