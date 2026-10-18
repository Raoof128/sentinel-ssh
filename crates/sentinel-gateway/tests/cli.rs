//! The `sentinel-ssh` binary: every subcommand, exit codes, default config locations and agent passthrough.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sentinel_testkit::configs::{TEST_HOST_KEY, TestDirs, fake_identity, fake_ssh_script, minimal_config_toml, write_private};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sentinel-ssh"))
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn write_config(dirs: &TestDirs, path: &Path, edit: impl Fn(String) -> String) -> PathBuf {
    let identity = fake_identity(dirs.state.path());
    write_private(path, &edit(minimal_config_toml(TEST_HOST_KEY, &identity, dirs)));
    path.to_path_buf()
}

#[test]
fn schemas_prints_all_tool_contracts() {
    let o = bin().arg("schemas").output().unwrap();
    assert!(o.status.success());
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 17);
}

#[test]
fn config_lint_accepts_good_and_rejects_bad_configs() {
    let dirs = TestDirs::new();
    let good = write_config(&dirs, &dirs.state.path().join("good.toml"), |t| t);
    let o = bin().args(["config", "lint", "--config"]).arg(&good).output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("ok: 1 host(s)"));
    let bad = write_config(&dirs, &dirs.state.path().join("bad.toml"), |t| {
        t.replace("schema_version = 1", "schema_version = 9")
    });
    let o = bin().args(["config", "lint", "--config"]).arg(&bad).output().unwrap();
    assert!(!o.status.success());
    assert!(text(&o).contains("unsupported schema_version 9"), "{}", text(&o));
}

#[test]
fn default_config_path_follows_xdg_then_home() {
    let dirs = TestDirs::new();
    let xdg = dirs.state.path().join("xdg");
    std::fs::create_dir_all(xdg.join("sentinel-ssh")).unwrap();
    write_config(&dirs, &xdg.join("sentinel-ssh/config.toml"), |t| t);
    let o = bin().args(["config", "lint"]).env("XDG_CONFIG_HOME", &xdg).output().unwrap();
    assert!(o.status.success(), "XDG: {}", text(&o));
    let home = dirs.state.path().join("home");
    std::fs::create_dir_all(home.join(".config/sentinel-ssh")).unwrap();
    write_config(&dirs, &home.join(".config/sentinel-ssh/config.toml"), |t| t);
    let o = bin()
        .args(["config", "lint"])
        .env_remove("XDG_CONFIG_HOME")
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(o.status.success(), "HOME: {}", text(&o));
}

#[test]
fn doctor_exit_code_matches_its_report() {
    let dirs = TestDirs::new();
    let cfg = write_config(&dirs, &dirs.state.path().join("c.toml"), |t| t);
    let o = bin().args(["doctor", "--config"]).arg(&cfg).output().unwrap();
    let out = text(&o);
    assert!(out.lines().all(|l| l.starts_with("[ok] ") || l.starts_with("[FAIL] ")), "{out}");
    assert_eq!(o.status.success(), !out.contains("[FAIL]"), "{out}");
    let o = bin().args(["doctor", "--config", "/nonexistent/c.toml"]).output().unwrap();
    assert!(!o.status.success());
    assert!(text(&o).contains("[FAIL] config.load"));
}

#[test]
fn doctor_reports_agent_socket_presence() {
    let dirs = TestDirs::new();
    let cfg = write_config(&dirs, &dirs.state.path().join("c.toml"), |t| {
        t.replace(
            &t[t.find("auth = {").unwrap()..t.find("}\n\n[hosts.roots.app]").unwrap() + 1],
            "auth = { method = \"agent\" }",
        )
    });
    let o = bin()
        .args(["doctor", "--config"])
        .arg(&cfg)
        .env("SSH_AUTH_SOCK", "/tmp/agent.sock")
        .output()
        .unwrap();
    assert!(
        text(&o).contains("[ok] host.h1.identity: ssh-agent via SSH_AUTH_SOCK"),
        "{}",
        text(&o)
    );
    let o = bin()
        .args(["doctor", "--config"])
        .arg(&cfg)
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .unwrap();
    assert!(
        text(&o).contains("[FAIL] host.h1.identity: SSH_AUTH_SOCK is not set"),
        "{}",
        text(&o)
    );
}

/// Agent auth must hand the agent socket (and nothing else from the environment) to the ssh client.
#[test]
fn agent_socket_is_passed_to_the_ssh_client() {
    let dirs = TestDirs::new();
    let marker = dirs.state.path().join("seen-sock");
    let script = fake_ssh_script(
        dirs.state.path(),
        "fake-ssh",
        &format!("printf '%s|%s' \"$SSH_AUTH_SOCK\" \"$SECRET_FROM_PARENT\" > '{}'", marker.display()),
    );
    let cfg = write_config(&dirs, &dirs.state.path().join("c.toml"), |t| {
        t.replace(
            &t[t.find("auth = {").unwrap()..t.find("}\n\n[hosts.roots.app]").unwrap() + 1],
            "auth = { method = \"agent\" }",
        )
        .replace("ssh_binary = \"/usr/bin/ssh\"", &format!("ssh_binary = \"{}\"", script.display()))
    });
    let o = bin()
        .args(["doctor", "--connect", "--config"])
        .arg(&cfg)
        .env("SSH_AUTH_SOCK", "/tmp/agent.sock")
        .env("SECRET_FROM_PARENT", "leak")
        .output()
        .unwrap();
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "/tmp/agent.sock|", "{}", text(&o));
}

#[test]
fn serve_with_a_bad_config_exits_with_an_error() {
    let o = bin().args(["serve", "--config", "/nonexistent/c.toml"]).output().unwrap();
    assert!(!o.status.success());
    assert!(text(&o).contains("sentinel-ssh: cannot read config file"), "{}", text(&o));
}
