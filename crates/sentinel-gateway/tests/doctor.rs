//! `sentinel-ssh doctor`: every check reports a clear failure, and none of them touches a remote host except `--connect`.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sentinel_gateway::doctor::{DoctorReport, run_doctor};
use sentinel_testkit::configs::{TEST_HOST_KEY, TestDirs, fake_identity, fake_ssh_script, minimal_config_toml, write_private};

struct Fx {
    dirs: TestDirs,
    identity: PathBuf,
}

fn fx() -> Fx {
    let dirs = TestDirs::new();
    let identity = fake_identity(dirs.state.path());
    Fx { dirs, identity }
}

impl Fx {
    fn config(&self, edit: impl Fn(String) -> String) -> PathBuf {
        let p = self.dirs.state.path().join("config.toml");
        write_private(&p, &edit(minimal_config_toml(TEST_HOST_KEY, &self.identity, &self.dirs)));
        p
    }
    fn with_ssh(&self, body: &str) -> PathBuf {
        let bin = fake_ssh_script(self.dirs.state.path(), "fake-ssh", body);
        self.config(|t| t.replace("ssh_binary = \"/usr/bin/ssh\"", &format!("ssh_binary = \"{}\"", bin.display())))
    }
}

fn check<'a>(r: &'a DoctorReport, name: &str) -> &'a sentinel_gateway::doctor::DoctorCheck {
    r.checks
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no check {name}: {}", r.render()))
}

#[test]
fn render_lists_every_check_with_its_status() {
    let f = fx();
    let r = run_doctor(&f.config(|t| t), false);
    let text = r.render();
    assert!(text.lines().count() == r.checks.len());
    assert!(text.contains("[ok] config.permissions: "), "{text}");
}

#[test]
fn identity_file_with_open_permissions_fails() {
    let f = fx();
    std::fs::set_permissions(&f.identity, std::fs::Permissions::from_mode(0o644)).unwrap();
    let r = run_doctor(&f.config(|t| t), false);
    let c = check(&r, "host.h1.identity");
    assert!(!c.ok && c.detail.contains("0600"), "{c:?}");
    assert!(!r.ok());
}

#[test]
fn old_or_foreign_ssh_clients_fail() {
    let f = fx();
    let r = run_doctor(&f.with_ssh("echo 'OpenSSH_7.4p1, OpenSSL 1.0.2k' >&2"), false);
    let c = check(&r, "ssh.binary");
    assert!(!c.ok && c.detail.contains("8.9 or newer"), "{c:?}");
    let r = run_doctor(&f.with_ssh("echo 'Dropbear v2022.83' >&2"), false);
    let c = check(&r, "ssh.binary");
    assert!(!c.ok && c.detail.contains("not an OpenSSH client"), "{c:?}");
    let r = run_doctor(
        &f.config(|t| t.replace("ssh_binary = \"/usr/bin/ssh\"", "ssh_binary = \"/nonexistent/ssh\"")),
        false,
    );
    assert!(!check(&r, "ssh.binary").ok);
}

#[test]
fn open_private_directories_fail() {
    let f = fx();
    let art = f.dirs.state.path().join("artifacts");
    std::fs::create_dir_all(&art).unwrap();
    std::fs::set_permissions(&art, std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = run_doctor(&f.config(|t| t), false);
    let c = check(&r, "dirs.artifact");
    assert!(!c.ok && c.detail.contains("0700"), "{c:?}");
}

#[test]
fn connect_reports_unreachable_hosts_and_missing_identities() {
    let f = fx();
    // TEST-NET address on a closed local port: ssh exits 255 without any network side effects.
    let cfg = f.config(|t| t.replace("address = \"203.0.113.10\"\nport = 22", "address = \"127.0.0.1\"\nport = 1"));
    let r = run_doctor(&cfg, true);
    let c = check(&r, "host.h1.connect");
    assert!(!c.ok && c.detail.contains("ConnectionFailed"), "{c:?}");
    std::fs::remove_file(&f.identity).unwrap();
    let r = run_doctor(&cfg, true);
    let c = check(&r, "host.h1.connect");
    assert!(!c.ok && c.detail.contains("ConfigInvalid"), "{c:?}");
}

#[test]
fn connect_with_an_unusable_runtime_dir_fails_cleanly() {
    let f = fx();
    let run = f.dirs.run.path().join("r");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = run_doctor(&f.config(|t| t), true);
    assert!(!check(&r, "dirs.runtime").ok);
    let c = check(&r, "connect");
    assert!(!c.ok && c.detail.contains("0700"), "{c:?}");
}

#[test]
fn an_ssh_binary_others_can_modify_fails() {
    let f = fx();
    let cfg = f.with_ssh("echo 'OpenSSH_10.3p1' >&2");
    std::fs::set_permissions(f.dirs.state.path().join("fake-ssh"), std::fs::Permissions::from_mode(0o777)).unwrap();
    let r = run_doctor(&cfg, false);
    let c = check(&r, "ssh.binary");
    assert!(!c.ok && c.detail.contains("writable by other users"), "{c:?}");
}
