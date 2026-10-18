use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sentinel_core::error::ErrorCode;
use sentinel_core::identity::HostId;
use sentinel_gateway::config::{Config, HostKey, load_config};
use sentinel_gateway::doctor::{run_doctor, run_doctor_with_system_config};
use sentinel_testkit::configs::{TEST_HOST_KEY, TestDirs, fake_identity, host_block, minimal_config_toml, write_private};

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
    fn minimal(&self) -> String {
        minimal_config_toml(TEST_HOST_KEY, &self.identity, &self.dirs)
    }
    fn path_of(&self, toml: &str) -> PathBuf {
        let p = self.dirs.state.path().join("config.toml");
        write_private(&p, toml);
        p
    }
    fn load(&self, toml: &str) -> sentinel_core::error::Result<Config> {
        load_config(&self.path_of(toml))
    }
}

fn write_with_mode(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn loads_minimal_config_with_defaults() {
    let f = fx();
    let c = f.load(&f.minimal()).unwrap();
    assert_eq!(c.gateway.budgets.max_active_operations, 64);
    assert_eq!(c.gateway.budgets.max_pending_operations, 128);
    assert_eq!(c.gateway.budgets.max_transfer_bytes, 268_435_456);
    assert_eq!(c.gateway.budgets.default_result_bytes, 8192);
    assert_eq!(c.gateway.budgets.max_result_bytes, 65536);
    assert_eq!(c.hosts[0].port, 22);
    assert_eq!(c.hosts[0].host_key.key_type, "ssh-ed25519");
}

#[test]
fn port_defaults_to_22() {
    let f = fx();
    let c = f.load(&f.minimal().replace("port = 22\n", "")).unwrap();
    assert_eq!(c.hosts[0].port, 22);
}

#[test]
fn world_readable_config_rejected() {
    let f = fx();
    let p = f.path_of(&f.minimal());
    write_with_mode(&p, 0o644);
    let e = load_config(&p).unwrap_err();
    assert_eq!(e.code, ErrorCode::ConfigInvalid);
    assert!(e.message.contains("0600"), "{}", e.message);
}

#[test]
fn host_key_with_hostname_prefix_is_rejected() {
    let f = fx();
    let e = f
        .load(&f.minimal().replace("ssh-ed25519 AAAA", "staging.example ssh-ed25519 AAAA"))
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ConfigInvalid);
    assert!(e.message.contains("<keytype> <base64>"), "{}", e.message);
    assert!("ssh-ed25519 not-base64!".parse::<HostKey>().is_err());
    assert!("ssh-ed25519".parse::<HostKey>().is_err());
    assert!(TEST_HOST_KEY.parse::<HostKey>().is_ok());
}

#[test]
fn relative_root_path_rejected() {
    let f = fx();
    assert_eq!(
        f.load(&f.minimal().replace("path = \"/srv/app\"", "path = \"srv/app\""))
            .unwrap_err()
            .code,
        ErrorCode::ConfigInvalid
    );
    assert_eq!(
        f.load(&f.minimal().replace("path = \"/srv/app\"", "path = \"/srv/../etc\""))
            .unwrap_err()
            .code,
        ErrorCode::ConfigInvalid
    );
}

#[test]
fn duplicate_host_ids_rejected() {
    let f = fx();
    let toml = f.minimal() + &host_block("h1", "203.0.113.11", 22, "x", TEST_HOST_KEY, &f.identity);
    let e = f.load(&toml).unwrap_err();
    assert_eq!(e.code, ErrorCode::ConfigInvalid);
    assert!(e.message.contains("duplicate"), "{}", e.message);
}

#[test]
fn unknown_service_in_health_check_rejected() {
    let f = fx();
    let toml = f.minimal() + "\n[hosts.health_checks.svc]\nkind = \"service_active\"\nservice = \"nope\"\n";
    assert_eq!(f.load(&toml).unwrap_err().code, ErrorCode::ConfigInvalid);
}

#[test]
fn bad_unit_name_rejected() {
    let f = fx();
    assert_eq!(
        f.load(&f.minimal().replace("app-api.service", "app api; reboot")).unwrap_err().code,
        ErrorCode::ConfigInvalid
    );
}

#[test]
fn unknown_fields_rejected() {
    let f = fx();
    let toml = f
        .minimal()
        .replace("environment = \"staging\"", "environment = \"staging\"\nproxy_command = \"nc\"");
    assert_eq!(f.load(&toml).unwrap_err().code, ErrorCode::ConfigInvalid);
}

#[test]
fn policy_mirrors_config() {
    let f = fx();
    let c = f.load(&f.minimal()).unwrap();
    let p = c.policy();
    let pr = c.principal();
    let h1 = HostId::parse("h1").unwrap();
    assert!(p.root(&pr, &h1, "app").unwrap().export);
    assert!(!p.root(&pr, &h1, "logs").unwrap().export);
    assert!(c.host(&h1).is_some());
}

#[test]
fn doctor_reports_without_connecting() {
    let f = fx();
    let r = run_doctor(&f.path_of(&f.minimal()), false);
    assert!(r.checks.iter().any(|c| c.name == "config.permissions" && c.ok), "{r:?}");
    assert!(r.checks.iter().any(|c| c.name == "ssh.binary"), "{r:?}");
    assert!(r.checks.iter().any(|c| c.name == "ssh.system_config"), "{r:?}");
    assert!(r.checks.iter().any(|c| c.name == "host.h1.identity" && c.ok), "{r:?}");
}

#[test]
fn doctor_flags_proxycommand_in_system_config() {
    let f = fx();
    let sys = f.dirs.state.path().join("ssh_config");
    write_private(&sys, "Host *\n  ProxyCommand nc %h %p\n");
    let r = run_doctor_with_system_config(&f.path_of(&f.minimal()), false, &sys);
    let c = r.checks.iter().find(|c| c.name == "ssh.system_config").unwrap();
    assert!(c.detail.contains("ProxyCommand"), "{c:?}");
}

#[test]
fn doctor_missing_config_fails() {
    let r = run_doctor(Path::new("/nonexistent/sentinel.toml"), false);
    assert!(r.checks.iter().any(|c| c.name == "config.load" && !c.ok));
    assert!(!r.ok());
}
