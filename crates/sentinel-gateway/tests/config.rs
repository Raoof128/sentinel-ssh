use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sentinel_core::error::ErrorCode;
use sentinel_core::identity::HostId;
use sentinel_gateway::config::{Config, HostKey, load_config};
use sentinel_gateway::doctor::run_doctor;
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
    assert!(r.checks.iter().any(|c| c.name == "host.h1.identity" && c.ok), "{r:?}");
}

#[test]
fn doctor_missing_config_fails() {
    let r = run_doctor(Path::new("/nonexistent/sentinel.toml"), false);
    assert!(r.checks.iter().any(|c| c.name == "config.load" && !c.ok));
    assert!(!r.ok());
}

#[test]
fn private_dir_is_created_0700_and_rejects_unsafe_dirs() {
    use sentinel_gateway::config::ensure_private_dir;
    let d = tempfile::tempdir().unwrap();
    let fresh = d.path().join("a/b");
    ensure_private_dir(&fresh).unwrap();
    assert_eq!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o700);
    let open = d.path().join("open");
    std::fs::create_dir(&open).unwrap();
    write_with_mode(&open, 0o755);
    assert_eq!(ensure_private_dir(&open).unwrap_err().code, ErrorCode::ConfigInvalid);
    let link = d.path().join("link");
    std::os::unix::fs::symlink(&fresh, &link).unwrap();
    let e = ensure_private_dir(&link).unwrap_err();
    assert!(e.message.contains("symlink"), "{}", e.message);
    let file = d.path().join("file");
    write_private(&file, "x");
    assert_eq!(ensure_private_dir(&file).unwrap_err().code, ErrorCode::ConfigInvalid);
}

fn rejects(f: &Fx, toml: &str, needle: &str) {
    let e = f.load(toml).unwrap_err();
    assert_eq!(e.code, ErrorCode::ConfigInvalid, "{toml}");
    assert!(e.message.contains(needle), "expected {needle:?} in {:?}", e.message);
}

#[test]
fn every_inventory_field_is_validated() {
    let f = fx();
    let m = f.minimal();
    rejects(
        &f,
        &m.replace("schema_version = 1", "schema_version = 2"),
        "unsupported schema_version 2",
    );
    rejects(
        &f,
        &m.replace("address = \"203.0.113.10\"", "address = \"-oProxyCommand=sh\""),
        "invalid address",
    );
    rejects(&f, &m.replace("user = \"sentinel-observer\"", "user = \"a b\""), "invalid user");
    rejects(
        &f,
        &m.replace("[hosts.roots.app]", "[hosts.roots.\"bad alias\"]"),
        "invalid root alias",
    );
    rejects(
        &f,
        &m.replace("read = true\nexport = true", "read = false\nexport = true"),
        "export requires read = true",
    );
    rejects(
        &f,
        &m.replace("[hosts.log_sources.api]", "[hosts.log_sources.\"a/b\"]"),
        "invalid log source id",
    );
    rejects(
        &f,
        &m.replace("[hosts.health_checks.api_http]", "[hosts.health_checks.\"x y\"]"),
        "invalid health check id",
    );
    rejects(
        &f,
        &m.replace("http://127.0.0.1:8080/health", "file:///etc/passwd"),
        "url must be http(s)",
    );
    rejects(&f, &m.replace("timeout_secs = 5", "timeout_secs = 0"), "timeout 1-60 s");
    rejects(&f, &m.replace("ssh-ed25519 AAAA", "ssh-dss AAAA"), "unsupported key type 'ssh-dss'");
    rejects(&f, &m.replace("id = \"raouf\"", "id = \"Not Valid\""), "principal.id");
}

#[test]
fn runtime_dir_too_long_for_a_control_socket_is_rejected() {
    let f = fx();
    let long = format!("/tmp/{}", "d".repeat(80));
    let toml = f.minimal().replace(
        &format!("runtime_dir = \"{}\"", f.dirs.run.path().join("r").display()),
        &format!("runtime_dir = \"{long}\""),
    );
    rejects(&f, &toml, "too long for an SSH ControlPath socket");
}

#[test]
fn service_active_health_check_is_accepted() {
    let f = fx();
    let c = f.load(&f.minimal()).unwrap();
    assert!(matches!(
        c.hosts[0].health_checks.get("api_active"),
        Some(sentinel_gateway::config::HealthCheckConfig::ServiceActive { service }) if service == "api"
    ));
}

#[test]
fn gateway_paths_default_under_home() {
    let f = fx();
    let m = f.minimal();
    let start = m.find("artifact_dir").unwrap();
    let end = m.find("[principal]").unwrap();
    let toml = format!("{}\n{}", &m[..start], &m[end..]);
    let c = f.load(&toml).unwrap();
    let home = std::env::var("HOME").unwrap();
    assert_eq!(
        c.gateway.artifact_dir,
        PathBuf::from(&home).join(".local/share/sentinel-ssh/artifacts")
    );
    assert_eq!(c.gateway.runtime_dir, PathBuf::from(&home).join(".local/state/sentinel-ssh/run"));
    assert_eq!(c.gateway.ssh_binary, PathBuf::from("/usr/bin/ssh"));
}

#[test]
fn files_and_dirs_owned_by_another_user_are_rejected() {
    // /etc/hosts and /usr are root-owned on every supported gateway platform.
    let e = load_config(Path::new("/etc/hosts")).unwrap_err();
    assert!(e.message.contains("owned by the current user"), "{}", e.message);
    let e = sentinel_gateway::config::ensure_private_dir(Path::new("/usr")).unwrap_err();
    assert!(e.message.contains("owned by the current user"), "{}", e.message);
}

#[test]
fn tilde_paths_expand_and_others_do_not() {
    use sentinel_gateway::config::expand_tilde;
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    assert_eq!(expand_tilde(Path::new("~/x")), home.join("x"));
    assert_eq!(expand_tilde(Path::new("/abs/x")), PathBuf::from("/abs/x"));
    assert_eq!(expand_tilde(Path::new("~other/x")), PathBuf::from("~other/x"));
}

/// Red team M2: the runtime_dir budget accounts for ssh's 17-byte temporary socket suffix (103 usable bytes).
#[test]
fn runtime_dir_budget_matches_the_real_socket_limit() {
    let f = fx();
    let ok = format!("/tmp/{}", "d".repeat(58));
    let too_long = format!("/tmp/{}", "d".repeat(59));
    let current = format!("runtime_dir = \"{}\"", f.dirs.run.path().join("r").display());
    assert_eq!(ok.len(), 63);
    assert!(f.load(&f.minimal().replace(&current, &format!("runtime_dir = \"{ok}\""))).is_ok());
    rejects(
        &f,
        &f.minimal().replace(&current, &format!("runtime_dir = \"{too_long}\"")),
        "too long for an SSH ControlPath socket",
    );
}

/// Red team M1: a private dir inside a directory others can write (and that is not sticky) can be swapped out.
#[test]
fn private_dirs_need_trusted_ancestors() {
    use sentinel_gateway::config::ensure_private_dir;
    let d = tempfile::tempdir().unwrap();
    let open = d.path().join("open");
    std::fs::create_dir(&open).unwrap();
    write_with_mode(&open, 0o777);
    let e = ensure_private_dir(&open.join("run")).unwrap_err();
    assert!(e.message.contains("writable by other users"), "{}", e.message);
    // A sticky world-writable parent like /tmp is fine: others cannot rename or replace our directory.
    write_with_mode(&open, 0o1777);
    assert!(ensure_private_dir(&open.join("run2")).is_ok());
}

/// Red team M4 / L1 / L6 / info: gateway paths are absolute and free of ssh % tokens; addresses carry no user.
#[test]
fn gateway_paths_and_addresses_are_unambiguous() {
    let f = fx();
    let m = f.minimal();
    rejects(
        &f,
        &m.replace("ssh_binary = \"/usr/bin/ssh\"", "ssh_binary = \"bin/ssh\""),
        "must be an absolute path",
    );
    rejects(
        &f,
        &m.replace("ssh_binary = \"/usr/bin/ssh\"", "ssh_binary = \"/usr/bin/ssh%d\""),
        "'%'",
    );
    let id = f.identity.display().to_string();
    rejects(&f, &m.replace(&id, &format!("{id}%u")), "'%'");
    let art = f.dirs.state.path().join("artifacts").display().to_string();
    rejects(&f, &m.replace(&art, "relative/artifacts"), "must be an absolute path");
    rejects(
        &f,
        &m.replace("address = \"203.0.113.10\"", "address = \"root@203.0.113.10\""),
        "invalid address",
    );
}

/// Security review: the ancestor check walked the lexical path, so a symlink into a dir under a world-writable parent
/// passed. The resolved path's chain is what must be trusted.
#[test]
fn trusted_ancestors_are_checked_on_the_resolved_path() {
    use sentinel_gateway::config::{check_trusted_executable, ensure_private_dir};
    let d = tempfile::tempdir().unwrap();
    let open = d.path().join("open");
    let inner = open.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    write_with_mode(&open, 0o777);
    write_with_mode(&inner, 0o755);
    let link = d.path().join("link");
    std::os::unix::fs::symlink(&inner, &link).unwrap();
    let e = ensure_private_dir(&link.join("run")).unwrap_err();
    assert!(e.message.contains("writable by other users"), "{}", e.message);
    let bin = inner.join("ssh");
    std::fs::write(&bin, "#!/bin/sh\n").unwrap();
    write_with_mode(&bin, 0o755);
    let e = check_trusted_executable(&link.join("ssh")).unwrap_err();
    assert!(e.message.contains("writable by other users"), "{}", e.message);
}
