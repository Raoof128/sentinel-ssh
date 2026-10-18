//! The Docker sshd fixture (`scripts/fixture-up.sh`). Tests skip when `SENTINEL_TEST_HOST` is unset.

use std::path::PathBuf;

use crate::configs::{TestDirs, gateway_header, write_private};

#[derive(Debug, Clone)]
pub struct SshFixture {
    pub address: String,
    pub port: u16,
    pub user: String,
    pub identity: PathBuf,
    /// `<type> <base64>`
    pub host_key: String,
    /// A valid key that is not the fixture's.
    pub wrong_host_key: String,
}

impl SshFixture {
    pub fn from_env() -> Option<Self> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Some(Self {
            address: get("SENTINEL_TEST_HOST")?,
            port: get("SENTINEL_TEST_PORT")?.parse().ok()?,
            user: get("SENTINEL_TEST_USER")?,
            identity: PathBuf::from(get("SENTINEL_TEST_IDENTITY")?),
            host_key: get("SENTINEL_TEST_HOST_KEY")?,
            wrong_host_key: get("SENTINEL_TEST_WRONG_HOST_KEY")?,
        })
    }

    /// Host `fx`: roots app (read+export), logs (read only), secrets (no read); service api; log source api; health api_http.
    pub fn config_toml(&self, dirs: &TestDirs, host_key: &str) -> String {
        gateway_header(dirs)
            + &format!(
                r#"
[[hosts]]
id = "fx"
environment = "fixture"
address = "{address}"
port = {port}
user = "{user}"
host_key = "{host_key}"
auth = {{ method = "identity_file", path = "{identity}" }}

[hosts.roots.app]
path = "/srv/app"
read = true
export = true

[hosts.roots.logs]
path = "/srv/app/logs"
read = true
export = false

[hosts.roots.secrets]
path = "/srv/secrets"
read = false
export = false

[hosts.services.api]
unit = "app-api.service"
scope = "system"

[hosts.log_sources.api]
path = "/srv/app/logs/api.log"

[hosts.log_sources.root_only]
path = "/srv/app/logs/root.log"

[hosts.log_sources.linked]
path = "/srv/app/logs/linked.log"

[hosts.health_checks.api_http]
kind = "http"
url = "http://127.0.0.1:8080/health"
expect_status = 200
timeout_secs = 5
"#,
                address = self.address,
                port = self.port,
                user = self.user,
                identity = self.identity.display(),
            )
    }

    /// Writes the config (mode 0600) and returns its path.
    pub fn write_config(&self, dirs: &TestDirs, wrong_key: bool) -> PathBuf {
        let key = if wrong_key { &self.wrong_host_key } else { &self.host_key };
        let p = dirs.state.path().join("fixture.toml");
        write_private(&p, &self.config_toml(dirs, key));
        p
    }
}
