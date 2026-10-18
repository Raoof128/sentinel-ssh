#![forbid(unsafe_code)]
//! SentinelSSH test support: scripted fake SSH backend, Docker sshd fixture and config fixtures.
pub mod configs;
pub mod ctx;
pub mod fake_backend;
pub mod fixture;

/// Installs a test log subscriber once per test binary, so log statements (and their arguments) run under test.
/// Output goes through the test harness capture.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("sentinel_gateway=trace")
        .try_init();
}
