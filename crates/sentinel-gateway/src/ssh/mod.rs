//! SSH transport.

use crate::config::Config;

/// `doctor --connect` results: one `(check name, ok, detail)` per host. Implemented with the backend in Task 7.
pub fn doctor_connect(_cfg: &Config) -> Vec<(String, bool, String)> {
    vec![(
        "connect".to_owned(),
        false,
        "connection checks are not available in this build".to_owned(),
    )]
}
