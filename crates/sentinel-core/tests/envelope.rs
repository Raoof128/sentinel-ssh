use sentinel_core::envelope::{EvidenceSource, ResultEnvelope};
use sentinel_core::identity::{HostId, OperationId};

#[test]
fn envelope_matches_spec_shape() {
    let e = ResultEnvelope::succeeded(
        OperationId::generate(),
        Some(HostId::parse("h1").unwrap()),
        serde_json::json!({"k": 1}),
    )
    .with_evidence("service_state", EvidenceSource::Observer)
    .warn("non_utf8_replaced");
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["schema_version"], "1");
    assert_eq!(v["outcome"], "succeeded");
    assert_eq!(v["truncated"], false);
    assert_eq!(v["retry"]["strategy"], "never");
    assert_eq!(v["evidence"][0]["source"], "observer");
    assert_eq!(v["host_id"], "h1");
    assert!(v["next_cursor"].is_null());
    assert_eq!(v["warnings"][0], "non_utf8_replaced");
}

#[test]
fn warn_is_idempotent() {
    let e = ResultEnvelope::succeeded(OperationId::generate(), None, ()).warn("x").warn("x");
    assert_eq!(e.warnings, vec!["x".to_string()]);
}
