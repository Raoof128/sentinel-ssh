use sentinel_core::error::{ErrorCode, RetryStrategy, SentinelError};

#[test]
fn codes_serialise_as_screaming_snake() {
    assert_eq!(serde_json::to_string(&ErrorCode::HostKeyChanged).unwrap(), "\"HOST_KEY_CHANGED\"");
    assert_eq!(
        serde_json::to_string(&ErrorCode::ResumeUnverifiable).unwrap(),
        "\"RESUME_UNVERIFIABLE\""
    );
}

#[test]
fn default_retry_follows_spec_table() {
    assert_eq!(ErrorCode::HostKeyChanged.default_retry(), RetryStrategy::Never);
    assert_eq!(ErrorCode::OutcomeUnknown.default_retry(), RetryStrategy::Reconcile);
    assert_eq!(ErrorCode::StalePlan.default_retry(), RetryStrategy::Replan);
    assert_eq!(ErrorCode::BudgetExceeded.default_retry(), RetryStrategy::NarrowRequest);
    assert_eq!(ErrorCode::PolicyDenied.default_retry(), RetryStrategy::Never);
}

#[test]
fn error_json_shape() {
    let e = SentinelError::new(ErrorCode::PolicyDenied, "export not permitted for root 'logs'").with_operation("op_1");
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["code"], "POLICY_DENIED");
    assert_eq!(v["retry"]["strategy"], "never");
    assert_eq!(v["operation_id"], "op_1");
    assert!(v.get("details").is_none(), "empty details omitted");
}

#[test]
fn details_round_trip() {
    let e = SentinelError::new(ErrorCode::BudgetExceeded, "queue full").with_detail("reason", "queue_wait_exceeded");
    let back: SentinelError = serde_json::from_value(serde_json::to_value(&e).unwrap()).unwrap();
    assert_eq!(back, e);
    assert_eq!(back.details["reason"], "queue_wait_exceeded");
}

#[test]
fn error_schema_snapshot() {
    insta::assert_json_snapshot!(schemars::schema_for!(SentinelError));
}

#[test]
fn io_errors_map_to_typed_codes() {
    let full: SentinelError = std::io::Error::from(std::io::ErrorKind::StorageFull).into();
    assert_eq!(full.code, ErrorCode::DiskFull);
    let other: SentinelError = std::io::Error::other("boom").into();
    assert_eq!(other.code, ErrorCode::Internal);
    assert!(other.message.contains("boom"));
}
