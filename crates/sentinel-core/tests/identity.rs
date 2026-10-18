use sentinel_core::error::ErrorCode;
use sentinel_core::identity::{ArtifactId, HostId, OperationId, PrincipalId};

#[test]
fn ids_validate() {
    assert!(HostId::parse("staging-api-1").is_ok());
    assert!(HostId::parse("Staging").is_err());
    assert!(HostId::parse("../x").is_err());
    assert_eq!(HostId::parse("").unwrap_err().code, ErrorCode::InvalidInput);
    assert!(PrincipalId::parse("raouf").is_ok());
}

#[test]
fn generated_ids_parse_and_differ() {
    let a = OperationId::generate();
    assert!(a.as_str().starts_with("op_"));
    assert_eq!(a.as_str().len(), 35);
    assert_ne!(a, OperationId::generate());
    assert!(OperationId::parse(a.as_str()).is_ok());
    assert!(OperationId::parse("op_../../etc").is_err());
    let art = ArtifactId::generate();
    assert!(art.as_str().starts_with("art_"));
    assert!(ArtifactId::parse(art.as_str()).is_ok());
    assert!(ArtifactId::parse(a.as_str()).is_err(), "operation id is not an artefact id");
}

#[test]
fn ids_serialise_as_plain_strings() {
    let h = HostId::parse("h1").unwrap();
    assert_eq!(serde_json::to_string(&h).unwrap(), "\"h1\"");
    let back: HostId = serde_json::from_str("\"h1\"").unwrap();
    assert_eq!(back, h);
    assert!(serde_json::from_str::<HostId>("\"BAD\"").is_err(), "deserialisation validates");
}

#[test]
fn ids_parse_via_from_str() {
    let h: HostId = "staging-1".parse().unwrap();
    assert_eq!(h.to_string(), "staging-1");
    assert!("Bad Host".parse::<HostId>().is_err());
    assert!("op_xyz".parse::<OperationId>().is_err());
}
