use std::collections::{BTreeMap, BTreeSet};

use sentinel_core::effect::Effect;
use sentinel_core::error::ErrorCode;
use sentinel_core::identity::{HostId, HostVisibility, Principal, PrincipalId, Role};
use sentinel_core::policy::{Decision, HostPolicy, PolicyEngine, ResourceRef, RootPolicy};

fn h(s: &str) -> HostId {
    HostId::parse(s).unwrap()
}

fn engine() -> PolicyEngine {
    let mut roots = BTreeMap::new();
    roots.insert(
        "app".into(),
        RootPolicy {
            alias: "app".into(),
            path: "/srv/app".into(),
            read: true,
            export: true,
        },
    );
    roots.insert(
        "logs".into(),
        RootPolicy {
            alias: "logs".into(),
            path: "/srv/app/logs".into(),
            read: true,
            export: false,
        },
    );
    roots.insert(
        "secrets".into(),
        RootPolicy {
            alias: "secrets".into(),
            path: "/srv/secrets".into(),
            read: false,
            export: false,
        },
    );
    PolicyEngine::new(vec![HostPolicy {
        host_id: h("h1"),
        environment: "staging".into(),
        roots,
        services: BTreeSet::from(["api".to_string()]),
        log_sources: BTreeSet::from(["api".to_string()]),
        health_checks: BTreeSet::from(["api_http".to_string()]),
    }])
}

fn observer() -> Principal {
    Principal {
        id: PrincipalId::parse("me").unwrap(),
        role: Role::Observer,
        visible_hosts: HostVisibility::All,
    }
}

fn restricted() -> Principal {
    Principal {
        id: PrincipalId::parse("me").unwrap(),
        role: Role::Observer,
        visible_hosts: HostVisibility::Only(BTreeSet::from([h("other")])),
    }
}

#[test]
fn deny_by_default_unknown_resource() {
    assert!(matches!(
        engine().evaluate(&observer(), Some(&h("h1")), &ResourceRef::Root("nope"), Effect::Read),
        Decision::Deny { .. }
    ));
    assert!(matches!(
        engine().evaluate(&observer(), Some(&h("h1")), &ResourceRef::Service("sshd"), Effect::Read),
        Decision::Deny { .. }
    ));
}

#[test]
fn read_allowed_on_registered_resources() {
    let e = engine();
    let p = observer();
    assert_eq!(
        e.evaluate(&p, Some(&h("h1")), &ResourceRef::Root("logs"), Effect::Read),
        Decision::Allow
    );
    assert_eq!(
        e.evaluate(&p, Some(&h("h1")), &ResourceRef::Service("api"), Effect::Read),
        Decision::Allow
    );
    assert_eq!(
        e.evaluate(&p, Some(&h("h1")), &ResourceRef::LogSource("api"), Effect::Read),
        Decision::Allow
    );
    assert_eq!(
        e.evaluate(&p, Some(&h("h1")), &ResourceRef::HealthCheck("api_http"), Effect::Read),
        Decision::Allow
    );
    assert_eq!(e.evaluate(&p, Some(&h("h1")), &ResourceRef::Host, Effect::Read), Decision::Allow);
}

#[test]
fn read_denied_on_unreadable_root() {
    assert!(matches!(
        engine().evaluate(&observer(), Some(&h("h1")), &ResourceRef::Root("secrets"), Effect::Read),
        Decision::Deny { .. }
    ));
}

#[test]
fn export_denied_when_root_not_exportable() {
    let d = engine().evaluate(&observer(), Some(&h("h1")), &ResourceRef::Root("logs"), Effect::Export);
    assert_eq!(
        d,
        Decision::Deny {
            reason: "export not permitted for root 'logs'".into()
        }
    );
}

#[test]
fn export_allowed_when_flagged() {
    assert_eq!(
        engine().evaluate(&observer(), Some(&h("h1")), &ResourceRef::Root("app"), Effect::Export),
        Decision::Allow
    );
}

#[test]
fn change_denied_for_every_role() {
    for role in [Role::Observer, Role::Operator, Role::Administrator] {
        let p = Principal { role, ..observer() };
        for eff in [Effect::Change, Effect::Stage, Effect::Plan] {
            assert!(matches!(
                engine().evaluate(&p, Some(&h("h1")), &ResourceRef::Root("app"), eff),
                Decision::Deny { .. }
            ));
        }
    }
}

#[test]
fn invisible_and_unknown_hosts_get_identical_denial() {
    let a = engine().evaluate(&restricted(), Some(&h("h1")), &ResourceRef::Host, Effect::Read);
    let b = engine().evaluate(&restricted(), Some(&h("ghost")), &ResourceRef::Host, Effect::Read);
    assert_eq!(a, b);
    assert!(matches!(a, Decision::Deny { .. }));
}

#[test]
fn host_resource_without_host_denied() {
    assert!(matches!(
        engine().evaluate(&observer(), None, &ResourceRef::Root("app"), Effect::Read),
        Decision::Deny { .. }
    ));
}

#[test]
fn control_only_on_own_operations() {
    let me = observer();
    let other = PrincipalId::parse("other").unwrap();
    assert_eq!(
        engine().evaluate(&me, None, &ResourceRef::Operation { owner: &me.id }, Effect::Control),
        Decision::Allow
    );
    assert_eq!(
        engine().evaluate(&me, None, &ResourceRef::Artifact { owner: &me.id }, Effect::Read),
        Decision::Allow
    );
    assert!(matches!(
        engine().evaluate(&me, None, &ResourceRef::Operation { owner: &other }, Effect::Control),
        Decision::Deny { .. }
    ));
    assert!(matches!(
        engine().evaluate(&me, None, &ResourceRef::Artifact { owner: &other }, Effect::Read),
        Decision::Deny { .. }
    ));
}

#[test]
fn visible_hosts_sorted_and_filtered() {
    assert_eq!(engine().visible_hosts(&restricted()).len(), 0);
    assert_eq!(engine().visible_hosts(&observer())[0].host_id.as_str(), "h1");
}

#[test]
fn root_lookup() {
    let e = engine();
    assert!(e.root(&observer(), &h("h1"), "app").unwrap().export);
    assert_eq!(e.root(&observer(), &h("h1"), "nope").unwrap_err().code, ErrorCode::PolicyDenied);
    assert_eq!(e.root(&restricted(), &h("h1"), "app").unwrap_err().code, ErrorCode::PolicyDenied);
}

#[test]
fn decision_into_result() {
    assert!(Decision::Allow.into_result().is_ok());
    assert_eq!(
        Decision::Deny { reason: "x".into() }.into_result().unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        Decision::RequireApproval.into_result().unwrap_err().code,
        ErrorCode::ApprovalRequired
    );
}

#[test]
fn owner_resources_allow_only_read_and_control() {
    let me = observer();
    assert!(matches!(
        engine().evaluate(&me, None, &ResourceRef::Artifact { owner: &me.id }, Effect::Export),
        Decision::Deny { .. }
    ));
}

#[test]
fn export_of_unknown_root_is_denied() {
    let d = engine().evaluate(&observer(), Some(&h("h1")), &ResourceRef::Root("nope"), Effect::Export);
    assert_eq!(
        d,
        Decision::Deny {
            reason: "unknown root 'nope'".into()
        }
    );
}

#[test]
fn control_on_host_resources_is_denied() {
    for r in [ResourceRef::Root("app"), ResourceRef::Host, ResourceRef::Service("api")] {
        assert!(matches!(
            engine().evaluate(&observer(), Some(&h("h1")), &r, Effect::Control),
            Decision::Deny { .. }
        ));
    }
}

/// Red team L3: a root the principal cannot read is not listed by ssh_hosts_list, so a denial must not confirm that it
/// exists. It answers exactly like an unregistered alias, for either effect.
#[test]
fn unreadable_root_is_indistinguishable_from_an_unknown_one() {
    let e = engine();
    for effect in [Effect::Read, Effect::Export] {
        let secret = e.evaluate(&observer(), Some(&h("h1")), &ResourceRef::Root("secrets"), effect);
        let nope = e.evaluate(&observer(), Some(&h("h1")), &ResourceRef::Root("nope"), effect);
        assert_eq!(
            secret,
            Decision::Deny {
                reason: "unknown root 'secrets'".into()
            }
        );
        assert_eq!(
            nope,
            Decision::Deny {
                reason: "unknown root 'nope'".into()
            }
        );
    }
    let looked_up = e.root(&observer(), &h("h1"), "secrets").unwrap_err();
    assert_eq!(looked_up.message, "unknown root 'secrets'");
}
