//! Deny-by-default policy evaluation (spec §9.1). Evaluates principal × host × resource × effect.
//! v0.1 is observer mode: Plan, Stage and Change are denied for every role.

use std::collections::{BTreeMap, BTreeSet};

use crate::effect::Effect;
use crate::error::{ErrorCode, Result, SentinelError};
use crate::identity::{HostId, Principal, PrincipalId};

/// Same message for unknown and invisible hosts so the denial does not disclose inventory (spec §6.5).
pub const HOST_UNAVAILABLE: &str = "host not available to this principal";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootPolicy {
    pub alias: String,
    /// Absolute Linux path, no trailing slash.
    pub path: String,
    pub read: bool,
    pub export: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPolicy {
    pub host_id: HostId,
    pub environment: String,
    pub roots: BTreeMap<String, RootPolicy>,
    pub services: BTreeSet<String>,
    pub log_sources: BTreeSet<String>,
    pub health_checks: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum ResourceRef<'a> {
    Host,
    Root(&'a str),
    Service(&'a str),
    LogSource(&'a str),
    HealthCheck(&'a str),
    Operation { owner: &'a PrincipalId },
    Artifact { owner: &'a PrincipalId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
    RequireApproval,
}

impl Decision {
    fn deny(reason: impl Into<String>) -> Self {
        Decision::Deny { reason: reason.into() }
    }

    pub fn into_result(self) -> Result<()> {
        match self {
            Decision::Allow => Ok(()),
            Decision::Deny { reason } => Err(SentinelError::new(ErrorCode::PolicyDenied, reason)),
            Decision::RequireApproval => Err(SentinelError::new(ErrorCode::ApprovalRequired, "independent approval required")),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    hosts: BTreeMap<HostId, HostPolicy>,
}

impl PolicyEngine {
    pub fn new(hosts: Vec<HostPolicy>) -> Self {
        Self {
            hosts: hosts.into_iter().map(|h| (h.host_id.clone(), h)).collect(),
        }
    }

    pub fn evaluate(&self, principal: &Principal, host: Option<&HostId>, resource: &ResourceRef, effect: Effect) -> Decision {
        if matches!(effect, Effect::Plan | Effect::Stage | Effect::Change) {
            return Decision::deny("protected changes are not available in v0.1 (observer mode)");
        }
        match resource {
            ResourceRef::Operation { owner } | ResourceRef::Artifact { owner } => {
                if !matches!(effect, Effect::Read | Effect::Control) {
                    return Decision::deny("unsupported effect for this resource");
                }
                if *owner == &principal.id {
                    Decision::Allow
                } else {
                    Decision::deny("not found")
                }
            }
            _ => {
                let Some(hp) = host.and_then(|id| self.host(principal, id)) else {
                    return Decision::deny(HOST_UNAVAILABLE);
                };
                self.evaluate_on_host(hp, resource, effect)
            }
        }
    }

    fn evaluate_on_host(&self, hp: &HostPolicy, resource: &ResourceRef, effect: Effect) -> Decision {
        match (resource, effect) {
            // An unreadable root is not listed by ssh_hosts_list, so it answers exactly like an unregistered alias:
            // a denial must not confirm that it exists (red team L3).
            (ResourceRef::Root(alias), Effect::Read) => match hp.roots.get(*alias) {
                Some(r) if r.read => Decision::Allow,
                _ => Decision::deny(format!("unknown root '{alias}'")),
            },
            (ResourceRef::Root(alias), Effect::Export) => match hp.roots.get(*alias) {
                Some(r) if r.read && r.export => Decision::Allow,
                Some(r) if r.read => Decision::deny(format!("export not permitted for root '{alias}'")),
                _ => Decision::deny(format!("unknown root '{alias}'")),
            },
            (ResourceRef::Host, Effect::Read) => Decision::Allow,
            (ResourceRef::Service(id), Effect::Read) => registered(&hp.services, id, "service"),
            (ResourceRef::LogSource(id), Effect::Read) => registered(&hp.log_sources, id, "log source"),
            (ResourceRef::HealthCheck(id), Effect::Read) => registered(&hp.health_checks, id, "health check"),
            _ => Decision::deny("effect not permitted on this resource"),
        }
    }

    /// Hosts this principal may see, sorted by id.
    pub fn visible_hosts(&self, principal: &Principal) -> Vec<&HostPolicy> {
        self.hosts
            .values()
            .filter(|h| principal.visible_hosts.can_see(&h.host_id))
            .collect()
    }

    pub fn host(&self, principal: &Principal, id: &HostId) -> Option<&HostPolicy> {
        self.hosts.get(id).filter(|h| principal.visible_hosts.can_see(&h.host_id))
    }

    pub fn root(&self, principal: &Principal, host: &HostId, alias: &str) -> Result<&RootPolicy> {
        let hp = self
            .host(principal, host)
            .ok_or_else(|| SentinelError::new(ErrorCode::PolicyDenied, HOST_UNAVAILABLE))?;
        hp.roots
            .get(alias)
            .filter(|r| r.read)
            .ok_or_else(|| SentinelError::new(ErrorCode::PolicyDenied, format!("unknown root '{alias}'")))
    }
}

fn registered(set: &BTreeSet<String>, id: &str, what: &str) -> Decision {
    if set.contains(id) {
        Decision::Allow
    } else {
        Decision::deny(format!("unknown {what} '{id}'"))
    }
}
