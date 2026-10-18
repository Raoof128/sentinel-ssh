//! Identifiers and principals. Ids are opaque and validated on every parse; possession of an id is never authorisation (spec §8.4).

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, Result, SentinelError};

fn is_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn is_prefixed_hex(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|rest| rest.len() == 32 && rest.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}

macro_rules! string_id {
    ($name:ident, $what:literal, $valid:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(s: &str) -> Result<Self> {
                let valid: fn(&str) -> bool = $valid;
                if valid(s) {
                    Ok(Self(s.to_owned()))
                } else {
                    Err(SentinelError::new(ErrorCode::InvalidInput, format!("invalid {}", $what)).with_detail("field", $what))
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = SentinelError;
            fn from_str(s: &str) -> Result<Self> {
                Self::parse(s)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::parse(&s).map_err(|e| serde::de::Error::custom(e.message))
            }
        }
    };
}

string_id!(HostId, "host_id", is_slug);
string_id!(PrincipalId, "principal_id", is_slug);
string_id!(OperationId, "operation_id", |s| is_prefixed_hex(s, "op_"));
string_id!(ArtifactId, "artifact_id", |s| is_prefixed_hex(s, "art_"));

impl OperationId {
    pub fn generate() -> Self {
        Self(format!("op_{}", uuid::Uuid::now_v7().simple()))
    }
}

impl ArtifactId {
    pub fn generate() -> Self {
        Self(format!("art_{}", uuid::Uuid::now_v7().simple()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Observer,
    Operator,
    Administrator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostVisibility {
    All,
    Only(BTreeSet<HostId>),
}

impl HostVisibility {
    pub fn can_see(&self, host: &HostId) -> bool {
        match self {
            HostVisibility::All => true,
            HostVisibility::Only(set) => set.contains(host),
        }
    }
}

/// An authenticated principal. Never constructed from a tool request field (spec §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: PrincipalId,
    pub role: Role,
    pub visible_hosts: HostVisibility,
}
