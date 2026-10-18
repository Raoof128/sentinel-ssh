#![forbid(unsafe_code)]
//! Shared SentinelSSH contract types: errors, identity, operations, envelopes, policy and path scoping. No I/O.
pub mod effect;
pub mod envelope;
pub mod error;
pub mod identity;
pub mod operation;
pub mod policy;
pub mod scope;
