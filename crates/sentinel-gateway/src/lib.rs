#![forbid(unsafe_code)]
//! SentinelSSH gateway: configuration, OpenSSH backend, scheduling, artefacts, tools and MCP glue.
pub mod cli;
pub mod config;
pub mod doctor;
pub mod jobs;
pub mod ssh;
