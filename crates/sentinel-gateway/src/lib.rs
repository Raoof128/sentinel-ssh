#![forbid(unsafe_code)]
//! SentinelSSH gateway: configuration, OpenSSH backend, scheduling, artefacts, tools and MCP glue.
pub mod artifacts;
pub mod cli;
pub mod config;
pub mod doctor;
pub mod jobs;
pub mod mcp;
pub mod ssh;
pub mod tools;
