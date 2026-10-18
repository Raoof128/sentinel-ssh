//! Command-line interface.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "sentinel-ssh",
    version,
    about = "Policy-scoped SSH inspection for AI agents over MCP (observer mode)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run the MCP server on stdio.
    Serve {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Check configuration, trust inputs and the SSH client. Never mutates remote state.
    Doctor {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Also connect to each host and run `true`.
        #[arg(long)]
        connect: bool,
    },
    /// Print every tool's input and output JSON Schema.
    Schemas,
    /// Configuration commands.
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    /// Validate the configuration file.
    Lint {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}
