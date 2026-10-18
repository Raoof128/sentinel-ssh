#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use sentinel_gateway::cli::{Cli, Commands, ConfigCommands};
use sentinel_gateway::config::{default_config_path, load_config};
use sentinel_gateway::doctor::run_doctor;
use sentinel_gateway::mcp::server::{serve_stdio, tool_schemas};
use sentinel_gateway::ssh::openssh::OpenSshBackend;
use sentinel_gateway::tools::AppContext;

fn serve(config: &std::path::Path) -> anyhow::Result<()> {
    // stdout is the protocol channel: logs go to stderr only, and never include argv above debug level.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("SENTINEL_LOG").unwrap_or_else(|_| "sentinel_gateway=info".into()))
        .init();
    let cfg = load_config(config).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let backend = OpenSshBackend::new(&cfg.gateway).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let ctx = AppContext::new(cfg, std::sync::Arc::new(backend)).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve_stdio(ctx))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor { config, connect } => {
            let report = run_doctor(&config.unwrap_or_else(default_config_path), connect);
            print!("{}", report.render());
            if report.ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
        }
        Commands::Config {
            command: ConfigCommands::Lint { config },
        } => match load_config(&config.unwrap_or_else(default_config_path)) {
            Ok(c) => {
                println!("ok: {} host(s)", c.hosts.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{}", e.message);
                ExitCode::FAILURE
            }
        },
        Commands::Serve { config } => match serve(&config.unwrap_or_else(default_config_path)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sentinel-ssh: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::Schemas => {
            println!("{}", serde_json::to_string_pretty(&tool_schemas()).expect("schemas serialise"));
            ExitCode::SUCCESS
        }
    }
}
