#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use sentinel_gateway::cli::{Cli, Commands, ConfigCommands};
use sentinel_gateway::config::{default_config_path, load_config};
use sentinel_gateway::doctor::run_doctor;

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
        Commands::Serve { .. } | Commands::Schemas => {
            eprintln!("not implemented");
            ExitCode::FAILURE
        }
    }
}
