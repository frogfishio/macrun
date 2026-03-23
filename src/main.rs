mod app;
mod cli;
mod config;
mod index;
mod k2mx;
mod keychain;
mod util;
mod vault;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use crate::app::App;
use crate::cli::Cli;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let app = App::load()?;
    app.execute(cli)
}