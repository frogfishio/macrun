// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

mod app;
mod cli;
mod config;
mod index;
mod keychain;
mod sealed;
mod util;
mod vault;

use std::process::ExitCode;

use anyhow::Result;
use clap::{CommandFactory, Parser};

use crate::app::App;
use crate::cli::Cli;

const LICENSE_TEXT: &str = "Copyright (c) Alexander R. Croft\nLicensed under the GNU General Public License, version 3 or any later version (GPL-3.0-or-later).";

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
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("{}-build {}", repo_version(), repo_build());
        return Ok(ExitCode::SUCCESS);
    }

    if args.iter().any(|arg| arg == "--license") {
        println!("{LICENSE_TEXT}");
        return Ok(ExitCode::SUCCESS);
    }

    let cli = Cli::parse();

    if cli.show_version {
        println!("{}-build {}", repo_version(), repo_build());
        return Ok(ExitCode::SUCCESS);
    }

    if cli.show_license {
        println!("{LICENSE_TEXT}");
        return Ok(ExitCode::SUCCESS);
    }

    if cli.command.is_none() {
        let mut command = Cli::command();
        command.print_long_help()?;
        println!();
        return Ok(ExitCode::from(2));
    }

    let app = App::load()?;
    app.execute(cli)
}

fn repo_version() -> &'static str {
    include_str!("../VERSION").trim()
}

fn repo_build() -> &'static str {
    include_str!("../BUILD").trim()
}
