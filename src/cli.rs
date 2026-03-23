// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

const TOP_LEVEL_LONG_ABOUT: &str = "macrun stores local development secrets in macOS Keychain and injects them into child processes only when you ask it to.\n\nIt is designed to replace ad hoc .env files and broad shell exports with project-aware, profile-aware secret injection.";

const TOP_LEVEL_AFTER_HELP: &str = "Examples:\n  macrun init --project my-app --profile dev\n  macrun import -f .env\n  macrun exec --prefix APP_ -- cargo run\n  macrun vault push APP_CLIENT_SECRET --vault-addr http://127.0.0.1:8200 --vault-key app-secrets\n\nUse `macrun <command> --help` for command-specific guidance.";

#[derive(Debug, Parser)]
#[command(
    name = "macrun",
    disable_version_flag = true,
    disable_help_subcommand = true,
    about = "Project-aware local secrets for macOS Keychain",
    long_about = TOP_LEVEL_LONG_ABOUT,
    after_help = TOP_LEVEL_AFTER_HELP,
    next_line_help = true
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PROJECT",
        help = "Override the resolved project scope"
    )]
    pub project: Option<String>,

    #[arg(
        long,
        global = true,
        value_name = "PROFILE",
        help = "Override the resolved profile scope"
    )]
    pub profile: Option<String>,

    #[arg(
        long,
        global = true,
        action = ArgAction::SetTrue,
        help = "Print JSON output when the command supports it"
    )]
    pub json: bool,

    #[arg(
        long = "version",
        short = 'V',
        global = true,
        action = ArgAction::SetTrue,
        help = "Print version and build metadata"
    )]
    pub show_version: bool,

    #[arg(
        long = "license",
        global = true,
        action = ArgAction::SetTrue,
        help = "Print copyright and license information"
    )]
    pub show_license: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Bind the current working tree to a project and default profile")]
    Init {
        #[arg(long, value_name = "PROJECT", help = "Project name to bind to this tree")]
        project: Option<String>,

        #[arg(long, value_name = "PROFILE", help = "Default profile for this tree")]
        profile: Option<String>,

        #[arg(long, help = "Overwrite an existing .macrun.toml file")]
        force: bool,
    },
    #[command(about = "Store one or more NAME=value pairs in Keychain")]
    Set {
        #[arg(required = true, value_name = "NAME=value", help = "Secret assignments to store")]
        pairs: Vec<String>,

        #[arg(long, default_value = "manual", help = "Metadata source label for stored secrets")]
        source: String,

        #[arg(long, help = "Optional metadata note stored alongside the index entry")]
        note: Option<String>,
    },
    #[command(about = "Print a single stored secret value")]
    Get {
        #[arg(value_name = "NAME", help = "Secret name to read")]
        name: String,
    },
    #[command(about = "Import secrets from a dotenv-style file")]
    Import {
        #[arg(short = 'f', long, value_name = "FILE", help = "Path to the source env file")]
        file: PathBuf,

        #[arg(long, help = "Replace existing stored values when keys already exist")]
        replace: bool,

        #[arg(long = "prefix", value_name = "PREFIX", help = "Import only keys that start with this prefix")]
        prefixes: Vec<String>,

        #[arg(long, default_value = "import", help = "Metadata source label for imported secrets")]
        source: String,
    },
    #[command(about = "List stored secret names for the active scope")]
    List {
        #[arg(long, help = "Show source, update time, and note metadata")]
        show_metadata: bool,

        #[arg(long = "prefix", value_name = "PREFIX", help = "List only keys that start with this prefix")]
        prefixes: Vec<String>,
    },
    #[command(
        about = "Run a command with selected secrets injected",
        after_help = "Examples:\n  macrun exec --prefix APP_ -- cargo run\n  macrun exec --only APP_DATABASE_URL --only APP_SESSION_SECRET -- python3 server.py"
    )]
    Exec {
        #[arg(long = "only", value_name = "NAME", help = "Inject only this specific key")]
        only: Vec<String>,

        #[arg(long = "prefix", value_name = "PREFIX", help = "Inject all keys that start with this prefix")]
        prefixes: Vec<String>,

        #[arg(last = true, required = true, value_name = "COMMAND", help = "Command to execute after --")]
        command: Vec<String>,
    },
    #[command(about = "Print selected secrets as shell exports or JSON")]
    Env {
        #[arg(long, value_enum, default_value = "shell", help = "Output format")]
        format: EnvFormat,

        #[arg(long = "only", value_name = "NAME", help = "Print only this specific key")]
        only: Vec<String>,

        #[arg(long = "prefix", value_name = "PREFIX", help = "Print only keys that start with this prefix")]
        prefixes: Vec<String>,
    },
    #[command(about = "Remove one or more stored secrets from the active scope")]
    Unset {
        #[arg(required = true, value_name = "NAME", help = "Secret names to remove")]
        names: Vec<String>,
    },
    #[command(about = "Delete every stored secret in the active project/profile scope")]
    Purge {
        #[arg(long, help = "Required confirmation for destructive purge")]
        yes: bool,
    },
    #[command(about = "Encrypt a stored secret with Vault transit")]
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    #[command(about = "Inspect resolved scope and local macrun state")]
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum VaultCommands {
    #[command(
        about = "Encrypt a stored secret using Vault transit",
        long_about = "Read a stored secret from Keychain, encrypt it with Vault transit, and print safe metadata without ever printing plaintext.",
        after_help = "Example:\n  macrun vault push APP_CLIENT_SECRET --vault-addr http://127.0.0.1:8200 --vault-key app-secrets --verify-decrypt"
    )]
    Push {
        #[arg(value_name = "ENV_KEY", help = "Stored secret name to encrypt")]
        env_key: String,

        #[arg(long, value_name = "URL", help = "Vault base URL, for example http://127.0.0.1:8200")]
        vault_addr: String,

        #[arg(long, default_value = "transit", value_name = "PATH", help = "Transit mount path inside Vault")]
        transit_path: String,

        #[arg(long, value_name = "KEY", help = "Vault transit key name")]
        vault_key: String,

        #[arg(long, help = "Verify a decrypt round-trip without printing plaintext")]
        verify_decrypt: bool,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum EnvFormat {
    Shell,
    Json,
}
