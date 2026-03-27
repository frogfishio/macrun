// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

const TOP_LEVEL_LONG_ABOUT: &str = "macrun stores local development secrets in macOS Keychain and injects them into child processes only when you ask it to.\n\nIt is designed to replace ad hoc .env files and broad shell exports with project-aware, env-aware secret injection.";

const TOP_LEVEL_AFTER_HELP: &str = "Examples:\n  macrun set URL=https://somewhere\n  macrun init --project my-app --env dev\n  macrun exec -- cargo run\n  macrun env --format json\n\nUse `macrun exec --help`, `macrun vault --help`, and `macrun archive --help` for advanced workflows.";

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

    #[arg(long, global = true, value_name = "ENV", help = "Override the resolved env scope")]
    pub env: Option<String>,

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
    #[command(about = "Bind the current working tree to a named project and env")]
    Init {
        #[arg(long, value_name = "PROJECT", help = "Project name to bind to this tree")]
        project: Option<String>,

        #[arg(long, value_name = "ENV", help = "Default env for this tree")]
        env: Option<String>,

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

        #[arg(long, default_value = "import", help = "Metadata source label for imported secrets")]
        source: String,
    },
    #[command(about = "List stored secret names for the active scope")]
    List {
        #[arg(long, help = "Show source, update time, and note metadata")]
        show_metadata: bool,
    },
    #[command(
        about = "Run a command with every secret from the active scope injected",
        after_help = "Examples:\n  macrun exec -- cargo run\n  macrun exec -- python3 server.py\n  macrun exec --vault-encrypt APP_CLIENT_SECRET=APP_SECRET_CIPHERTEXT --vault-addr http://127.0.0.1:8200 --vault-key app-secrets -- app"
    )]
    Exec {
        #[arg(
            long,
            value_name = "SRC[=DST]",
            help = "Replace a plaintext secret with Vault Transit ciphertext in the child environment"
        )]
        vault_encrypt: Vec<String>,

        #[arg(
            long,
            value_name = "URL",
            help = "Vault base URL for --vault-encrypt, for example http://127.0.0.1:8200"
        )]
        vault_addr: Option<String>,

        #[arg(
            long,
            default_value = "transit",
            value_name = "PATH",
            help = "Transit mount path for --vault-encrypt"
        )]
        transit_path: String,

        #[arg(
            long,
            value_name = "KEY",
            help = "Vault transit key name for --vault-encrypt"
        )]
        vault_key: Option<String>,

        #[arg(last = true, required = true, value_name = "COMMAND", help = "Command to execute after --")]
        command: Vec<String>,
    },
    #[command(about = "Print all secrets in the active scope as shell exports or JSON")]
    Env {
        #[arg(long, value_enum, default_value = "shell", help = "Output format")]
        format: EnvFormat,
    },
    #[command(about = "Remove one or more stored secrets from the active scope")]
    Unset {
        #[arg(required = true, value_name = "NAME", help = "Secret names to remove")]
        names: Vec<String>,
    },
    #[command(about = "Delete every stored secret in the active project/env scope")]
    Purge {
        #[arg(long, help = "Required confirmation for destructive purge")]
        yes: bool,
    },
    #[command(about = "Transfer stored secrets into Vault for bootstrap workflows")]
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    #[command(about = "Manage the global master secret used for encrypted archive files")]
    Master {
        #[command(subcommand)]
        command: MasterCommands,
    },
    #[command(about = "Export and import encrypted .env.macrun files")]
    Archive {
        #[command(subcommand)]
        command: ArchiveCommands,
    },
    #[command(about = "Inspect resolved scope and local macrun state")]
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum VaultCommands {
    #[command(
        about = "Encrypt a stored secret using Vault transit",
        long_about = "Read a stored secret from Keychain, encrypt it with Vault transit, and print ciphertext for use in an application database or another downstream system.",
        after_help = "Example:\n  macrun vault encrypt APP_CLIENT_SECRET --vault-addr http://127.0.0.1:8200 --vault-key app-secrets --verify-decrypt"
    )]
    Encrypt {
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
    #[command(
        about = "Write one or more stored secrets into Vault KV",
        long_about = "Read one or more stored secrets from Keychain and write them into Vault KV so applications can fetch them directly from Vault instead of storing them in a database.",
        after_help = "Examples:\n  macrun vault push APP_CLIENT_SECRET --vault-addr http://127.0.0.1:8200 --path apps/my-app/dev\n  macrun vault push APP_CLIENT_SECRET API_TOKEN --vault-addr http://127.0.0.1:8200 --mount secret --path apps/my-app/dev --kv-version v2"
    )]
    Push {
        #[arg(required = true, value_name = "ENV_KEY", help = "Stored secret names to write into Vault")]
        env_keys: Vec<String>,

        #[arg(long, value_name = "URL", help = "Vault base URL, for example http://127.0.0.1:8200")]
        vault_addr: String,

        #[arg(long, default_value = "secret", value_name = "MOUNT", help = "Vault KV mount name")]
        mount: String,

        #[arg(long, value_name = "PATH", help = "Logical Vault KV path below the mount")]
        path: String,

        #[arg(long, value_enum, default_value = "v2", help = "Vault KV engine version")]
        kv_version: KvVersionArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum MasterCommands {
    #[command(
        about = "Set the global master secret without printing it back",
        after_help = "Examples:\n  macrun master set\n  printf '%s' 'correct horse battery staple' | macrun master set --stdin"
    )]
    Set {
        #[arg(long, help = "Read the master secret from stdin instead of prompting")]
        stdin: bool,
    },
    #[command(about = "Clear the global master secret from Keychain")]
    Clear,
    #[command(about = "Show whether the global master secret is configured")]
    Status,
}

#[derive(Debug, Subcommand)]
pub enum ArchiveCommands {
    #[command(
        about = "Export an encrypted .env.macrun file",
        after_help = "Resolution rules match every other command: --project/--env first, then local config, then (default)/dev.\n\nExamples:\n  macrun archive export --mode scope --file .env.macrun\n  macrun --project my-app archive export --mode project --file my-app.macrun"
    )]
    Export {
        #[arg(short = 'f', long, default_value = ".env.macrun", value_name = "FILE", help = "Path to the encrypted archive file")]
        file: PathBuf,

        #[arg(long, value_enum, default_value = "scope", help = "What to export: the resolved project/env scope, or the resolved project's whole bundle")]
        mode: ArchiveExportMode,
    },
    #[command(
        about = "Import an encrypted .env.macrun file back into Keychain",
        after_help = "Examples:\n  macrun archive import --file .env.macrun\n  macrun archive import --file .env.macrun --replace"
    )]
    Import {
        #[arg(short = 'f', long, default_value = ".env.macrun", value_name = "FILE", help = "Path to the encrypted archive file")]
        file: PathBuf,

        #[arg(long, help = "Replace existing stored values when keys already exist")]
        replace: bool,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum ArchiveExportMode {
    #[value(help = "Export the resolved project/env scope")]
    Scope,
    #[value(help = "Export the resolved project, including all envs in that project")]
    Project,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum EnvFormat {
    Shell,
    Json,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum KvVersionArg {
    V1,
    V2,
}
