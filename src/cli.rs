// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

const TOP_LEVEL_LONG_ABOUT: &str =
    "Keep secrets in macOS Keychain and give them to commands when they run.";

const TOP_LEVEL_AFTER_HELP: &str = "Examples:\n  macrun set API_TOKEN\n  macrun set myapp API_TOKEN\n  macrun set myapp staging API_TOKEN\n  macrun run myapp staging -- npm start";

#[derive(Debug, Parser)]
#[command(
    name = "macrun",
    disable_version_flag = true,
    disable_help_subcommand = true,
    about = "Secrets for local commands",
    long_about = TOP_LEVEL_LONG_ABOUT,
    after_help = TOP_LEVEL_AFTER_HELP,
    next_line_help = true
)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        hide = true,
        value_name = "PROJECT",
        help = "Override the resolved project scope"
    )]
    pub project: Option<String>,

    #[arg(
        long,
        global = true,
        hide = true,
        value_name = "ENV",
        help = "Override the resolved env scope"
    )]
    pub env: Option<String>,

    #[arg(
        long,
        global = true,
        hide = true,
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
    #[command(
        hide = true,
        about = "Bind the current working tree to a named project and env"
    )]
    Init {
        #[arg(
            long,
            value_name = "PROJECT",
            help = "Project name to bind to this tree"
        )]
        project: Option<String>,

        #[arg(long, value_name = "ENV", help = "Default env for this tree")]
        env: Option<String>,

        #[arg(long, help = "Overwrite an existing .macrun.toml file")]
        force: bool,
    },
    #[command(
        about = "Save a secret in Keychain",
        after_help = "Examples:\n  macrun set API_TOKEN\n  macrun set myapp API_TOKEN\n  macrun set myapp staging API_TOKEN\n\nThe value is prompted for securely. For automation, use --stdin or --from-env."
    )]
    Set {
        #[arg(
            required = true,
            num_args = 1..=3,
            value_name = "SCOPE",
            help = "SECRET, PROJECT SECRET, or PROJECT ENVIRONMENT SECRET"
        )]
        parts: Vec<String>,

        #[arg(
            long,
            conflicts_with = "from_env",
            help = "Read the value from standard input"
        )]
        stdin: bool,

        #[arg(
            long,
            value_name = "VARIABLE",
            help = "Read the value from an environment variable"
        )]
        from_env: Option<String>,

        #[arg(
            long,
            hide = true,
            default_value = "manual",
            help = "Metadata source label for stored secrets"
        )]
        source: String,

        #[arg(
            long,
            hide = true,
            help = "Optional metadata note stored alongside the index entry"
        )]
        note: Option<String>,
    },
    #[command(hide = true, about = "Print a single stored secret value")]
    Get {
        #[arg(value_name = "NAME", help = "Secret name to read")]
        name: String,
    },
    #[command(hide = true, about = "Import secrets from a dotenv-style file")]
    Import {
        #[arg(
            short = 'f',
            long,
            value_name = "FILE",
            help = "Path to the source env file"
        )]
        file: PathBuf,

        #[arg(long, help = "Replace existing stored values when keys already exist")]
        replace: bool,

        #[arg(
            long,
            default_value = "import",
            help = "Metadata source label for imported secrets"
        )]
        source: String,
    },
    #[command(about = "List secret names")]
    List {
        #[arg(
            num_args = 0..=2,
            value_name = "SCOPE",
            help = "Nothing, PROJECT, or PROJECT ENVIRONMENT"
        )]
        scope: Vec<String>,

        #[arg(
            long,
            hide = true,
            help = "Show source, update time, and note metadata"
        )]
        show_metadata: bool,
    },
    #[command(
        about = "Run a command with its secrets",
        after_help = "Examples:\n  macrun run -- env\n  macrun run myapp -- npm start\n  macrun run myapp staging -- npm start"
    )]
    Run {
        #[arg(
            num_args = 0..=2,
            value_name = "SCOPE",
            help = "Nothing, PROJECT, or PROJECT ENVIRONMENT"
        )]
        scope: Vec<String>,

        #[arg(
            last = true,
            required = true,
            value_name = "COMMAND",
            help = "Command to run after --"
        )]
        command: Vec<String>,
    },
    #[command(
        hide = true,
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

        #[arg(
            last = true,
            required = true,
            value_name = "COMMAND",
            help = "Command to execute after --"
        )]
        command: Vec<String>,
    },
    #[command(
        hide = true,
        about = "Print all secrets in the active scope as shell exports or JSON"
    )]
    Env {
        #[arg(long, value_enum, default_value = "shell", help = "Output format")]
        format: EnvFormat,
    },
    #[command(hide = true, about = "Remove a secret")]
    Remove {
        #[arg(
            required = true,
            num_args = 1..=3,
            value_name = "SCOPE",
            help = "SECRET, PROJECT SECRET, or PROJECT ENVIRONMENT SECRET"
        )]
        parts: Vec<String>,
    },
    #[command(about = "Unset a secret")]
    Unset {
        #[arg(
            required = true,
            num_args = 1..=3,
            value_name = "SCOPE",
            help = "SECRET, PROJECT SECRET, or PROJECT ENVIRONMENT SECRET"
        )]
        parts: Vec<String>,
    },
    #[command(
        hide = true,
        about = "Delete every stored secret in the active project/env scope"
    )]
    Purge {
        #[arg(long, help = "Required confirmation for destructive purge")]
        yes: bool,
    },
    #[command(
        hide = true,
        about = "Transfer stored secrets into Vault for bootstrap workflows"
    )]
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    #[command(
        hide = true,
        about = "Manage the global master secret used for encrypted archive files"
    )]
    Master {
        #[command(subcommand)]
        command: MasterCommands,
    },
    #[command(hide = true, about = "Export and import encrypted .env.macrun files")]
    Archive {
        #[command(subcommand)]
        command: ArchiveCommands,
    },
    #[command(hide = true, about = "Inspect resolved scope and local macrun state")]
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

        #[arg(
            long,
            value_name = "URL",
            help = "Vault base URL, for example http://127.0.0.1:8200"
        )]
        vault_addr: String,

        #[arg(
            long,
            default_value = "transit",
            value_name = "PATH",
            help = "Transit mount path inside Vault"
        )]
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
        #[arg(
            required = true,
            value_name = "ENV_KEY",
            help = "Stored secret names to write into Vault"
        )]
        env_keys: Vec<String>,

        #[arg(
            long,
            value_name = "URL",
            help = "Vault base URL, for example http://127.0.0.1:8200"
        )]
        vault_addr: String,

        #[arg(
            long,
            default_value = "secret",
            value_name = "MOUNT",
            help = "Vault KV mount name"
        )]
        mount: String,

        #[arg(
            long,
            value_name = "PATH",
            help = "Logical Vault KV path below the mount"
        )]
        path: String,

        #[arg(
            long,
            value_enum,
            default_value = "v2",
            help = "Vault KV engine version"
        )]
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
        #[arg(
            short = 'f',
            long,
            default_value = ".env.macrun",
            value_name = "FILE",
            help = "Path to the encrypted archive file"
        )]
        file: PathBuf,

        #[arg(
            long,
            value_enum,
            default_value = "scope",
            help = "What to export: the resolved project/env scope, or the resolved project's whole bundle"
        )]
        mode: ArchiveExportMode,
    },
    #[command(
        about = "Import an encrypted .env.macrun file back into Keychain",
        after_help = "Examples:\n  macrun archive import --file .env.macrun\n  macrun archive import --file .env.macrun --replace"
    )]
    Import {
        #[arg(
            short = 'f',
            long,
            default_value = ".env.macrun",
            value_name = "FILE",
            help = "Path to the encrypted archive file"
        )]
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

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Commands};

    #[test]
    fn set_accepts_project_environment_and_secret() {
        let cli = Cli::try_parse_from(["macrun", "set", "shop", "staging", "API_TOKEN", "--stdin"])
            .unwrap();
        match cli.command.unwrap() {
            Commands::Set { parts, stdin, .. } => {
                assert_eq!(parts, ["shop", "staging", "API_TOKEN"]);
                assert!(stdin);
            }
            _ => panic!("expected set"),
        }
    }

    #[test]
    fn run_keeps_scope_separate_from_the_command() {
        let cli = Cli::try_parse_from(["macrun", "run", "shop", "staging", "--", "npm", "start"])
            .unwrap();
        match cli.command.unwrap() {
            Commands::Run { scope, command } => {
                assert_eq!(scope, ["shop", "staging"]);
                assert_eq!(command, ["npm", "start"]);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn unset_uses_the_same_scope_shape_as_set() {
        let cli = Cli::try_parse_from(["macrun", "unset", "shop", "staging", "API_TOKEN"]).unwrap();
        match cli.command.unwrap() {
            Commands::Unset { parts } => {
                assert_eq!(parts, ["shop", "staging", "API_TOKEN"]);
            }
            _ => panic!("expected unset"),
        }
    }

    #[test]
    fn normal_help_only_shows_the_four_everyday_commands() {
        let help = Cli::command().render_long_help().to_string();
        for command in ["set", "list", "run", "unset"] {
            assert!(help.contains(command));
        }
        for hidden in ["remove", "init", "exec", "vault", "archive", "doctor"] {
            assert!(!help.contains(&format!("  {hidden}\n")));
        }
    }
}
