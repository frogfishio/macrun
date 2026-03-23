use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "macrun", version, about = "Keychain-backed local development secrets")]
pub struct Cli {
    #[arg(long, global = true)]
    pub project: Option<String>,

    #[arg(long, global = true)]
    pub profile: Option<String>,

    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Init {
        #[arg(long)]
        project: Option<String>,

        #[arg(long)]
        profile: Option<String>,

        #[arg(long)]
        force: bool,
    },
    Set {
        #[arg(required = true, value_name = "NAME=value")]
        pairs: Vec<String>,

        #[arg(long, default_value = "manual")]
        source: String,

        #[arg(long)]
        note: Option<String>,
    },
    Get {
        name: String,
    },
    Import {
        #[arg(short = 'f', long)]
        file: PathBuf,

        #[arg(long)]
        replace: bool,

        #[arg(long = "prefix")]
        prefixes: Vec<String>,

        #[arg(long, default_value = "import")]
        source: String,
    },
    List {
        #[arg(long)]
        show_metadata: bool,

        #[arg(long = "prefix")]
        prefixes: Vec<String>,
    },
    Exec {
        #[arg(long = "only")]
        only: Vec<String>,

        #[arg(long = "prefix")]
        prefixes: Vec<String>,

        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    Env {
        #[arg(long, value_enum, default_value = "shell")]
        format: EnvFormat,

        #[arg(long = "only")]
        only: Vec<String>,

        #[arg(long = "prefix")]
        prefixes: Vec<String>,
    },
    Unset {
        #[arg(required = true)]
        names: Vec<String>,
    },
    Purge {
        #[arg(long)]
        yes: bool,
    },
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum VaultCommands {
    Push {
        env_key: String,

        #[arg(long)]
        vault_addr: String,

        #[arg(long, default_value = "transit")]
        transit_path: String,

        #[arg(long)]
        vault_key: String,

        #[arg(long)]
        provider: String,

        #[arg(long)]
        name: String,

        #[arg(long)]
        k2mx_base_url: Option<String>,

        #[arg(long)]
        k2mx_bootstrap_token: Option<String>,

        #[arg(long)]
        provider_id: Option<String>,

        #[arg(long)]
        version: Option<String>,

        #[arg(long)]
        tenant_id: Option<String>,

        #[arg(long)]
        client_id: Option<String>,

        #[arg(long)]
        active_from: Option<String>,

        #[arg(long)]
        retired_at: Option<String>,

        #[arg(long)]
        dry_run: bool,

        #[arg(long)]
        verify_decrypt: bool,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum EnvFormat {
    Shell,
    Json,
}
