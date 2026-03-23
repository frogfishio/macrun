// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{anyhow, bail, Context, Result};
use directories::ProjectDirs;

use crate::cli::{Cli, Commands, EnvFormat, VaultCommands};
use crate::config::{find_local_config, LocalConfig, ResolvedScope, CONFIG_FILE_NAME};
use crate::index::{IndexFile, StoredSecretMeta};
use crate::keychain::{delete_secret, read_secret, store_secret};
use crate::util::{parse_env_file, parse_pair, select_entries, shell_quote, validate_env_name};
use crate::vault::{parse_key_version, VaultClient};

pub struct App {
    state_dir: PathBuf,
    index_path: PathBuf,
}

impl App {
    pub fn load() -> Result<Self> {
        let dirs = ProjectDirs::from("io", "frogfish", "macrun")
            .ok_or_else(|| anyhow!("could not resolve application directories"))?;
        let state_dir = dirs.config_dir().to_path_buf();
        let index_path = state_dir.join("index.json");
        fs::create_dir_all(&state_dir).with_context(|| {
            format!("failed to create state directory {}", state_dir.display())
        })?;
        Ok(Self {
            state_dir,
            index_path,
        })
    }

    pub fn execute(&self, cli: Cli) -> Result<ExitCode> {
        match cli.command {
            Some(Commands::Init {
                project,
                profile,
                force,
            }) => self.init(project.or(cli.project), profile.or(cli.profile), force, cli.json),
            Some(Commands::Set { pairs, source, note }) => {
                let scope = self.resolve_scope(cli.project, cli.profile)?;
                self.set_pairs(&scope, pairs, &source, note, cli.json)
            }
            Some(Commands::Get { name }) => {
                let scope = self.resolve_scope(cli.project, cli.profile)?;
                self.get_secret(&scope, &name, cli.json)
            }
            Some(Commands::Import {
                file,
                replace,
                prefixes,
                source,
            }) => {
                let scope = self.resolve_scope(cli.project, cli.profile)?;
                self.import_file(&scope, &file, replace, &prefixes, &source, cli.json)
            }
            Some(Commands::List {
                show_metadata,
                prefixes,
            }) => {
                let scope = self.resolve_scope(cli.project, cli.profile)?;
                self.list_entries(&scope, show_metadata, &prefixes, cli.json)
            }
            Some(Commands::Exec {
                only,
                prefixes,
                command,
            }) => {
                let scope = self.resolve_scope(cli.project, cli.profile)?;
                self.exec_command(&scope, &only, &prefixes, &command)
            }
            Some(Commands::Env {
                format,
                only,
                prefixes,
            }) => {
                let scope = self.resolve_scope(cli.project, cli.profile)?;
                self.print_env(&scope, &format, &only, &prefixes)
            }
            Some(Commands::Unset { names }) => {
                let scope = self.resolve_scope(cli.project, cli.profile)?;
                self.unset_names(&scope, &names, cli.json)
            }
            Some(Commands::Purge { yes }) => {
                let scope = self.resolve_scope(cli.project, cli.profile)?;
                self.purge_scope(&scope, yes, cli.json)
            }
            Some(Commands::Vault { command }) => {
                let scope = self.resolve_scope(cli.project, cli.profile)?;
                match command {
                    VaultCommands::Push {
                        env_key,
                        vault_addr,
                        transit_path,
                        vault_key,
                        verify_decrypt,
                    } => self.vault_push(
                        &scope,
                        &env_key,
                        &vault_addr,
                        &transit_path,
                        &vault_key,
                        verify_decrypt,
                        cli.json,
                    ),
                }
            }
            Some(Commands::Doctor) => self.doctor(cli.project, cli.profile, cli.json),
            None => bail!("no command provided"),
        }
    }

    fn vault_push(
        &self,
        scope: &ResolvedScope,
        env_key: &str,
        vault_addr: &str,
        transit_path: &str,
        vault_key: &str,
        verify_decrypt: bool,
        json: bool,
    ) -> Result<ExitCode> {
        validate_env_name(env_key)?;
        let plaintext = read_secret(&scope.project, &scope.profile, env_key)?;
        let vault = VaultClient::from_env(vault_addr, transit_path)?;
        let encrypted = vault.encrypt(vault_key, plaintext.as_bytes())?;
        let key_version = parse_key_version(&encrypted.ciphertext);
        let decrypt_verified = if verify_decrypt {
            let round_trip = vault.decrypt(vault_key, &encrypted.ciphertext)?;
            round_trip == plaintext
        } else {
            false
        };

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": scope.project,
                    "profile": scope.profile,
                    "env_key": env_key,
                    "vault_addr": vault_addr,
                    "transit_path": transit_path,
                    "vault_key": vault_key,
                    "ciphertext_length": encrypted.ciphertext.len(),
                    "key_version": key_version,
                    "verified_decrypt": decrypt_verified,
                    "mode": "encrypted",
                }))?
            );
        } else {
            println!("prepared Vault transit ciphertext");
            println!("project: {}", scope.project);
            println!("profile: {}", scope.profile);
            println!("env key: {env_key}");
            println!("vault addr: {vault_addr}");
            println!("transit path: {transit_path}");
            println!("vault key: {vault_key}");
            println!("ciphertext length: {}", encrypted.ciphertext.len());
            if let Some(version) = key_version {
                println!("key version: {version}");
            }
            println!(
                "verified decrypt: {}",
                if decrypt_verified { "yes" } else { "no" }
            );
        }

        Ok(ExitCode::SUCCESS)
    }

    fn init(
        &self,
        project: Option<String>,
        profile: Option<String>,
        force: bool,
        json: bool,
    ) -> Result<ExitCode> {
        let cwd = env::current_dir().context("failed to determine current working directory")?;
        let project = project.ok_or_else(|| anyhow!("`macrun init` requires --project NAME"))?;
        let profile = profile.unwrap_or_else(|| "dev".to_owned());
        let config_path = cwd.join(CONFIG_FILE_NAME);

        if config_path.exists() && !force {
            bail!(
                "{} already exists; pass --force to overwrite",
                config_path.display()
            );
        }

        let config = LocalConfig {
            project: project.clone(),
            default_profile: profile.clone(),
        };
        let toml = toml::to_string_pretty(&config).context("failed to serialize local config")?;
        fs::write(&config_path, toml).with_context(|| {
            format!("failed to write local config {}", config_path.display())
        })?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": project,
                    "profile": profile,
                    "config_path": config_path,
                }))?
            );
        } else {
            println!("initialized {}", config_path.display());
            println!("project: {project}");
            println!("default profile: {profile}");
        }

        Ok(ExitCode::SUCCESS)
    }

    fn set_pairs(
        &self,
        scope: &ResolvedScope,
        pairs: Vec<String>,
        source: &str,
        note: Option<String>,
        json: bool,
    ) -> Result<ExitCode> {
        let mut index = self.load_index()?;
        let mut written = Vec::new();

        for pair in pairs {
            let (name, value) = parse_pair(&pair)?;
            store_secret(&scope.project, &scope.profile, &name, &value)?;
            index.upsert(StoredSecretMeta::new(
                scope.project.clone(),
                scope.profile.clone(),
                name.clone(),
                source.to_owned(),
                note.clone(),
            ));
            written.push(name);
        }

        self.save_index(&index)?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": scope.project,
                    "profile": scope.profile,
                    "written": written,
                }))?
            );
        } else {
            println!(
                "stored {} secret(s) for {}/{}",
                written.len(),
                scope.project,
                scope.profile
            );
            for name in written {
                println!("- {name}");
            }
        }

        Ok(ExitCode::SUCCESS)
    }

    fn get_secret(&self, scope: &ResolvedScope, name: &str, json: bool) -> Result<ExitCode> {
        let value = read_secret(&scope.project, &scope.profile, name)?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": scope.project,
                    "profile": scope.profile,
                    "name": name,
                    "value": value,
                }))?
            );
        } else {
            println!("{value}");
        }
        Ok(ExitCode::SUCCESS)
    }

    fn import_file(
        &self,
        scope: &ResolvedScope,
        file: &Path,
        replace: bool,
        prefixes: &[String],
        source: &str,
        json: bool,
    ) -> Result<ExitCode> {
        let contents = fs::read_to_string(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let parsed = parse_env_file(&contents)?;
        let mut index = self.load_index()?;
        let mut imported = Vec::new();
        let mut skipped = Vec::new();

        for (name, value) in parsed {
            if !prefixes.is_empty() && !prefixes.iter().any(|prefix| name.starts_with(prefix)) {
                skipped.push(name);
                continue;
            }

            if !replace && index.contains(&scope.project, &scope.profile, &name) {
                skipped.push(name);
                continue;
            }

            store_secret(&scope.project, &scope.profile, &name, &value)?;
            index.upsert(StoredSecretMeta::new(
                scope.project.clone(),
                scope.profile.clone(),
                name.clone(),
                source.to_owned(),
                Some(format!("imported from {}", file.display())),
            ));
            imported.push(name);
        }

        self.save_index(&index)?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": scope.project,
                    "profile": scope.profile,
                    "file": file,
                    "imported": imported,
                    "skipped": skipped,
                }))?
            );
        } else {
            println!(
                "imported {} secret(s) into {}/{}",
                imported.len(),
                scope.project,
                scope.profile
            );
            if !skipped.is_empty() {
                println!("skipped {} key(s)", skipped.len());
            }
        }

        Ok(ExitCode::SUCCESS)
    }

    fn list_entries(
        &self,
        scope: &ResolvedScope,
        show_metadata: bool,
        prefixes: &[String],
        json: bool,
    ) -> Result<ExitCode> {
        let index = self.load_index()?;
        let entries = index.filtered_entries(&scope.project, &scope.profile, prefixes);
        if json {
            println!("{}", serde_json::to_string_pretty(&entries)?);
            return Ok(ExitCode::SUCCESS);
        }

        if entries.is_empty() {
            println!("no secrets stored for {}/{}", scope.project, scope.profile);
            return Ok(ExitCode::SUCCESS);
        }

        for entry in entries {
            if show_metadata {
                println!(
                    "{}\tsource={}\tupdated_at={}{}",
                    entry.key,
                    entry.source,
                    entry.updated_at,
                    entry
                        .note
                        .as_ref()
                        .map(|note| format!("\tnote={note}"))
                        .unwrap_or_default()
                );
            } else {
                println!("{}", entry.key);
            }
        }

        Ok(ExitCode::SUCCESS)
    }

    fn exec_command(
        &self,
        scope: &ResolvedScope,
        only: &[String],
        prefixes: &[String],
        command: &[String],
    ) -> Result<ExitCode> {
        let env_map = self.selected_env(scope, only, prefixes)?;
        if env_map.is_empty() {
            bail!("no secrets matched the current selection");
        }

        let program = command
            .first()
            .ok_or_else(|| anyhow!("exec requires a command after `--`"))?;
        let args = &command[1..];

        eprintln!(
            "macrun: exec project={} profile={} keys={}",
            scope.project,
            scope.profile,
            env_map.len()
        );

        let status = Command::new(program)
            .args(args)
            .envs(&env_map)
            .status()
            .with_context(|| format!("failed to execute `{program}`"))?;

        if let Some(code) = status.code() {
            Ok(ExitCode::from(code as u8))
        } else {
            Ok(ExitCode::from(1))
        }
    }

    fn print_env(
        &self,
        scope: &ResolvedScope,
        format: &EnvFormat,
        only: &[String],
        prefixes: &[String],
    ) -> Result<ExitCode> {
        let env_map = self.selected_env(scope, only, prefixes)?;
        match format {
            EnvFormat::Shell => {
                for (key, value) in env_map {
                    println!("export {}={}", key, shell_quote(&value));
                }
            }
            EnvFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&env_map)?);
            }
        }
        Ok(ExitCode::SUCCESS)
    }

    fn unset_names(
        &self,
        scope: &ResolvedScope,
        names: &[String],
        json: bool,
    ) -> Result<ExitCode> {
        let mut index = self.load_index()?;
        let mut removed = Vec::new();
        for name in names {
            delete_secret(&scope.project, &scope.profile, name)?;
            index.remove(&scope.project, &scope.profile, name);
            removed.push(name.clone());
        }
        self.save_index(&index)?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": scope.project,
                    "profile": scope.profile,
                    "removed": removed,
                }))?
            );
        } else {
            println!("removed {} secret(s)", removed.len());
        }
        Ok(ExitCode::SUCCESS)
    }

    fn purge_scope(&self, scope: &ResolvedScope, yes: bool, json: bool) -> Result<ExitCode> {
        if !yes {
            bail!("purge is destructive; re-run with --yes");
        }

        let mut index = self.load_index()?;
        let keys: Vec<String> = index
            .entries_for_scope(&scope.project, &scope.profile)
            .into_iter()
            .map(|entry| entry.key.clone())
            .collect();

        for key in &keys {
            delete_secret(&scope.project, &scope.profile, key)?;
            index.remove(&scope.project, &scope.profile, key);
        }
        self.save_index(&index)?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": scope.project,
                    "profile": scope.profile,
                    "purged": keys,
                }))?
            );
        } else {
            println!("purged {}/{}", scope.project, scope.profile);
        }
        Ok(ExitCode::SUCCESS)
    }

    fn doctor(&self, project: Option<String>, profile: Option<String>, json: bool) -> Result<ExitCode> {
        let cwd = env::current_dir().context("failed to determine current working directory")?;
        let local = find_local_config(&cwd)?;
        let resolved = self.resolve_scope(project, profile).ok();
        let index = self.load_index().unwrap_or_default();
        let scoped_count = resolved
            .as_ref()
            .map(|scope| index.entries_for_scope(&scope.project, &scope.profile).len())
            .unwrap_or(0);

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "cwd": cwd,
                    "local_config": local.as_ref().map(|hit| &hit.path),
                    "resolved_scope": resolved,
                    "state_dir": self.state_dir,
                    "index_path": self.index_path,
                    "total_index_entries": index.entries.len(),
                    "scoped_entries": scoped_count,
                }))?
            );
        } else {
            println!("cwd: {}", cwd.display());
            match local {
                Some(hit) => println!("local config: {}", hit.path.display()),
                None => println!("local config: none"),
            }
            if let Some(scope) = resolved {
                println!("project: {}", scope.project);
                println!("profile: {}", scope.profile);
                println!("scope entries: {}", scoped_count);
            } else {
                println!("project/profile: unresolved");
            }
            println!("state dir: {}", self.state_dir.display());
            println!("index path: {}", self.index_path.display());
            println!("total indexed secrets: {}", index.entries.len());
        }

        Ok(ExitCode::SUCCESS)
    }

    fn selected_env(
        &self,
        scope: &ResolvedScope,
        only: &[String],
        prefixes: &[String],
    ) -> Result<BTreeMap<String, String>> {
        let index = self.load_index()?;
        let entries = select_entries(index.entries_for_scope(&scope.project, &scope.profile), only, prefixes)?;
        let mut env_map = BTreeMap::new();
        for entry in entries {
            let value = read_secret(&scope.project, &scope.profile, &entry.key)?;
            env_map.insert(entry.key.clone(), value);
        }
        Ok(env_map)
    }

    fn resolve_scope(&self, project: Option<String>, profile: Option<String>) -> Result<ResolvedScope> {
        let cwd = env::current_dir().context("failed to determine current working directory")?;
        let local = find_local_config(&cwd)?;

        let resolved_project = match project {
            Some(project) => project,
            None => local.as_ref().map(|hit| hit.config.project.clone()).ok_or_else(|| {
                anyhow!("no project resolved; run `macrun init --project NAME` or pass --project")
            })?,
        };

        let resolved_profile = profile
            .or_else(|| local.as_ref().map(|hit| hit.config.default_profile.clone()))
            .unwrap_or_else(|| "dev".to_owned());

        Ok(ResolvedScope {
            project: resolved_project,
            profile: resolved_profile,
            config_path: local.map(|hit| hit.path),
        })
    }

    fn load_index(&self) -> Result<IndexFile> {
        if !self.index_path.exists() {
            return Ok(IndexFile::default());
        }
        let contents = fs::read_to_string(&self.index_path)
            .with_context(|| format!("failed to read {}", self.index_path.display()))?;
        let index = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", self.index_path.display()))?;
        Ok(index)
    }

    fn save_index(&self, index: &IndexFile) -> Result<()> {
        let temp_path = self.index_path.with_extension("json.tmp");
        let contents = serde_json::to_string_pretty(index).context("failed to encode index")?;
        fs::write(&temp_path, contents)
            .with_context(|| format!("failed to write {}", temp_path.display()))?;
        fs::rename(&temp_path, &self.index_path)
            .with_context(|| format!("failed to move {} into place", self.index_path.display()))?;
        Ok(())
    }
}