// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{anyhow, bail, Context, Result};
use directories::ProjectDirs;
use rpassword::prompt_password;

use crate::cli::{
    ArchiveCommands, ArchiveExportMode, Cli, Commands, EnvFormat, KvVersionArg, MasterCommands,
    VaultCommands,
};
use crate::config::{find_local_config, LocalConfig, ResolvedScope, CONFIG_FILE_NAME};
use crate::index::{IndexFile, StoredSecretMeta};
use crate::keychain::{
    clear_master_secret, delete_legacy_secret, delete_secret, has_master_secret,
    read_legacy_secret, read_master_secret, read_project_bundle, read_scope_secrets, read_secret,
    store_secret, write_master_secret, write_project_bundle, write_scope_secrets,
};
use crate::sealed::{open_scope, seal_scope, SealedScopeFile, SealedScopePayload};
use crate::util::{
    parse_env_file, parse_env_mapping, parse_pair, shell_quote, validate_env_name, EnvMapping,
};
use crate::vault::{parse_key_version, KvVersion, VaultClient};

const DEFAULT_PROJECT_KEY: &str = "__default_project__";
const DEFAULT_PROJECT_LABEL: &str = "(default)";
const DEFAULT_ENV: &str = "dev";

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
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("failed to create state directory {}", state_dir.display()))?;
        Ok(Self {
            state_dir,
            index_path,
        })
    }

    pub fn execute(&self, cli: Cli) -> Result<ExitCode> {
        match cli.command {
            Some(Commands::Init {
                project,
                env,
                force,
            }) => self.init(project.or(cli.project), env.or(cli.env), force, cli.json),
            Some(Commands::Set {
                parts,
                stdin,
                from_env,
                source,
                note,
            }) => {
                if parts.iter().all(|part| part.contains('=')) {
                    if stdin || from_env.is_some() {
                        bail!("NAME=value cannot be combined with --stdin or --from-env");
                    }
                    let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                    self.set_pairs(&scope, parts, &source, note, cli.json)
                } else {
                    let (scope_parts, name) = parts.split_at(parts.len() - 1);
                    let scope = self.resolve_public_scope(scope_parts, cli.project, cli.env)?;
                    let value = self.read_secret_input(&name[0], stdin, from_env.as_deref())?;
                    self.set_one(&scope, &name[0], value)
                }
            }
            Some(Commands::Get { name }) => {
                let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                self.get_secret(&scope, &name, cli.json)
            }
            Some(Commands::Import {
                file,
                replace,
                source,
            }) => {
                let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                self.import_file(&scope, &file, replace, &source, cli.json)
            }
            Some(Commands::List {
                scope,
                show_metadata,
            }) => {
                if show_metadata || cli.project.is_some() || cli.env.is_some() || cli.json {
                    let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                    self.list_entries(&scope, show_metadata, cli.json)
                } else {
                    let scope = self.resolve_simple_scope(&scope)?;
                    self.list_simple(&scope)
                }
            }
            Some(Commands::Run { scope, command }) => {
                let scope = self.resolve_public_scope(&scope, cli.project, cli.env)?;
                self.run_command(&scope, &command)
            }
            Some(Commands::Exec {
                vault_encrypt,
                vault_addr,
                transit_path,
                vault_key,
                command,
            }) => {
                let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                self.exec_command(
                    &scope,
                    &command,
                    &vault_encrypt,
                    vault_addr.as_deref(),
                    &transit_path,
                    vault_key.as_deref(),
                )
            }
            Some(Commands::Env { format }) => {
                let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                self.print_env(&scope, &format)
            }
            Some(Commands::Remove { parts }) => {
                let (scope_parts, name) = parts.split_at(parts.len() - 1);
                let scope = self.resolve_public_scope(scope_parts, cli.project, cli.env)?;
                self.remove_simple(&scope, &name[0])
            }
            Some(Commands::Unset { parts }) => {
                let (scope_parts, name) = parts.split_at(parts.len() - 1);
                let scope = self.resolve_public_scope(scope_parts, cli.project, cli.env)?;
                self.remove_simple(&scope, &name[0])
            }
            Some(Commands::Purge { yes }) => {
                let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                self.purge_scope(&scope, yes, cli.json)
            }
            Some(Commands::Vault { command }) => {
                let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                match command {
                    VaultCommands::Encrypt {
                        env_key,
                        vault_addr,
                        transit_path,
                        vault_key,
                        verify_decrypt,
                    } => self.vault_encrypt(
                        &scope,
                        &env_key,
                        &vault_addr,
                        &transit_path,
                        &vault_key,
                        verify_decrypt,
                        cli.json,
                    ),
                    VaultCommands::Push {
                        env_keys,
                        vault_addr,
                        mount,
                        path,
                        kv_version,
                    } => self.vault_push(
                        &scope,
                        &env_keys,
                        &vault_addr,
                        &mount,
                        &path,
                        kv_version,
                        cli.json,
                    ),
                }
            }
            Some(Commands::Master { command }) => match command {
                MasterCommands::Set { stdin } => self.master_set(stdin, cli.json),
                MasterCommands::Clear => self.master_clear(cli.json),
                MasterCommands::Status => self.master_status(cli.json),
            },
            Some(Commands::Archive { command }) => match command {
                ArchiveCommands::Export { file, mode } => {
                    let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                    self.archive_export(&scope, mode, &file, cli.json)
                }
                ArchiveCommands::Import { file, replace } => {
                    self.archive_import(cli.project, cli.env, &file, replace, cli.json)
                }
            },
            Some(Commands::Doctor) => self.doctor(cli.project, cli.env, cli.json),
            None => bail!("no command provided"),
        }
    }

    fn master_set(&self, stdin: bool, json: bool) -> Result<ExitCode> {
        let secret = if stdin {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("failed to read master secret from stdin")?;
            buffer.trim_end_matches(['\n', '\r']).to_owned()
        } else {
            let first =
                prompt_password("master secret: ").context("failed to read master secret")?;
            let second = prompt_password("confirm master secret: ")
                .context("failed to read master secret confirmation")?;
            if first != second {
                bail!("master secret confirmation did not match");
            }
            first
        };

        if secret.is_empty() {
            bail!("master secret cannot be empty");
        }

        write_master_secret(&secret)?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "configured": true }))?
            );
        } else {
            println!("master secret stored");
        }
        Ok(ExitCode::SUCCESS)
    }

    fn master_clear(&self, json: bool) -> Result<ExitCode> {
        clear_master_secret()?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "configured": false }))?
            );
        } else {
            println!("master secret cleared");
        }
        Ok(ExitCode::SUCCESS)
    }

    fn master_status(&self, json: bool) -> Result<ExitCode> {
        let configured = has_master_secret()?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "configured": configured }))?
            );
        } else {
            println!(
                "master secret: {}",
                if configured { "configured" } else { "missing" }
            );
        }
        Ok(ExitCode::SUCCESS)
    }

    fn archive_export(
        &self,
        scope: &ResolvedScope,
        mode: ArchiveExportMode,
        file: &Path,
        json: bool,
    ) -> Result<ExitCode> {
        let master_secret = read_master_secret()
            .context("master secret is not configured; run `macrun master set`")?;
        let payload = match mode {
            ArchiveExportMode::Scope => {
                let secrets = self.selected_env(scope)?;
                if secrets.is_empty() {
                    bail!("no secrets stored for the current project/env scope");
                }
                SealedScopePayload::Scope {
                    project: self.export_project_name(scope).to_owned(),
                    env: scope.env.clone(),
                    secrets,
                }
            }
            ArchiveExportMode::Project => {
                let bundle = read_project_bundle(&scope.project)?;
                if bundle.envs.is_empty() {
                    bail!("no secrets stored for the current project");
                }
                SealedScopePayload::Project {
                    project: self.export_project_name(scope).to_owned(),
                    envs: bundle.envs,
                }
            }
        };
        let sealed = seal_scope(&master_secret, &payload)?;
        self.write_json_file(file, &sealed)?;

        if json {
            let metadata = match &payload {
                SealedScopePayload::Scope {
                    project,
                    env,
                    secrets,
                } => serde_json::json!({
                    "file": file,
                    "mode": "scope",
                    "target": "resolved_scope",
                    "project": project,
                    "env": env,
                    "secrets": secrets.len(),
                }),
                SealedScopePayload::Project { project, envs } => {
                    let secret_count: usize = envs.values().map(|secrets| secrets.len()).sum();
                    serde_json::json!({
                        "file": file,
                        "mode": "project",
                        "target": "resolved_project_all_envs",
                        "project": project,
                        "envs": envs.len(),
                        "secrets": secret_count,
                    })
                }
            };
            println!("{}", serde_json::to_string_pretty(&metadata)?);
        } else {
            match &payload {
                SealedScopePayload::Scope { project, env, .. } => {
                    println!(
                        "exported encrypted resolved scope {}/{} to {}",
                        project,
                        env,
                        file.display()
                    );
                }
                SealedScopePayload::Project { project, envs } => {
                    println!(
                        "exported encrypted resolved project {} (all {} envs) to {}",
                        project,
                        envs.len(),
                        file.display()
                    );
                }
            }
        }

        Ok(ExitCode::SUCCESS)
    }

    fn archive_import(
        &self,
        project_override: Option<String>,
        env_override: Option<String>,
        file: &Path,
        replace: bool,
        json: bool,
    ) -> Result<ExitCode> {
        let master_secret = read_master_secret()
            .context("master secret is not configured; run `macrun master set`")?;
        let sealed: SealedScopeFile = self.read_json_file(file)?;
        let payload = open_scope(&master_secret, &sealed)?;
        match payload {
            SealedScopePayload::Scope {
                project,
                env,
                secrets,
            } => {
                let target_scope = ResolvedScope {
                    project: self.import_project_name(project_override.unwrap_or(project)),
                    env: env_override.unwrap_or(env),
                    config_path: None,
                };

                let mut index = self.load_index()?;
                let mut scope_secrets =
                    read_scope_secrets(&target_scope.project, &target_scope.env)?;
                let mut imported = Vec::new();
                let mut skipped = Vec::new();

                for (name, value) in secrets {
                    if !replace && index.contains(&target_scope.project, &target_scope.env, &name) {
                        skipped.push(name);
                        continue;
                    }
                    scope_secrets.insert(name.clone(), value);
                    index.upsert(StoredSecretMeta::new(
                        target_scope.project.clone(),
                        target_scope.env.clone(),
                        name.clone(),
                        "archive".to_owned(),
                        Some(format!("imported from {}", file.display())),
                    ));
                    imported.push(name);
                }

                write_scope_secrets(&target_scope.project, &target_scope.env, &scope_secrets)?;
                self.save_index(&index)?;

                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "file": file,
                            "mode": "scope",
                            "project": self.display_project(&target_scope),
                            "env": target_scope.env,
                            "imported": imported,
                            "skipped": skipped,
                        }))?
                    );
                } else {
                    println!(
                        "imported {} secret(s) from {} into {}/{}",
                        imported.len(),
                        file.display(),
                        self.display_project(&target_scope),
                        target_scope.env
                    );
                    if !skipped.is_empty() {
                        println!("skipped {} key(s)", skipped.len());
                    }
                }
            }
            SealedScopePayload::Project { project, envs } => {
                if env_override.is_some() {
                    bail!("--env cannot be used when importing a whole-project archive");
                }

                let target_project = self.import_project_name(project_override.unwrap_or(project));
                let mut bundle = read_project_bundle(&target_project)?;
                let mut index = self.load_index()?;
                let mut imported = Vec::new();
                let mut skipped = Vec::new();

                for (env_name, secrets) in envs {
                    let target_env = bundle.envs.entry(env_name.clone()).or_default();
                    for (name, value) in secrets {
                        if !replace && index.contains(&target_project, &env_name, &name) {
                            skipped.push(format!("{env_name}/{name}"));
                            continue;
                        }
                        target_env.insert(name.clone(), value);
                        index.upsert(StoredSecretMeta::new(
                            target_project.clone(),
                            env_name.clone(),
                            name.clone(),
                            "archive".to_owned(),
                            Some(format!("imported from {}", file.display())),
                        ));
                        imported.push(format!("{env_name}/{name}"));
                    }
                }

                write_project_bundle(&target_project, &bundle)?;
                self.save_index(&index)?;

                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "file": file,
                            "mode": "project",
                            "project": target_project,
                            "imported": imported,
                            "skipped": skipped,
                        }))?
                    );
                } else {
                    println!(
                        "imported {} secret(s) from {} into project {}",
                        imported.len(),
                        file.display(),
                        target_project
                    );
                    if !skipped.is_empty() {
                        println!("skipped {} key(s)", skipped.len());
                    }
                }
            }
        }

        Ok(ExitCode::SUCCESS)
    }

    fn vault_encrypt(
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
        let plaintext = read_secret(&scope.project, &scope.env, env_key)?;
        let vault = VaultClient::from_env(vault_addr)?;
        let encrypted = vault.encrypt(transit_path, vault_key, plaintext.as_bytes())?;
        let key_version = parse_key_version(&encrypted.ciphertext);
        let decrypt_verified = if verify_decrypt {
            let round_trip = vault.decrypt(transit_path, vault_key, &encrypted.ciphertext)?;
            round_trip == plaintext
        } else {
            false
        };

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": self.display_project(scope),
                    "env": scope.env,
                    "env_key": env_key,
                    "vault_addr": vault_addr,
                    "transit_path": transit_path,
                    "vault_key": vault_key,
                    "ciphertext": encrypted.ciphertext,
                    "ciphertext_length": encrypted.ciphertext.len(),
                    "key_version": key_version,
                    "verified_decrypt": decrypt_verified,
                    "mode": "transit-encrypt",
                }))?
            );
        } else {
            println!("{}", encrypted.ciphertext);
            if verify_decrypt {
                eprintln!(
                    "macrun: verified Vault transit decrypt for {}/{} {}",
                    self.display_project(scope),
                    scope.env,
                    env_key
                );
            } else if let Some(version) = key_version {
                eprintln!("macrun: Vault transit key version {version}");
            }
        }

        Ok(ExitCode::SUCCESS)
    }

    fn vault_push(
        &self,
        scope: &ResolvedScope,
        env_keys: &[String],
        vault_addr: &str,
        mount: &str,
        path: &str,
        kv_version: KvVersionArg,
        json: bool,
    ) -> Result<ExitCode> {
        let vault = VaultClient::from_env(vault_addr)?;
        let mut data = BTreeMap::new();

        for env_key in env_keys {
            validate_env_name(env_key)?;
            let plaintext = read_secret(&scope.project, &scope.env, env_key)?;
            data.insert(env_key.clone(), plaintext);
        }

        let kv_version = match kv_version {
            KvVersionArg::V1 => KvVersion::V1,
            KvVersionArg::V2 => KvVersion::V2,
        };
        vault.kv_put(mount, path, kv_version, data.clone())?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": self.display_project(scope),
                    "env": scope.env,
                    "vault_addr": vault_addr,
                    "mount": mount,
                    "path": path,
                    "kv_version": match kv_version {
                        KvVersion::V1 => "v1",
                        KvVersion::V2 => "v2",
                    },
                    "written": env_keys,
                    "mode": "kv-push",
                }))?
            );
        } else {
            println!(
                "wrote {} secret(s) to Vault {}/{}",
                env_keys.len(),
                mount,
                path.trim_matches('/')
            );
            for env_key in env_keys {
                println!("- {env_key}");
            }
        }

        Ok(ExitCode::SUCCESS)
    }

    fn init(
        &self,
        project: Option<String>,
        env: Option<String>,
        force: bool,
        json: bool,
    ) -> Result<ExitCode> {
        let cwd = env::current_dir().context("failed to determine current working directory")?;
        let project = project.ok_or_else(|| anyhow!("`macrun init` requires --project NAME"))?;
        if project == DEFAULT_PROJECT_KEY {
            bail!("`{DEFAULT_PROJECT_KEY}` is reserved for macrun internal use");
        }
        let env = env.unwrap_or_else(|| DEFAULT_ENV.to_owned());
        let config_path = cwd.join(CONFIG_FILE_NAME);

        if config_path.exists() && !force {
            bail!(
                "{} already exists; pass --force to overwrite",
                config_path.display()
            );
        }

        let config = LocalConfig {
            project: project.clone(),
            default_env: env.clone(),
        };
        let toml = toml::to_string_pretty(&config).context("failed to serialize local config")?;
        fs::write(&config_path, toml)
            .with_context(|| format!("failed to write local config {}", config_path.display()))?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": project,
                    "env": env,
                    "config_path": config_path,
                }))?
            );
        } else {
            println!("initialized {}", config_path.display());
            println!("project: {project}");
            println!("default env: {env}");
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
        let mut scope_secrets = read_scope_secrets(&scope.project, &scope.env)?;
        let mut written = Vec::new();

        for pair in pairs {
            let (name, value) = parse_pair(&pair)?;
            scope_secrets.insert(name.clone(), value);
            index.upsert(StoredSecretMeta::new(
                scope.project.clone(),
                scope.env.clone(),
                name.clone(),
                source.to_owned(),
                note.clone(),
            ));
            written.push(name);
        }

        write_scope_secrets(&scope.project, &scope.env, &scope_secrets)?;
        self.save_index(&index)?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": self.display_project(scope),
                    "env": scope.env,
                    "written": written,
                }))?
            );
        } else {
            println!(
                "stored {} secret(s) for {}/{}",
                written.len(),
                self.display_project(scope),
                scope.env
            );
            for name in written {
                println!("- {name}");
            }
        }

        Ok(ExitCode::SUCCESS)
    }

    fn read_secret_input(&self, name: &str, stdin: bool, from_env: Option<&str>) -> Result<String> {
        validate_env_name(name)?;

        let value = if stdin {
            let mut value = String::new();
            io::stdin()
                .read_to_string(&mut value)
                .context("failed to read the secret from standard input")?;
            value.trim_end_matches(['\n', '\r']).to_owned()
        } else if let Some(variable) = from_env {
            env::var(variable)
                .with_context(|| format!("environment variable {variable} is not set"))?
        } else {
            prompt_password(format!("{name}: ")).context("failed to read the secret")?
        };

        if value.is_empty() {
            bail!("secret value cannot be empty");
        }
        Ok(value)
    }

    fn set_one(&self, scope: &ResolvedScope, name: &str, value: String) -> Result<ExitCode> {
        validate_env_name(name)?;
        let mut secrets = read_scope_secrets(&scope.project, &scope.env)?;
        secrets.insert(name.to_owned(), value);
        write_scope_secrets(&scope.project, &scope.env, &secrets)?;

        let mut index = self.load_index()?;
        index.upsert(StoredSecretMeta::new(
            scope.project.clone(),
            scope.env.clone(),
            name.to_owned(),
            "manual".to_owned(),
            None,
        ));
        self.save_index(&index)?;
        Ok(ExitCode::SUCCESS)
    }

    fn get_secret(&self, scope: &ResolvedScope, name: &str, json: bool) -> Result<ExitCode> {
        let value = read_secret(&scope.project, &scope.env, name)?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": self.display_project(scope),
                    "env": scope.env,
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
        source: &str,
        json: bool,
    ) -> Result<ExitCode> {
        let contents = fs::read_to_string(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let parsed = parse_env_file(&contents)?;
        let mut index = self.load_index()?;
        let mut scope_secrets = read_scope_secrets(&scope.project, &scope.env)?;
        let mut imported = Vec::new();
        let mut skipped = Vec::new();

        for (name, value) in parsed {
            if !replace && index.contains(&scope.project, &scope.env, &name) {
                skipped.push(name);
                continue;
            }

            scope_secrets.insert(name.clone(), value);
            index.upsert(StoredSecretMeta::new(
                scope.project.clone(),
                scope.env.clone(),
                name.clone(),
                source.to_owned(),
                Some(format!("imported from {}", file.display())),
            ));
            imported.push(name);
        }

        write_scope_secrets(&scope.project, &scope.env, &scope_secrets)?;
        self.save_index(&index)?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": self.display_project(scope),
                    "env": scope.env,
                    "file": file,
                    "imported": imported,
                    "skipped": skipped,
                }))?
            );
        } else {
            println!(
                "imported {} secret(s) into {}/{}",
                imported.len(),
                self.display_project(scope),
                scope.env
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
        json: bool,
    ) -> Result<ExitCode> {
        let index = self.load_index()?;
        let entries = index.entries_owned_for_scope(&scope.project, &scope.env);
        if json {
            println!("{}", serde_json::to_string_pretty(&entries)?);
            return Ok(ExitCode::SUCCESS);
        }

        if entries.is_empty() {
            println!(
                "no secrets stored for {}/{}",
                self.display_project(scope),
                scope.env
            );
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

    fn list_simple(&self, scope: &ResolvedScope) -> Result<ExitCode> {
        for name in read_scope_secrets(&scope.project, &scope.env)?.keys() {
            println!("{name}");
        }
        Ok(ExitCode::SUCCESS)
    }

    fn exec_command(
        &self,
        scope: &ResolvedScope,
        command: &[String],
        vault_encrypt: &[String],
        vault_addr: Option<&str>,
        transit_path: &str,
        vault_key: Option<&str>,
    ) -> Result<ExitCode> {
        let mut env_map = self.selected_env(scope)?;
        let encrypted_count = self.inject_vault_ciphertexts(
            scope,
            &mut env_map,
            vault_encrypt,
            vault_addr,
            transit_path,
            vault_key,
        )?;

        eprintln!(
            "macrun: exec project={} env={} keys={} encrypted={}",
            self.display_project(scope),
            scope.env,
            env_map.len(),
            encrypted_count
        );

        self.spawn_command(command, &env_map)
    }

    fn run_command(&self, scope: &ResolvedScope, command: &[String]) -> Result<ExitCode> {
        let env_map = self.selected_env(scope)?;
        self.spawn_command(command, &env_map)
    }

    fn spawn_command(
        &self,
        command: &[String],
        env_map: &BTreeMap<String, String>,
    ) -> Result<ExitCode> {
        if env_map.is_empty() {
            bail!("no secrets found for that scope");
        }

        let program = command
            .first()
            .ok_or_else(|| anyhow!("a command is required after `--`"))?;
        let args = &command[1..];

        let status = Command::new(program)
            .args(args)
            .envs(env_map)
            .status()
            .with_context(|| format!("failed to execute `{program}`"))?;

        if let Some(code) = status.code() {
            Ok(ExitCode::from(code as u8))
        } else {
            Ok(ExitCode::from(1))
        }
    }

    fn print_env(&self, scope: &ResolvedScope, format: &EnvFormat) -> Result<ExitCode> {
        let env_map = self.selected_env(scope)?;
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

    fn remove_simple(&self, scope: &ResolvedScope, name: &str) -> Result<ExitCode> {
        validate_env_name(name)?;
        let mut secrets = read_scope_secrets(&scope.project, &scope.env)?;
        secrets.remove(name);
        write_scope_secrets(&scope.project, &scope.env, &secrets)?;
        delete_legacy_secret(&scope.project, &scope.env, name)?;

        let mut index = self.load_index()?;
        index.remove(&scope.project, &scope.env, name);
        self.save_index(&index)?;
        Ok(ExitCode::SUCCESS)
    }

    fn purge_scope(&self, scope: &ResolvedScope, yes: bool, json: bool) -> Result<ExitCode> {
        if !yes {
            bail!("purge is destructive; re-run with --yes");
        }

        let mut index = self.load_index()?;
        let keys: Vec<String> = index
            .entries_for_scope(&scope.project, &scope.env)
            .into_iter()
            .map(|entry| entry.key.clone())
            .collect();

        for key in &keys {
            delete_legacy_secret(&scope.project, &scope.env, key)?;
            index.remove(&scope.project, &scope.env, key);
        }
        write_scope_secrets(&scope.project, &scope.env, &BTreeMap::new())?;
        self.save_index(&index)?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": self.display_project(scope),
                    "env": scope.env,
                    "purged": keys,
                }))?
            );
        } else {
            println!("purged {}/{}", self.display_project(scope), scope.env);
        }
        Ok(ExitCode::SUCCESS)
    }

    fn doctor(&self, project: Option<String>, env: Option<String>, json: bool) -> Result<ExitCode> {
        let cwd = env::current_dir().context("failed to determine current working directory")?;
        let local = find_local_config(&cwd)?;
        let resolved = self.resolve_runtime_scope(project, env).ok();
        let index = self.load_index().unwrap_or_default();
        let scoped_count = resolved
            .as_ref()
            .map(|scope| index.entries_for_scope(&scope.project, &scope.env).len())
            .unwrap_or(0);

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "cwd": cwd,
                    "local_config": local.as_ref().map(|hit| &hit.path),
                    "resolved_scope": resolved.as_ref().map(|scope| serde_json::json!({
                        "project": self.display_project(scope),
                        "env": scope.env,
                        "config_path": scope.config_path,
                    })),
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
                println!("project: {}", self.display_project(&scope));
                println!("env: {}", scope.env);
                println!("scope entries: {}", scoped_count);
            } else {
                println!("project/env: unresolved");
            }
            println!("state dir: {}", self.state_dir.display());
            println!("index path: {}", self.index_path.display());
            println!("total indexed secrets: {}", index.entries.len());
        }

        Ok(ExitCode::SUCCESS)
    }

    fn selected_env(&self, scope: &ResolvedScope) -> Result<BTreeMap<String, String>> {
        read_scope_secrets(&scope.project, &scope.env)
    }

    fn inject_vault_ciphertexts(
        &self,
        scope: &ResolvedScope,
        env_map: &mut BTreeMap<String, String>,
        vault_encrypt: &[String],
        vault_addr: Option<&str>,
        transit_path: &str,
        vault_key: Option<&str>,
    ) -> Result<usize> {
        if vault_encrypt.is_empty() {
            return Ok(0);
        }

        let vault_addr = vault_addr
            .ok_or_else(|| anyhow!("--vault-addr is required when using --vault-encrypt"))?;
        let vault_key = vault_key
            .ok_or_else(|| anyhow!("--vault-key is required when using --vault-encrypt"))?;
        let vault = VaultClient::from_env(vault_addr)?;
        let mappings = vault_encrypt
            .iter()
            .map(|item| parse_env_mapping(item))
            .collect::<Result<Vec<EnvMapping>>>()?;

        for mapping in &mappings {
            let plaintext = read_secret(&scope.project, &scope.env, &mapping.source)?;
            let encrypted = vault.encrypt(transit_path, vault_key, plaintext.as_bytes())?;
            env_map.remove(&mapping.source);
            env_map.insert(mapping.target.clone(), encrypted.ciphertext);
        }

        Ok(mappings.len())
    }

    fn resolve_simple_scope(&self, parts: &[String]) -> Result<ResolvedScope> {
        let scope = simple_scope(parts)?;
        self.migrate_legacy_default_scope(&scope)?;
        self.migrate_project_bundle(&scope.project)?;
        Ok(scope)
    }

    fn resolve_public_scope(
        &self,
        parts: &[String],
        legacy_project: Option<String>,
        legacy_env: Option<String>,
    ) -> Result<ResolvedScope> {
        if legacy_project.is_some() || legacy_env.is_some() {
            if !parts.is_empty() {
                bail!("project and environment cannot be given both as words and as options");
            }
            self.resolve_runtime_scope(legacy_project, legacy_env)
        } else {
            self.resolve_simple_scope(parts)
        }
    }

    fn resolve_scope(&self, project: Option<String>, env: Option<String>) -> Result<ResolvedScope> {
        let cwd = env::current_dir().context("failed to determine current working directory")?;
        let local = find_local_config(&cwd)?;

        let resolved_project = project
            .or_else(|| local.as_ref().map(|hit| hit.config.project.clone()))
            .unwrap_or_else(|| DEFAULT_PROJECT_KEY.to_owned());

        let resolved_env = env
            .or_else(|| local.as_ref().map(|hit| hit.config.default_env.clone()))
            .unwrap_or_else(|| DEFAULT_ENV.to_owned());

        Ok(ResolvedScope {
            project: resolved_project,
            env: resolved_env,
            config_path: local.map(|hit| hit.path),
        })
    }

    fn resolve_runtime_scope(
        &self,
        project: Option<String>,
        env: Option<String>,
    ) -> Result<ResolvedScope> {
        let scope = self.resolve_scope(project, env)?;
        self.migrate_legacy_default_scope(&scope)?;
        self.migrate_project_bundle(&scope.project)?;
        Ok(scope)
    }

    fn migrate_legacy_default_scope(&self, scope: &ResolvedScope) -> Result<()> {
        if scope.project != DEFAULT_PROJECT_KEY {
            return Ok(());
        }

        let mut index = self.load_index()?;
        let legacy_entries = index.entries_owned_for_scope("default", &scope.env);
        if legacy_entries.is_empty() {
            return Ok(());
        }

        for entry in legacy_entries {
            let value = read_secret("default", &scope.env, &entry.key)?;
            if !index.contains(DEFAULT_PROJECT_KEY, &scope.env, &entry.key) {
                store_secret(DEFAULT_PROJECT_KEY, &scope.env, &entry.key, &value)?;
                index.upsert(StoredSecretMeta::new(
                    DEFAULT_PROJECT_KEY.to_owned(),
                    scope.env.clone(),
                    entry.key.clone(),
                    entry.source.clone(),
                    entry.note.clone(),
                ));
            }
            delete_secret("default", &scope.env, &entry.key)?;
            index.remove("default", &scope.env, &entry.key);
        }

        self.save_index(&index)
    }

    fn migrate_project_bundle(&self, project: &str) -> Result<()> {
        let index = self.load_index().unwrap_or_default();
        let project_entries = index.entries_owned_for_project(project);
        if project_entries.is_empty() {
            return Ok(());
        }

        let mut bundle = read_project_bundle(project)?;
        let mut changed = false;

        for entry in project_entries {
            if bundle
                .envs
                .get(&entry.env)
                .and_then(|scope| scope.get(&entry.key))
                .is_some()
            {
                continue;
            }

            match read_legacy_secret(project, &entry.env, &entry.key) {
                Ok(value) => {
                    bundle
                        .envs
                        .entry(entry.env.clone())
                        .or_default()
                        .insert(entry.key.clone(), value);
                    delete_legacy_secret(project, &entry.env, &entry.key)?;
                    changed = true;
                }
                Err(_) => continue,
            }
        }

        if changed {
            write_project_bundle(project, &bundle)?;
        }

        Ok(())
    }

    fn display_project<'a>(&self, scope: &'a ResolvedScope) -> &'a str {
        if scope.project == DEFAULT_PROJECT_KEY {
            DEFAULT_PROJECT_LABEL
        } else {
            &scope.project
        }
    }

    fn export_project_name<'a>(&self, scope: &'a ResolvedScope) -> &'a str {
        self.display_project(scope)
    }

    fn import_project_name(&self, project: String) -> String {
        if project == DEFAULT_PROJECT_LABEL {
            DEFAULT_PROJECT_KEY.to_owned()
        } else {
            project
        }
    }

    fn write_json_file<T: serde::Serialize>(&self, file: &Path, value: &T) -> Result<()> {
        let temp_path = file.with_extension("tmp");
        let contents = serde_json::to_string_pretty(value).context("failed to encode JSON file")?;
        fs::write(&temp_path, contents)
            .with_context(|| format!("failed to write {}", temp_path.display()))?;
        fs::rename(&temp_path, file)
            .with_context(|| format!("failed to move {} into place", file.display()))?;
        Ok(())
    }

    fn read_json_file<T: serde::de::DeserializeOwned>(&self, file: &Path) -> Result<T> {
        let contents = fs::read_to_string(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", file.display()))
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

fn simple_scope(parts: &[String]) -> Result<ResolvedScope> {
    let (project, env) = match parts {
        [] => (DEFAULT_PROJECT_KEY.to_owned(), DEFAULT_ENV.to_owned()),
        [project] => (project.clone(), DEFAULT_ENV.to_owned()),
        [project, env] => (project.clone(), env.clone()),
        _ => bail!("scope must be empty, PROJECT, or PROJECT ENVIRONMENT"),
    };

    if project.is_empty() {
        bail!("project cannot be empty");
    }
    if project == DEFAULT_PROJECT_KEY && !parts.is_empty() {
        bail!("that project name is reserved");
    }
    if env.is_empty() {
        bail!("environment cannot be empty");
    }

    Ok(ResolvedScope {
        project,
        env,
        config_path: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{simple_scope, DEFAULT_ENV, DEFAULT_PROJECT_KEY};

    fn parts(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn simple_scope_defaults_to_the_machine() {
        let scope = simple_scope(&[]).unwrap();
        assert_eq!(scope.project, DEFAULT_PROJECT_KEY);
        assert_eq!(scope.env, DEFAULT_ENV);
    }

    #[test]
    fn simple_scope_accepts_a_project_without_an_environment() {
        let scope = simple_scope(&parts(&["shop"])).unwrap();
        assert_eq!(scope.project, "shop");
        assert_eq!(scope.env, DEFAULT_ENV);
    }

    #[test]
    fn simple_scope_accepts_a_project_and_environment() {
        let scope = simple_scope(&parts(&["shop", "staging"])).unwrap();
        assert_eq!(scope.project, "shop");
        assert_eq!(scope.env, "staging");
    }
}
