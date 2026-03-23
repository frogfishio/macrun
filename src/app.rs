// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{anyhow, bail, Context, Result};
use directories::ProjectDirs;

use crate::cli::{Cli, Commands, EnvFormat, KvVersionArg, VaultCommands};
use crate::config::{find_local_config, LocalConfig, ResolvedScope, CONFIG_FILE_NAME};
use crate::index::{IndexFile, StoredSecretMeta};
use crate::keychain::{
    delete_legacy_secret, delete_secret, read_legacy_secret, read_project_bundle, read_scope_secrets,
    read_secret, store_secret, write_project_bundle, write_scope_secrets,
};
use crate::util::{parse_env_file, parse_env_mapping, parse_pair, shell_quote, validate_env_name, EnvMapping};
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
                env,
                force,
            }) => self.init(project.or(cli.project), env.or(cli.env), force, cli.json),
            Some(Commands::Set { pairs, source, note }) => {
                let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                self.set_pairs(&scope, pairs, &source, note, cli.json)
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
            Some(Commands::List { show_metadata }) => {
                let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                self.list_entries(&scope, show_metadata, cli.json)
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
            Some(Commands::Unset { names }) => {
                let scope = self.resolve_runtime_scope(cli.project, cli.env)?;
                self.unset_names(&scope, &names, cli.json)
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
            Some(Commands::Doctor) => self.doctor(cli.project, cli.env, cli.json),
            None => bail!("no command provided"),
        }
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
        fs::write(&config_path, toml).with_context(|| {
            format!("failed to write local config {}", config_path.display())
        })?;

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

        if env_map.is_empty() {
            bail!("no secrets stored for the current project/env scope");
        }

        let program = command
            .first()
            .ok_or_else(|| anyhow!("exec requires a command after `--`"))?;
        let args = &command[1..];

        eprintln!(
            "macrun: exec project={} env={} keys={} encrypted={}",
            self.display_project(scope),
            scope.env,
            env_map.len(),
            encrypted_count
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
    ) -> Result<ExitCode> {
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

    fn unset_names(
        &self,
        scope: &ResolvedScope,
        names: &[String],
        json: bool,
    ) -> Result<ExitCode> {
        let mut index = self.load_index()?;
        let mut scope_secrets = read_scope_secrets(&scope.project, &scope.env)?;
        let mut removed = Vec::new();
        for name in names {
            scope_secrets.remove(name);
            delete_legacy_secret(&scope.project, &scope.env, name)?;
            index.remove(&scope.project, &scope.env, name);
            removed.push(name.clone());
        }
        write_scope_secrets(&scope.project, &scope.env, &scope_secrets)?;
        self.save_index(&index)?;

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "project": self.display_project(scope),
                    "env": scope.env,
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

    fn selected_env(
        &self,
        scope: &ResolvedScope,
    ) -> Result<BTreeMap<String, String>> {
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

        let vault_addr = vault_addr.ok_or_else(|| {
            anyhow!("--vault-addr is required when using --vault-encrypt")
        })?;
        let vault_key = vault_key.ok_or_else(|| {
            anyhow!("--vault-key is required when using --vault-encrypt")
        })?;
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