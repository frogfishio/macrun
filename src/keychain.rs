// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use keyring::Entry;
use serde::{Deserialize, Serialize};

const GLOBAL_SERVICE: &str = "macrun/global";
const MASTER_SECRET_ACCOUNT: &str = "__master_secret__";
const PROJECT_BUNDLE_ACCOUNT: &str = "__project_bundle__";

type ScopeSecrets = BTreeMap<String, String>;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProjectSecretBundle {
    pub envs: BTreeMap<String, ScopeSecrets>,
}

fn legacy_keychain_entry(project: &str, env: &str, key: &str) -> Result<Entry> {
    let service = format!("macrun/{project}/{env}");
    Entry::new(&service, key).context("failed to create Keychain entry")
}

fn project_bundle_entry(project: &str) -> Result<Entry> {
    let service = format!("macrun/{project}");
    Entry::new(&service, PROJECT_BUNDLE_ACCOUNT).context("failed to create Keychain entry")
}

fn master_secret_entry() -> Result<Entry> {
    Entry::new(GLOBAL_SERVICE, MASTER_SECRET_ACCOUNT).context("failed to create Keychain entry")
}

pub fn write_master_secret(secret: &str) -> Result<()> {
    let entry = master_secret_entry()?;
    entry
        .set_password(secret)
        .context("failed to store master secret in Keychain")
}

pub fn read_master_secret() -> Result<String> {
    let entry = master_secret_entry()?;
    entry
        .get_password()
        .context("failed to read master secret from Keychain")
}

pub fn clear_master_secret() -> Result<()> {
    let entry = master_secret_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(err).context("failed to delete master secret from Keychain"),
    }
}

pub fn has_master_secret() -> Result<bool> {
    let entry = master_secret_entry()?;
    match entry.get_password() {
        Ok(_) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(err) => Err(err).context("failed to check master secret in Keychain"),
    }
}

pub fn read_project_bundle(project: &str) -> Result<ProjectSecretBundle> {
    let entry = project_bundle_entry(project)?;
    match entry.get_password() {
        Ok(contents) => serde_json::from_str(&contents)
            .with_context(|| format!("failed to decode Keychain bundle for {project}")),
        Err(keyring::Error::NoEntry) => Ok(ProjectSecretBundle::default()),
        Err(err) => Err(err)
            .with_context(|| format!("failed to read Keychain bundle for {project}")),
    }
}

pub fn write_project_bundle(project: &str, bundle: &ProjectSecretBundle) -> Result<()> {
    let entry = project_bundle_entry(project)?;
    if bundle.envs.is_empty() {
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => return Ok(()),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to delete Keychain bundle for {project}"));
            }
        }
    }

    let contents = serde_json::to_string(bundle)
        .with_context(|| format!("failed to encode Keychain bundle for {project}"))?;
    entry
        .set_password(&contents)
        .with_context(|| format!("failed to store Keychain bundle for {project}"))
}

pub fn read_scope_secrets(project: &str, env: &str) -> Result<ScopeSecrets> {
    let bundle = read_project_bundle(project)?;
    Ok(bundle.envs.get(env).cloned().unwrap_or_default())
}

pub fn write_scope_secrets(project: &str, env: &str, secrets: &ScopeSecrets) -> Result<()> {
    let mut bundle = read_project_bundle(project)?;
    if secrets.is_empty() {
        bundle.envs.remove(env);
    } else {
        bundle.envs.insert(env.to_owned(), secrets.clone());
    }
    write_project_bundle(project, &bundle)
}

pub fn read_legacy_secret(project: &str, env: &str, key: &str) -> Result<String> {
    let entry = legacy_keychain_entry(project, env, key)?;
    entry
        .get_password()
        .with_context(|| format!("failed to read legacy Keychain item for {project}/{env}/{key}"))
}

pub fn delete_legacy_secret(project: &str, env: &str, key: &str) -> Result<()> {
    let entry = legacy_keychain_entry(project, env, key)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(err).with_context(|| {
            format!("failed to delete legacy Keychain item for {project}/{env}/{key}")
        }),
    }
}

pub fn store_secret(project: &str, env: &str, key: &str, value: &str) -> Result<()> {
    let mut secrets = read_scope_secrets(project, env)?;
    secrets.insert(key.to_owned(), value.to_owned());
    write_scope_secrets(project, env, &secrets)
}

pub fn read_secret(project: &str, env: &str, key: &str) -> Result<String> {
    let secrets = read_scope_secrets(project, env)?;
    if let Some(value) = secrets.get(key) {
        return Ok(value.clone());
    }
    read_legacy_secret(project, env, key)
}

pub fn delete_secret(project: &str, env: &str, key: &str) -> Result<()> {
    let mut secrets = read_scope_secrets(project, env)?;
    secrets.remove(key);
    write_scope_secrets(project, env, &secrets)?;
    delete_legacy_secret(project, env, key)
}
