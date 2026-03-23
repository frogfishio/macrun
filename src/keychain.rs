// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use keyring::Entry;

fn keychain_entry(project: &str, env: &str, key: &str) -> Result<Entry> {
    let service = format!("macrun/{project}/{env}");
    Entry::new(&service, key).context("failed to create Keychain entry")
}

pub fn store_secret(project: &str, env: &str, key: &str, value: &str) -> Result<()> {
    let entry = keychain_entry(project, env, key)?;
    entry
        .set_password(value)
        .with_context(|| format!("failed to store Keychain item for {project}/{env}/{key}"))
}

pub fn read_secret(project: &str, env: &str, key: &str) -> Result<String> {
    let entry = keychain_entry(project, env, key)?;
    entry
        .get_password()
        .with_context(|| format!("failed to read Keychain item for {project}/{env}/{key}"))
}

pub fn delete_secret(project: &str, env: &str, key: &str) -> Result<()> {
    let entry = keychain_entry(project, env, key)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(err)
            .with_context(|| format!("failed to delete Keychain item for {project}/{env}/{key}")),
    }
}
