use anyhow::{Context, Result};
use keyring::Entry;

fn keychain_entry(project: &str, profile: &str, key: &str) -> Result<Entry> {
    let service = format!("macrun/{project}/{profile}");
    Entry::new(&service, key).context("failed to create Keychain entry")
}

pub fn store_secret(project: &str, profile: &str, key: &str, value: &str) -> Result<()> {
    let entry = keychain_entry(project, profile, key)?;
    entry
        .set_password(value)
        .with_context(|| format!("failed to store Keychain item for {project}/{profile}/{key}"))
}

pub fn read_secret(project: &str, profile: &str, key: &str) -> Result<String> {
    let entry = keychain_entry(project, profile, key)?;
    entry
        .get_password()
        .with_context(|| format!("failed to read Keychain item for {project}/{profile}/{key}"))
}

pub fn delete_secret(project: &str, profile: &str, key: &str) -> Result<()> {
    let entry = keychain_entry(project, profile, key)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(err)
            .with_context(|| format!("failed to delete Keychain item for {project}/{profile}/{key}")),
    }
}
