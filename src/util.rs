// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, bail, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvMapping {
    pub source: String,
    pub target: String,
}

pub fn parse_pair(input: &str) -> Result<(String, String)> {
    let (name, value) = input
        .split_once('=')
        .ok_or_else(|| anyhow!("expected NAME=value, got `{input}`"))?;
    validate_env_name(name)?;
    Ok((name.to_owned(), value.to_owned()))
}

pub fn parse_env_mapping(input: &str) -> Result<EnvMapping> {
    if let Some((source, target)) = input.split_once('=') {
        validate_env_name(source)?;
        validate_env_name(target)?;
        Ok(EnvMapping {
            source: source.to_owned(),
            target: target.to_owned(),
        })
    } else {
        validate_env_name(input)?;
        Ok(EnvMapping {
            source: input.to_owned(),
            target: input.to_owned(),
        })
    }
}

pub fn parse_env_file(contents: &str) -> Result<Vec<(String, String)>> {
    let mut parsed = Vec::new();
    for (line_no, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid env line {}: {}", line_no + 1, raw_line))?;
        validate_env_name(name.trim())?;
        parsed.push((name.trim().to_owned(), unquote(value.trim())));
    }
    Ok(parsed)
}

pub fn validate_env_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("env var name cannot be empty");
    }
    if name.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        bail!("env var name cannot start with a digit: {name}");
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        bail!("env var name may only contain A-Z, a-z, 0-9, and _: {name}");
    }
    Ok(())
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn iso_timestamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", now)
}

fn unquote(value: &str) -> String {
    if value.len() >= 2 {
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::{parse_env_file, parse_env_mapping, parse_pair, shell_quote, EnvMapping};

    #[test]
    fn parse_pair_accepts_basic_assignment() {
        let (name, value) = parse_pair("APP_API_KEY=secret").unwrap();
        assert_eq!(name, "APP_API_KEY");
        assert_eq!(value, "secret");
    }

    #[test]
    fn parse_env_file_ignores_comments_and_unquotes() {
        let parsed = parse_env_file(
            "# comment\nexport RBAC_JWT_SECRET=secret\nK2DB_MONGO_URI=\"mongodb://127.0.0.1\"\n",
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "RBAC_JWT_SECRET");
        assert_eq!(parsed[1].1, "mongodb://127.0.0.1");
    }

    #[test]
    fn shell_quote_wraps_single_quotes() {
        assert_eq!(shell_quote("ab'cd"), "'ab'\\''cd'");
    }

    #[test]
    fn parse_env_mapping_defaults_target_to_source() {
        assert_eq!(
            parse_env_mapping("APP_CLIENT_SECRET").unwrap(),
            EnvMapping {
                source: "APP_CLIENT_SECRET".to_owned(),
                target: "APP_CLIENT_SECRET".to_owned(),
            }
        );
    }

    #[test]
    fn parse_env_mapping_accepts_source_and_target() {
        assert_eq!(
            parse_env_mapping("APP_CLIENT_SECRET=APP_CLIENT_SECRET_CIPHERTEXT").unwrap(),
            EnvMapping {
                source: "APP_CLIENT_SECRET".to_owned(),
                target: "APP_CLIENT_SECRET_CIPHERTEXT".to_owned(),
            }
        );
    }
}
