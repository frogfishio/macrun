use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Result};

use crate::index::StoredSecretMeta;

pub fn parse_pair(input: &str) -> Result<(String, String)> {
    let (name, value) = input
        .split_once('=')
        .ok_or_else(|| anyhow!("expected NAME=value, got `{input}`"))?;
    validate_env_name(name)?;
    Ok((name.to_owned(), value.to_owned()))
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

pub fn select_entries<'a>(
    entries: Vec<&'a StoredSecretMeta>,
    only: &[String],
    prefixes: &[String],
) -> Result<Vec<&'a StoredSecretMeta>> {
    if only.is_empty() && prefixes.is_empty() {
        return Ok(entries);
    }

    let only_set: BTreeSet<&str> = only.iter().map(String::as_str).collect();
    for key in &only_set {
        validate_env_name(key)?;
    }

    let selected: Vec<&StoredSecretMeta> = entries
        .into_iter()
        .filter(|entry| {
            only_set.contains(entry.key.as_str())
                || prefixes.iter().any(|prefix| entry.key.starts_with(prefix))
        })
        .collect();

    let selected_names: BTreeSet<&str> = selected.iter().map(|entry| entry.key.as_str()).collect();
    let missing: Vec<&str> = only_set
        .into_iter()
        .filter(|name| !selected_names.contains(name))
        .collect();
    if !missing.is_empty() {
        bail!("requested secret(s) not found: {}", missing.join(", "));
    }

    Ok(selected)
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
    use super::{parse_env_file, parse_pair, select_entries, shell_quote};
    use crate::index::StoredSecretMeta;

    #[test]
    fn parse_pair_accepts_basic_assignment() {
        let (name, value) = parse_pair("K2MX_API_KEY=secret").unwrap();
        assert_eq!(name, "K2MX_API_KEY");
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
    fn select_entries_respects_only_and_prefix() {
        let entries = vec![
            StoredSecretMeta::new(
                "frogfish-k2".into(),
                "dev".into(),
                "RBAC_JWT_SECRET".into(),
                "manual".into(),
                None,
            ),
            StoredSecretMeta::new(
                "frogfish-k2".into(),
                "dev".into(),
                "K2MX_K2DB_API_KEY".into(),
                "manual".into(),
                None,
            ),
        ];
        let refs = entries.iter().collect::<Vec<_>>();
        let selected = select_entries(refs, &["RBAC_JWT_SECRET".into()], &["K2MX_".into()]).unwrap();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn shell_quote_wraps_single_quotes() {
        assert_eq!(shell_quote("ab'cd"), "'ab'\\''cd'");
    }
}
