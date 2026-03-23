use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE_NAME: &str = ".macrun.toml";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LocalConfig {
    pub project: String,
    pub default_profile: String,
}

#[derive(Clone, Debug)]
pub struct LocalConfigHit {
    pub path: PathBuf,
    pub config: LocalConfig,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedScope {
    pub project: String,
    pub profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,
}

pub fn find_local_config(start: &Path) -> Result<Option<LocalConfigHit>> {
    for dir in start.ancestors() {
        let candidate = dir.join(CONFIG_FILE_NAME);
        if candidate.exists() {
            let contents = fs::read_to_string(&candidate)
                .with_context(|| format!("failed to read {}", candidate.display()))?;
            let config = toml::from_str::<LocalConfig>(&contents)
                .with_context(|| format!("failed to parse {}", candidate.display()))?;
            return Ok(Some(LocalConfigHit {
                path: candidate,
                config,
            }));
        }
    }
    Ok(None)
}
