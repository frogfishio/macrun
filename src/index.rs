use serde::{Deserialize, Serialize};

use crate::util::iso_timestamp_now;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IndexFile {
    pub entries: Vec<StoredSecretMeta>,
}

impl IndexFile {
    pub fn upsert(&mut self, entry: StoredSecretMeta) {
        if let Some(existing) = self.entries.iter_mut().find(|candidate| {
            candidate.project == entry.project
                && candidate.profile == entry.profile
                && candidate.key == entry.key
        }) {
            *existing = entry;
        } else {
            self.entries.push(entry);
            self.entries.sort_by(|left, right| {
                (&left.project, &left.profile, &left.key)
                    .cmp(&(&right.project, &right.profile, &right.key))
            });
        }
    }

    pub fn contains(&self, project: &str, profile: &str, key: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.project == project && entry.profile == profile && entry.key == key)
    }

    pub fn remove(&mut self, project: &str, profile: &str, key: &str) {
        self.entries.retain(|entry| {
            !(entry.project == project && entry.profile == profile && entry.key == key)
        });
    }

    pub fn entries_for_scope(&self, project: &str, profile: &str) -> Vec<&StoredSecretMeta> {
        self.entries
            .iter()
            .filter(|entry| entry.project == project && entry.profile == profile)
            .collect()
    }

    pub fn filtered_entries(
        &self,
        project: &str,
        profile: &str,
        prefixes: &[String],
    ) -> Vec<StoredSecretMeta> {
        self.entries
            .iter()
            .filter(|entry| entry.project == project && entry.profile == profile)
            .filter(|entry| {
                prefixes.is_empty() || prefixes.iter().any(|prefix| entry.key.starts_with(prefix))
            })
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredSecretMeta {
    pub project: String,
    pub profile: String,
    pub key: String,
    pub source: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl StoredSecretMeta {
    pub fn new(
        project: String,
        profile: String,
        key: String,
        source: String,
        note: Option<String>,
    ) -> Self {
        Self {
            project,
            profile,
            key,
            source,
            updated_at: iso_timestamp_now(),
            note,
        }
    }
}
