// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

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
                && candidate.env == entry.env
                && candidate.key == entry.key
        }) {
            *existing = entry;
        } else {
            self.entries.push(entry);
            self.entries.sort_by(|left, right| {
                (&left.project, &left.env, &left.key).cmp(&(&right.project, &right.env, &right.key))
            });
        }
    }

    pub fn contains(&self, project: &str, env: &str, key: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.project == project && entry.env == env && entry.key == key)
    }

    pub fn remove(&mut self, project: &str, env: &str, key: &str) {
        self.entries.retain(|entry| {
            !(entry.project == project && entry.env == env && entry.key == key)
        });
    }

    pub fn entries_for_scope(&self, project: &str, env: &str) -> Vec<&StoredSecretMeta> {
        self.entries
            .iter()
            .filter(|entry| entry.project == project && entry.env == env)
            .collect()
    }

    pub fn entries_owned_for_scope(&self, project: &str, env: &str) -> Vec<StoredSecretMeta> {
        self.entries
            .iter()
            .filter(|entry| entry.project == project && entry.env == env)
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredSecretMeta {
    pub project: String,
    #[serde(alias = "profile")]
    pub env: String,
    pub key: String,
    pub source: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl StoredSecretMeta {
    pub fn new(
        project: String,
        env: String,
        key: String,
        source: String,
        note: Option<String>,
    ) -> Self {
        Self {
            project,
            env,
            key,
            source,
            updated_at: iso_timestamp_now(),
            note,
        }
    }
}
