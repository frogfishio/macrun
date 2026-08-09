// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

pub struct VaultClient {
    client: Client,
    vault_addr: String,
}

impl VaultClient {
    pub fn from_env(vault_addr: &str) -> Result<Self> {
        let token = std::env::var("VAULT_TOKEN")
            .map_err(|_| anyhow!("VAULT_TOKEN is required for Vault operations"))?;
        Self::new(vault_addr, &token)
    }

    pub fn new(vault_addr: &str, token: &str) -> Result<Self> {
        if vault_addr.trim().is_empty() {
            bail!("vault address cannot be empty");
        }
        if token.trim().is_empty() {
            bail!("Vault token cannot be empty");
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Vault-Token",
            HeaderValue::from_str(token).context("Vault token contains invalid header bytes")?,
        );

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("failed to build Vault HTTP client")?;

        Ok(Self {
            client,
            vault_addr: vault_addr.trim_end_matches('/').to_owned(),
        })
    }

    pub fn encrypt(
        &self,
        transit_path: &str,
        key_name: &str,
        plaintext: &[u8],
    ) -> Result<EncryptResponse> {
        if transit_path.trim().is_empty() {
            bail!("transit path cannot be empty");
        }
        if key_name.trim().is_empty() {
            bail!("vault key cannot be empty");
        }

        let url = self.endpoint(transit_path, &format!("encrypt/{key_name}"));
        let payload = EncryptRequest {
            plaintext: STANDARD.encode(plaintext),
        };

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .with_context(|| format!("failed to call Vault transit encrypt at {url}"))?;

        let status = response.status();
        let body = response.text().context("failed to read Vault response body")?;
        if !status.is_success() {
            bail!("Vault transit encrypt failed with {status}: {body}");
        }

        let parsed: VaultEnvelope<EncryptData> =
            serde_json::from_str(&body).context("failed to parse Vault transit encrypt response")?;
        Ok(EncryptResponse {
            ciphertext: parsed.data.ciphertext,
        })
    }

    pub fn decrypt(&self, transit_path: &str, key_name: &str, ciphertext: &str) -> Result<String> {
        if transit_path.trim().is_empty() {
            bail!("transit path cannot be empty");
        }
        if key_name.trim().is_empty() {
            bail!("vault key cannot be empty");
        }

        let url = self.endpoint(transit_path, &format!("decrypt/{key_name}"));
        let payload = DecryptRequest {
            ciphertext: ciphertext.to_owned(),
        };

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .with_context(|| format!("failed to call Vault transit decrypt at {url}"))?;

        let status = response.status();
        let body = response.text().context("failed to read Vault response body")?;
        if !status.is_success() {
            bail!("Vault transit decrypt failed with {status}: {body}");
        }

        let parsed: VaultEnvelope<DecryptData> =
            serde_json::from_str(&body).context("failed to parse Vault transit decrypt response")?;
        let decoded = STANDARD
            .decode(parsed.data.plaintext)
            .context("failed to decode Vault transit plaintext")?;
        String::from_utf8(decoded).context("Vault transit plaintext was not valid UTF-8")
    }

    pub fn kv_put(
        &self,
        mount: &str,
        path: &str,
        kv_version: KvVersion,
        data: BTreeMap<String, String>,
    ) -> Result<()> {
        let mount = mount.trim_matches('/');
        let path = path.trim_matches('/');
        if mount.is_empty() {
            bail!("Vault mount cannot be empty");
        }
        if path.is_empty() {
            bail!("Vault path cannot be empty");
        }
        if data.is_empty() {
            bail!("at least one secret is required to write to Vault");
        }

        let suffix = match kv_version {
            KvVersion::V1 => path.to_owned(),
            KvVersion::V2 => format!("data/{path}"),
        };
        let url = self.endpoint(mount, &suffix);
        let payload = match kv_version {
            KvVersion::V1 => serde_json::json!(data),
            KvVersion::V2 => serde_json::json!({ "data": data }),
        };

        let response = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .with_context(|| format!("failed to write secrets to Vault KV at {url}"))?;

        let status = response.status();
        let body = response.text().context("failed to read Vault response body")?;
        if !status.is_success() {
            bail!("Vault KV write failed with {status}: {body}");
        }

        Ok(())
    }

    fn endpoint(&self, mount: &str, suffix: &str) -> String {
        format!(
            "{}/v1/{}/{}",
            self.vault_addr,
            mount.trim_matches('/'),
            suffix.trim_matches('/')
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum KvVersion {
    V1,
    V2,
}

pub fn parse_key_version(ciphertext: &str) -> Option<u32> {
    let mut parts = ciphertext.split(':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("vault"), Some(version), Some(_)) => version.strip_prefix('v')?.parse().ok(),
        _ => None,
    }
}

pub struct EncryptResponse {
    pub ciphertext: String,
}

#[derive(Serialize)]
struct EncryptRequest {
    plaintext: String,
}

#[derive(Serialize)]
struct DecryptRequest {
    ciphertext: String,
}

#[derive(Deserialize)]
struct VaultEnvelope<T> {
    data: T,
}

#[derive(Deserialize)]
struct EncryptData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

#[cfg(test)]
mod tests {
    use super::parse_key_version;

    #[test]
    fn parse_key_version_reads_vault_prefix() {
        assert_eq!(parse_key_version("vault:v3:abcdef"), Some(3));
    }

    #[test]
    fn parse_key_version_rejects_non_vault_ciphertext() {
        assert_eq!(parse_key_version("not-vault"), None);
    }
}
