use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

pub struct K2MxClient {
    client: Client,
    base_url: String,
}

impl K2MxClient {
    pub fn new(base_url: &str, bootstrap_token: &str) -> Result<Self> {
        if base_url.trim().is_empty() {
            bail!("k2mx base URL cannot be empty");
        }
        if bootstrap_token.trim().is_empty() {
            bail!("k2mx bootstrap token cannot be empty");
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-bootstrap-token",
            HeaderValue::from_str(bootstrap_token)
                .context("k2mx bootstrap token contains invalid header bytes")?,
        );

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("failed to build k2mx HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
        })
    }

    pub fn create_provider_secret(
        &self,
        request: &CreateProviderSecretRequest,
    ) -> Result<CreateResult> {
        let url = format!("{}/v1/admin/provider-secrets", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(request)
            .send()
            .with_context(|| format!("failed to call k2mx provider secret create at {url}"))?;

        let status = response.status();
        let body = response
            .text()
            .context("failed to read k2mx provider secret create response")?;

        if !status.is_success() {
            bail!("k2mx provider secret create failed with {status}: {body}");
        }

        serde_json::from_str(&body).context("failed to parse k2mx provider secret create response")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateProviderSecretRequest {
    pub provider_id: String,
    pub version: String,
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret_wrapped: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateResult {
    pub id: String,
}