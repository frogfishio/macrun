// SPDX-FileCopyrightText: 2026 Alexander R. Croft
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

const FILE_FORMAT: &str = "macrun-sealed-scope";
const FILE_VERSION: u32 = 1;
const PBKDF2_ITERATIONS: u32 = 600_000;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const AAD_CONTEXT: &[u8] = b"macrun-sealed-scope-v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedScopeFile {
    pub format: String,
    pub version: u32,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SealedScopePayload {
    Scope {
        project: String,
        env: String,
        secrets: BTreeMap<String, String>,
    },
    Project {
        project: String,
        envs: BTreeMap<String, BTreeMap<String, String>>,
    },
}

pub fn seal_scope(master_secret: &str, payload: &SealedScopePayload) -> Result<SealedScopeFile> {
    if master_secret.is_empty() {
        return Err(anyhow!("master secret cannot be empty"));
    }

    let random = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    random
        .fill(&mut salt)
        .map_err(|_| anyhow!("failed to generate salt"))?;
    random
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow!("failed to generate nonce"))?;

    let key = derive_key(master_secret, &salt);
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &key)
            .map_err(|_| anyhow!("failed to prepare encryption key"))?,
    );

    let mut plaintext = serde_json::to_vec(payload).context("failed to encode sealed payload")?;
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(AAD_CONTEXT),
        &mut plaintext,
    )
    .map_err(|_| anyhow!("failed to encrypt scope payload"))?;

    Ok(SealedScopeFile {
        format: FILE_FORMAT.to_owned(),
        version: FILE_VERSION,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(plaintext),
    })
}

pub fn open_scope(master_secret: &str, sealed: &SealedScopeFile) -> Result<SealedScopePayload> {
    if sealed.format != FILE_FORMAT {
        return Err(anyhow!("unsupported sealed file format: {}", sealed.format));
    }
    if sealed.version != FILE_VERSION {
        return Err(anyhow!("unsupported sealed file version: {}", sealed.version));
    }

    let salt = decode_exact::<SALT_LEN>(&sealed.salt, "salt")?;
    let nonce_bytes = decode_exact::<NONCE_LEN>(&sealed.nonce, "nonce")?;
    let mut ciphertext = STANDARD
        .decode(&sealed.ciphertext)
        .context("failed to decode ciphertext")?;

    let key = derive_key(master_secret, &salt);
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &key)
            .map_err(|_| anyhow!("failed to prepare decryption key"))?,
    );
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(AAD_CONTEXT),
            &mut ciphertext,
        )
        .map_err(|_| anyhow!("failed to decrypt sealed scope file"))?;

    serde_json::from_slice(plaintext).context("failed to decode decrypted scope payload")
}

fn derive_key(master_secret: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).expect("PBKDF2 iterations must be non-zero"),
        salt,
        master_secret.as_bytes(),
        &mut key,
    );
    key
}

fn decode_exact<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let decoded = STANDARD
        .decode(value)
        .with_context(|| format!("failed to decode {label}"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("invalid {label} length"))
}

#[cfg(test)]
mod tests {
    use super::{open_scope, seal_scope, SealedScopePayload};
    use std::collections::BTreeMap;

    #[test]
    fn sealed_scope_round_trips() {
        let mut secrets = BTreeMap::new();
        secrets.insert("APP_KEY".to_owned(), "secret".to_owned());
        let payload = SealedScopePayload::Scope {
            project: "my-app".to_owned(),
            env: "dev".to_owned(),
            secrets,
        };

        let sealed = seal_scope("correct horse battery staple", &payload).unwrap();
        let opened = open_scope("correct horse battery staple", &sealed).unwrap();
        match opened {
            SealedScopePayload::Scope {
                project,
                env,
                secrets,
            } => {
                assert_eq!(project, "my-app");
                assert_eq!(env, "dev");
                assert_eq!(secrets.get("APP_KEY").unwrap(), "secret");
            }
            SealedScopePayload::Project { .. } => panic!("expected scope payload"),
        }
    }
}
