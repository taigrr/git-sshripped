#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use git_ssh_crypt_recipient_models::{RecipientKey, RecipientSource};
use sha2::{Digest, Sha256};

#[must_use]
pub fn recipient_store_dir(repo_root: &Path) -> PathBuf {
    repo_root.join(".git-ssh-crypt").join("recipients")
}

pub fn add_recipient_from_public_key(
    repo_root: &Path,
    public_key_line: &str,
    source: RecipientSource,
) -> Result<RecipientKey> {
    let trimmed = public_key_line.trim();
    if trimmed.is_empty() {
        bail!("empty SSH public key line");
    }

    let mut parts = trimmed.split_whitespace();
    let key_type = parts
        .next()
        .context("SSH public key is missing key type")?
        .to_string();
    let key_body = parts
        .next()
        .context("SSH public key is missing key material")?;

    let mut hasher = Sha256::new();
    hasher.update(key_type.as_bytes());
    hasher.update([b':']);
    hasher.update(key_body.as_bytes());
    let fingerprint = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hasher.finalize());

    let recipient = RecipientKey {
        fingerprint: fingerprint.clone(),
        key_type,
        public_key_line: trimmed.to_string(),
        source,
    };

    let dir = recipient_store_dir(repo_root);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create recipient dir {}", dir.display()))?;
    let file = dir.join(format!("{fingerprint}.toml"));
    let content = toml::to_string_pretty(&recipient)
        .with_context(|| format!("failed to serialize recipient {}", recipient.fingerprint))?;
    fs::write(&file, content)
        .with_context(|| format!("failed to write recipient file {}", file.display()))?;

    Ok(recipient)
}

pub fn add_recipients_from_github_keys(repo_root: &Path, url: &str) -> Result<Vec<RecipientKey>> {
    let text = reqwest::blocking::get(url)
        .with_context(|| format!("failed to GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GitHub keys request returned error for {url}"))?
        .text()
        .context("failed to read GitHub keys body")?;

    let mut added = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let recipient =
            add_recipient_from_public_key(repo_root, line, RecipientSource::GithubKeysUrl)
                .with_context(|| format!("failed to add recipient from key line '{line}'"))?;
        added.push(recipient);
    }

    Ok(added)
}
