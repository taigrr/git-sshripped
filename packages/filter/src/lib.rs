#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use anyhow::{Result, bail};
use git_sshripped_encryption::{decrypt, encrypt, is_encrypted};
use git_sshripped_encryption_models::EncryptionAlgorithm;

pub fn clean(
    algorithm: EncryptionAlgorithm,
    repo_key: Option<&[u8]>,
    path: &str,
    content: &[u8],
) -> Result<Vec<u8>> {
    if is_encrypted(content) {
        return Ok(content.to_vec());
    }

    let key = repo_key.ok_or_else(|| {
        anyhow::anyhow!(
            "repository is locked and cannot encrypt protected file '{}'; run git-sshripped unlock",
            path
        )
    })?;
    encrypt(algorithm, key, path, content)
}

pub fn smudge(repo_key: Option<&[u8]>, path: &str, content: &[u8]) -> Result<Vec<u8>> {
    if !is_encrypted(content) {
        return Ok(content.to_vec());
    }

    if let Some(key) = repo_key {
        return decrypt(key, path, content);
    }

    Ok(content.to_vec())
}

pub fn diff(repo_key: Option<&[u8]>, path: &str, content: &[u8]) -> Result<Vec<u8>> {
    if !is_encrypted(content) {
        return Ok(content.to_vec());
    }

    if let Some(key) = repo_key {
        return decrypt(key, path, content);
    }

    bail!("file '{}' is encrypted and repository is locked", path)
}
