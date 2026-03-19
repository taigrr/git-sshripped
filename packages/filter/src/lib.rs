#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use anyhow::{Result, bail};
use git_ssh_crypt_encryption::{decrypt, encrypt, is_encrypted};
use git_ssh_crypt_repository_models::RepositoryManifest;
use globset::{Glob, GlobSet, GlobSetBuilder};

fn compile_protected_set(manifest: &RepositoryManifest) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in &manifest.protected_patterns {
        builder.add(Glob::new(pattern)?);
    }
    Ok(builder.build()?)
}

pub fn is_protected_path(manifest: &RepositoryManifest, path: &str) -> Result<bool> {
    let set = compile_protected_set(manifest)?;
    Ok(set.is_match(path))
}

pub fn clean(
    manifest: &RepositoryManifest,
    repo_key: Option<&[u8]>,
    path: &str,
    content: &[u8],
) -> Result<Vec<u8>> {
    if !is_protected_path(manifest, path)? {
        return Ok(content.to_vec());
    }

    if is_encrypted(content) {
        return Ok(content.to_vec());
    }

    let key = repo_key.ok_or_else(|| {
        anyhow::anyhow!(
            "repository is locked and cannot encrypt protected file '{}'; run git-ssh-crypt unlock",
            path
        )
    })?;
    encrypt(manifest.encryption_algorithm, key, path, content)
}

pub fn smudge(
    manifest: &RepositoryManifest,
    repo_key: Option<&[u8]>,
    path: &str,
    content: &[u8],
) -> Result<Vec<u8>> {
    if !is_protected_path(manifest, path)? {
        return Ok(content.to_vec());
    }

    if !is_encrypted(content) {
        return Ok(content.to_vec());
    }

    if let Some(key) = repo_key {
        return decrypt(key, path, content);
    }

    Ok(content.to_vec())
}

pub fn diff(
    manifest: &RepositoryManifest,
    repo_key: Option<&[u8]>,
    path: &str,
    content: &[u8],
) -> Result<Vec<u8>> {
    if !is_protected_path(manifest, path)? || !is_encrypted(content) {
        return Ok(content.to_vec());
    }

    if let Some(key) = repo_key {
        return decrypt(key, path, content);
    }

    bail!("file '{}' is encrypted and repository is locked", path)
}
