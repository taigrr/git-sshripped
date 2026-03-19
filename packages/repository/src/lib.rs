#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use git_ssh_crypt_repository_models::RepositoryManifest;

#[must_use]
pub fn metadata_dir(repo_root: &Path) -> PathBuf {
    repo_root.join(".git-ssh-crypt")
}

#[must_use]
pub fn manifest_file(repo_root: &Path) -> PathBuf {
    metadata_dir(repo_root).join("manifest.toml")
}

pub fn write_manifest(repo_root: &Path, manifest: &RepositoryManifest) -> Result<()> {
    let dir = metadata_dir(repo_root);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create metadata directory {}", dir.display()))?;
    let text = toml::to_string_pretty(manifest).context("failed to serialize manifest")?;
    let file = manifest_file(repo_root);
    fs::write(&file, text).with_context(|| format!("failed to write {}", file.display()))?;
    Ok(())
}

pub fn read_manifest(repo_root: &Path) -> Result<RepositoryManifest> {
    let file = manifest_file(repo_root);
    let text = fs::read_to_string(&file)
        .with_context(|| format!("failed to read manifest {}", file.display()))?;
    toml::from_str(&text).context("failed to parse repository manifest")
}

pub fn install_gitattributes(repo_root: &Path, patterns: &[String]) -> Result<()> {
    let path = repo_root.join(".gitattributes");
    let mut existing = if path.exists() {
        fs::read_to_string(&path)
            .with_context(|| format!("failed to read gitattributes {}", path.display()))?
    } else {
        String::new()
    };

    for pattern in patterns {
        let line = format!("{pattern} filter=git-ssh-crypt diff=git-ssh-crypt");
        if !existing.lines().any(|item| item.trim() == line) {
            if !existing.ends_with('\n') && !existing.is_empty() {
                existing.push('\n');
            }
            existing.push_str(&line);
            existing.push('\n');
        }
    }

    fs::write(&path, existing)
        .with_context(|| format!("failed to write gitattributes {}", path.display()))?;
    Ok(())
}

pub fn install_git_filters(repo_root: &Path) -> Result<()> {
    let pairs = [
        (
            "filter.git-ssh-crypt.clean",
            "git-ssh-crypt clean --path %f",
        ),
        (
            "filter.git-ssh-crypt.smudge",
            "git-ssh-crypt smudge --path %f",
        ),
        ("filter.git-ssh-crypt.required", "true"),
        (
            "diff.git-ssh-crypt.textconv",
            "git-ssh-crypt diff --path %f",
        ),
    ];

    for (key, value) in pairs {
        let status = Command::new("git")
            .args(["config", "--local", key, value])
            .current_dir(repo_root)
            .status()
            .with_context(|| format!("failed to set git config {key}"))?;

        if !status.success() {
            anyhow::bail!("git config failed for key '{key}'");
        }
    }
    Ok(())
}
