#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use git_sshripped_repository_models::{
    GithubSourceRegistry, RepositoryLocalConfig, RepositoryManifest,
};

#[must_use]
pub fn metadata_dir(repo_root: &Path) -> PathBuf {
    repo_root.join(".git-sshripped")
}

#[must_use]
pub fn manifest_file(repo_root: &Path) -> PathBuf {
    metadata_dir(repo_root).join("manifest.toml")
}

#[must_use]
pub fn github_sources_file(repo_root: &Path) -> PathBuf {
    metadata_dir(repo_root).join("github-sources.toml")
}

#[must_use]
pub fn local_config_file(repo_root: &Path) -> PathBuf {
    metadata_dir(repo_root).join("config.toml")
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

pub fn read_github_sources(repo_root: &Path) -> Result<GithubSourceRegistry> {
    let file = github_sources_file(repo_root);
    if !file.exists() {
        return Ok(GithubSourceRegistry::default());
    }
    let text = fs::read_to_string(&file)
        .with_context(|| format!("failed to read github source registry {}", file.display()))?;
    toml::from_str(&text).context("failed to parse github source registry")
}

pub fn write_github_sources(repo_root: &Path, registry: &GithubSourceRegistry) -> Result<()> {
    let dir = metadata_dir(repo_root);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create metadata directory {}", dir.display()))?;
    let text = toml::to_string_pretty(registry).context("failed to serialize github sources")?;
    let file = github_sources_file(repo_root);
    fs::write(&file, text)
        .with_context(|| format!("failed to write github source registry {}", file.display()))?;
    Ok(())
}

pub fn read_local_config(repo_root: &Path) -> Result<RepositoryLocalConfig> {
    let file = local_config_file(repo_root);
    if !file.exists() {
        return Ok(RepositoryLocalConfig::default());
    }
    let text = fs::read_to_string(&file)
        .with_context(|| format!("failed to read repository config {}", file.display()))?;
    toml::from_str(&text).context("failed to parse repository local config")
}

pub fn write_local_config(repo_root: &Path, config: &RepositoryLocalConfig) -> Result<()> {
    let dir = metadata_dir(repo_root);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create metadata directory {}", dir.display()))?;
    let text = toml::to_string_pretty(config).context("failed to serialize local config")?;
    let file = local_config_file(repo_root);
    fs::write(&file, text)
        .with_context(|| format!("failed to write local config {}", file.display()))?;
    Ok(())
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
        let line = if let Some(negated) = pattern.strip_prefix('!') {
            format!("{negated} !filter !diff")
        } else {
            format!("{pattern} filter=git-sshripped diff=git-sshripped")
        };
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

pub fn install_git_filters(repo_root: &Path, bin: &str) -> Result<()> {
    let pairs = [
        (
            "filter.git-sshripped.process".to_string(),
            format!("{bin} filter-process"),
        ),
        (
            "filter.git-sshripped.clean".to_string(),
            format!("{bin} clean --path %f"),
        ),
        (
            "filter.git-sshripped.smudge".to_string(),
            format!("{bin} smudge --path %f"),
        ),
        (
            "filter.git-sshripped.required".to_string(),
            "true".to_string(),
        ),
        (
            "diff.git-sshripped.textconv".to_string(),
            format!("{bin} diff --path %f"),
        ),
    ];

    for (key, value) in &pairs {
        let status = Command::new("git")
            .args(["config", "--local", key.as_str(), value.as_str()])
            .current_dir(repo_root)
            .status()
            .with_context(|| format!("failed to set git config {key}"))?;

        if !status.success() {
            anyhow::bail!("git config failed for key '{key}'");
        }
    }
    Ok(())
}
