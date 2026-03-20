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

/// Write the repository manifest to `.git-sshripped/manifest.toml`.
///
/// # Errors
///
/// Returns an error if the metadata directory cannot be created, the manifest
/// cannot be serialized, or the file cannot be written.
pub fn write_manifest(repo_root: &Path, manifest: &RepositoryManifest) -> Result<()> {
    let dir = metadata_dir(repo_root);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create metadata directory {}", dir.display()))?;
    let text = toml::to_string_pretty(manifest).context("failed to serialize manifest")?;
    let file = manifest_file(repo_root);
    fs::write(&file, text).with_context(|| format!("failed to write {}", file.display()))?;
    Ok(())
}

/// Read the repository manifest from `.git-sshripped/manifest.toml`.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn read_manifest(repo_root: &Path) -> Result<RepositoryManifest> {
    let file = manifest_file(repo_root);
    let text = fs::read_to_string(&file)
        .with_context(|| format!("failed to read manifest {}", file.display()))?;
    toml::from_str(&text).context("failed to parse repository manifest")
}

/// Read the GitHub source registry, returning a default if the file does not exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or parsed.
pub fn read_github_sources(repo_root: &Path) -> Result<GithubSourceRegistry> {
    let file = github_sources_file(repo_root);
    if !file.exists() {
        return Ok(GithubSourceRegistry::default());
    }
    let text = fs::read_to_string(&file)
        .with_context(|| format!("failed to read github source registry {}", file.display()))?;
    toml::from_str(&text).context("failed to parse github source registry")
}

/// Write the GitHub source registry to `.git-sshripped/github-sources.toml`.
///
/// # Errors
///
/// Returns an error if the metadata directory cannot be created, the registry
/// cannot be serialized, or the file cannot be written.
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

/// Read the local repository config, returning a default if the file does not exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or parsed.
pub fn read_local_config(repo_root: &Path) -> Result<RepositoryLocalConfig> {
    let file = local_config_file(repo_root);
    if !file.exists() {
        return Ok(RepositoryLocalConfig::default());
    }
    let text = fs::read_to_string(&file)
        .with_context(|| format!("failed to read repository config {}", file.display()))?;
    toml::from_str(&text).context("failed to parse repository local config")
}

/// Write the local repository config to `.git-sshripped/config.toml`.
///
/// # Errors
///
/// Returns an error if the metadata directory cannot be created, the config
/// cannot be serialized, or the file cannot be written.
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

/// Append filter/diff attribute lines to `.gitattributes` for the given patterns.
///
/// # Errors
///
/// Returns an error if the `.gitattributes` file cannot be read or written.
pub fn install_gitattributes(repo_root: &Path, patterns: &[String]) -> Result<()> {
    let path = repo_root.join(".gitattributes");
    let mut existing = if path.exists() {
        fs::read_to_string(&path)
            .with_context(|| format!("failed to read gitattributes {}", path.display()))?
    } else {
        String::new()
    };

    for pattern in patterns {
        let line = pattern.strip_prefix('!').map_or_else(
            || format!("{pattern} filter=git-sshripped diff=git-sshripped"),
            |negated| format!("{negated} !filter !diff"),
        );
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

/// Shell-quote a string so it survives interpretation by the shell.
///
/// If the string contains no characters that need quoting it is returned as-is.
/// Otherwise it is wrapped in single quotes with any embedded single quotes
/// escaped using the `'\''` idiom.
fn shell_quote(s: &str) -> String {
    if !s.contains(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '\'' | '"' | '\\' | '(' | ')' | '&' | ';' | '|' | '<' | '>' | '`' | '$' | '!' | '#'
            )
    }) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Install Git filter and diff configuration via `git config --local`.
///
/// # Errors
///
/// Returns an error if any `git config` command fails.
pub fn install_git_filters(repo_root: &Path, bin: &str) -> Result<()> {
    let quoted = shell_quote(bin);
    let pairs = [
        (
            "filter.git-sshripped.process".to_string(),
            format!("{quoted} filter-process"),
        ),
        (
            "filter.git-sshripped.clean".to_string(),
            format!("{quoted} clean --path %f"),
        ),
        (
            "filter.git-sshripped.smudge".to_string(),
            format!("{quoted} smudge --path %f"),
        ),
        (
            "filter.git-sshripped.required".to_string(),
            "true".to_string(),
        ),
        (
            "diff.git-sshripped.textconv".to_string(),
            format!("{quoted} diff --path %f"),
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

// ---------------------------------------------------------------------------
// Agent-wrapped key file helpers
//
// Agent-wrap files are stored inside the git common directory
// (`git rev-parse --git-common-dir`) so they are:
//   - local to the machine (never committed)
//   - shared across linked worktrees
// ---------------------------------------------------------------------------

/// Directory for agent-wrapped key files inside the git common directory.
#[must_use]
pub fn agent_wrap_dir(common_dir: &Path) -> PathBuf {
    common_dir.join("git-sshripped-agent-wrap")
}

/// Path to an agent-wrapped key file for a given fingerprint.
#[must_use]
pub fn agent_wrap_file(common_dir: &Path, fingerprint: &str) -> PathBuf {
    agent_wrap_dir(common_dir).join(format!("{fingerprint}.toml"))
}

/// Read an agent-wrapped key file, returning `None` if the file does not exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be read or parsed.
pub fn read_agent_wrap(
    common_dir: &Path,
    fingerprint: &str,
) -> Result<Option<git_sshripped_ssh_agent_models::AgentWrappedKey>> {
    let file = agent_wrap_file(common_dir, fingerprint);
    if !file.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&file)
        .with_context(|| format!("failed to read agent-wrap file {}", file.display()))?;
    let key: git_sshripped_ssh_agent_models::AgentWrappedKey =
        toml::from_str(&text).context("failed to parse agent-wrap file")?;
    Ok(Some(key))
}

/// Write an agent-wrapped key file.
///
/// # Errors
///
/// Returns an error if the directory cannot be created, the file cannot be
/// serialized, or the file cannot be written.
pub fn write_agent_wrap(
    common_dir: &Path,
    wrapped: &git_sshripped_ssh_agent_models::AgentWrappedKey,
) -> Result<()> {
    let dir = agent_wrap_dir(common_dir);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create agent-wrap directory {}", dir.display()))?;
    let file = agent_wrap_file(common_dir, &wrapped.fingerprint);
    let text = toml::to_string_pretty(wrapped).context("failed to serialize agent-wrap key")?;
    fs::write(&file, text)
        .with_context(|| format!("failed to write agent-wrap file {}", file.display()))?;
    Ok(())
}

/// List all agent-wrap `.toml` files in the agent-wrap directory.
///
/// # Errors
///
/// Returns an error if the directory cannot be read.
pub fn list_agent_wrap_files(common_dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = agent_wrap_dir(common_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        {
            files.push(path);
        }
    }
    Ok(files)
}

/// Parse an agent-wrapped key from a TOML string.
///
/// # Errors
///
/// Returns an error if the string is not valid TOML or does not match the
/// expected schema.
pub fn parse_agent_wrap(text: &str) -> Result<git_sshripped_ssh_agent_models::AgentWrappedKey> {
    toml::from_str(text).context("failed to parse agent-wrap TOML")
}
