#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use base64::Engine;
use git_sshripped_worktree_models::UnlockSession;

fn git_rev_parse(cwd: &Path, arg: &str) -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", arg])
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to execute git rev-parse {arg}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "git rev-parse {arg} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let text = String::from_utf8(output.stdout).context("git rev-parse output was not utf8")?;
    Ok(PathBuf::from(text.trim()))
}

/// Resolve the Git common directory for the current working directory.
///
/// # Errors
///
/// Returns an error if `git rev-parse --git-common-dir` fails.
pub fn git_common_dir(cwd: &Path) -> Result<PathBuf> {
    git_rev_parse(cwd, "--git-common-dir")
}

/// Resolve the Git directory for the current working directory.
///
/// For the main worktree this returns `.git`; for a linked worktree it
/// returns the worktree-specific Git directory (e.g.
/// `<main>/.git/worktrees/<name>`).
///
/// # Errors
///
/// Returns an error if `git rev-parse --git-dir` fails.
pub fn git_dir(cwd: &Path) -> Result<PathBuf> {
    git_rev_parse(cwd, "--git-dir")
}

/// Resolve the working-tree root for the current working directory.
///
/// # Errors
///
/// Returns an error if `git rev-parse --show-toplevel` fails.
pub fn git_toplevel(cwd: &Path) -> Result<PathBuf> {
    git_rev_parse(cwd, "--show-toplevel")
}

/// Returns `true` when the current working directory is inside a linked
/// (non-main) Git worktree.
///
/// Detection works by comparing the resolved `--git-dir` (worktree-specific)
/// against `--git-common-dir` (shared).  When they differ the worktree is a
/// linked one.
///
/// # Errors
///
/// Returns an error if the underlying `git rev-parse` calls fail.
pub fn is_linked_worktree(cwd: &Path) -> Result<bool> {
    let git_dir_raw = git_dir(cwd)?;
    let common_dir_raw = git_common_dir(cwd)?;

    // Both flags may return relative paths – resolve them to absolute.
    let abs_git = if git_dir_raw.is_absolute() {
        git_dir_raw
    } else {
        cwd.join(git_dir_raw)
    };
    let abs_common = if common_dir_raw.is_absolute() {
        common_dir_raw
    } else {
        cwd.join(common_dir_raw)
    };

    // Canonicalize to collapse symlinks and `..` components.
    let canon_git = fs::canonicalize(&abs_git).unwrap_or(abs_git);
    let canon_common = fs::canonicalize(&abs_common).unwrap_or(abs_common);

    Ok(canon_git != canon_common)
}

#[must_use]
pub fn session_file(common_dir: &Path) -> PathBuf {
    common_dir
        .join("git-sshripped")
        .join("session")
        .join("unlock.json")
}

/// Persist the unlock session to disk.
///
/// # Errors
///
/// Returns an error if the session directory cannot be created, the session
/// cannot be serialized, or the file cannot be written.
pub fn write_unlock_session(
    common_dir: &Path,
    key: &[u8],
    key_source: &str,
    repo_key_id: Option<String>,
) -> Result<()> {
    let file = session_file(common_dir);
    let parent = file
        .parent()
        .context("session path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create session dir {}", parent.display()))?;

    let session = UnlockSession {
        key_b64: base64::engine::general_purpose::STANDARD_NO_PAD.encode(key),
        key_source: key_source.to_string(),
        repo_key_id,
    };
    let text =
        serde_json::to_string_pretty(&session).context("failed to serialize unlock session")?;
    fs::write(&file, text)
        .with_context(|| format!("failed to write session file {}", file.display()))?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&file)
            .with_context(|| format!("failed to read session file metadata {}", file.display()))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&file, perms)
            .with_context(|| format!("failed to set secure permissions on {}", file.display()))?;
    }

    Ok(())
}

/// Remove the unlock session file, locking the repository.
///
/// # Errors
///
/// Returns an error if the session file exists but cannot be removed.
pub fn clear_unlock_session(common_dir: &Path) -> Result<()> {
    let file = session_file(common_dir);
    if file.exists() {
        fs::remove_file(&file)
            .with_context(|| format!("failed to remove session file {}", file.display()))?;
    }
    Ok(())
}

/// Read the current unlock session, if one exists.
///
/// # Errors
///
/// Returns an error if the session file exists but cannot be read or parsed.
pub fn read_unlock_session(common_dir: &Path) -> Result<Option<UnlockSession>> {
    let file = session_file(common_dir);
    if !file.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&file)
        .with_context(|| format!("failed to read session file {}", file.display()))?;
    let session = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse session file {}", file.display()))?;
    Ok(Some(session))
}
