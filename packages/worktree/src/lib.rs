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
use git_ssh_crypt_worktree_models::UnlockSession;

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

pub fn git_common_dir(cwd: &Path) -> Result<PathBuf> {
    git_rev_parse(cwd, "--git-common-dir")
}

pub fn git_toplevel(cwd: &Path) -> Result<PathBuf> {
    git_rev_parse(cwd, "--show-toplevel")
}

#[must_use]
pub fn session_file(common_dir: &Path) -> PathBuf {
    common_dir
        .join("git-ssh-crypt")
        .join("session")
        .join("unlock.json")
}

pub fn write_unlock_session(common_dir: &Path, key: &[u8], key_source: &str) -> Result<()> {
    let file = session_file(common_dir);
    let parent = file
        .parent()
        .context("session path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create session dir {}", parent.display()))?;

    let session = UnlockSession {
        key_b64: base64::engine::general_purpose::STANDARD_NO_PAD.encode(key),
        key_source: key_source.to_string(),
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

pub fn clear_unlock_session(common_dir: &Path) -> Result<()> {
    let file = session_file(common_dir);
    if file.exists() {
        fs::remove_file(&file)
            .with_context(|| format!("failed to remove session file {}", file.display()))?;
    }
    Ok(())
}

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
