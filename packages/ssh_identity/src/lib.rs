#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::path::PathBuf;
use std::process::Command;

use age::Decryptor;
use age::Identity;
use age::ssh::Identity as SshIdentity;
use anyhow::{Context, Result};
use git_ssh_crypt_ssh_identity_models::{IdentityDescriptor, IdentitySource};

#[must_use]
pub fn default_public_key_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".ssh").join("id_ed25519.pub"));
        candidates.push(home.join(".ssh").join("id_rsa.pub"));
    }
    candidates
}

#[must_use]
pub fn default_private_key_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".ssh").join("id_ed25519"));
        candidates.push(home.join(".ssh").join("id_rsa"));
    }
    candidates
}

pub fn agent_public_keys() -> Result<Vec<String>> {
    if std::env::var_os("SSH_AUTH_SOCK").is_none() {
        return Ok(Vec::new());
    }

    let output = Command::new("ssh-add")
        .arg("-L")
        .output()
        .context("failed to run ssh-add -L")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let text = String::from_utf8(output.stdout).context("ssh-add output was not utf8")?;
    let keys = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect();
    Ok(keys)
}

pub fn private_keys_matching_agent() -> Result<Vec<PathBuf>> {
    let agent_keys = agent_public_keys()?;
    if agent_keys.is_empty() {
        return Ok(Vec::new());
    }

    let mut matches = Vec::new();
    for public_candidate in default_public_key_candidates() {
        if !public_candidate.exists() {
            continue;
        }

        let public_line = std::fs::read_to_string(&public_candidate).with_context(|| {
            format!(
                "failed reading public key candidate {}",
                public_candidate.display()
            )
        })?;
        let public_line = public_line.trim();

        if !agent_keys.iter().any(|line| line.trim() == public_line) {
            continue;
        }

        if let Some(stem) = public_candidate.file_name().and_then(|s| s.to_str())
            && let Some(private_name) = stem.strip_suffix(".pub")
        {
            let private_path = public_candidate
                .parent()
                .map_or_else(|| PathBuf::from(private_name), |p| p.join(private_name));
            if private_path.exists() {
                matches.push(private_path);
            }
        }
    }

    Ok(matches)
}

pub fn detect_identity() -> Result<IdentityDescriptor> {
    if std::env::var_os("SSH_AUTH_SOCK").is_some() {
        return Ok(IdentityDescriptor {
            source: IdentitySource::SshAgent,
            label: "SSH agent".to_string(),
        });
    }

    for candidate in default_public_key_candidates() {
        if candidate.exists() {
            return Ok(IdentityDescriptor {
                source: IdentitySource::IdentityFile,
                label: candidate.display().to_string(),
            });
        }
    }

    Ok(IdentityDescriptor {
        source: IdentitySource::IdentityFile,
        label: "unresolved".to_string(),
    })
}

pub fn unwrap_repo_key_from_wrapped_files(
    wrapped_files: &[PathBuf],
    identity_files: &[PathBuf],
) -> Result<Option<(Vec<u8>, IdentityDescriptor)>> {
    let mut identities: Vec<(SshIdentity, PathBuf)> = Vec::new();

    for identity_file in identity_files {
        if !identity_file.exists() {
            continue;
        }
        let content = std::fs::read(identity_file)
            .with_context(|| format!("failed reading identity file {}", identity_file.display()))?;
        let filename = Some(identity_file.display().to_string());
        let identity = SshIdentity::from_buffer(std::io::Cursor::new(&content), filename).with_context(|| {
            format!(
                "failed parsing identity file {}; encrypted/private-key prompts are not yet supported",
                identity_file.display()
            )
        })?;
        identities.push((identity, identity_file.clone()));
    }

    for wrapped in wrapped_files {
        let wrapped_bytes = std::fs::read(wrapped)
            .with_context(|| format!("failed reading wrapped key {}", wrapped.display()))?;

        for (identity, path) in &identities {
            let decryptor = Decryptor::new(&wrapped_bytes[..])
                .with_context(|| format!("invalid wrapped key format {}", wrapped.display()))?;
            let mut reader = match decryptor.decrypt(std::iter::once(identity as &dyn Identity)) {
                Ok(reader) => reader,
                Err(_) => continue,
            };

            let mut key = Vec::new();
            std::io::Read::read_to_end(&mut reader, &mut key).with_context(|| {
                format!("failed reading decrypted key from {}", wrapped.display())
            })?;
            return Ok(Some((
                key,
                IdentityDescriptor {
                    source: IdentitySource::IdentityFile,
                    label: path.display().to_string(),
                },
            )));
        }
    }

    Ok(None)
}
