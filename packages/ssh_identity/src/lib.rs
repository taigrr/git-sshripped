#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::path::PathBuf;

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
