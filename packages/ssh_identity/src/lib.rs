#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::path::PathBuf;

use anyhow::Result;
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
