#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use git_ssh_crypt_cli_models::InitOptions;
use git_ssh_crypt_encryption_models::EncryptionAlgorithm;
use git_ssh_crypt_filter::{clean, diff, smudge};
use git_ssh_crypt_recipient::{add_recipient_from_public_key, add_recipients_from_github_keys};
use git_ssh_crypt_recipient_models::RecipientSource;
use git_ssh_crypt_repository::{
    install_git_filters, install_gitattributes, metadata_dir, read_manifest, write_manifest,
};
use git_ssh_crypt_repository_models::RepositoryManifest;
use git_ssh_crypt_ssh_identity::detect_identity;
use git_ssh_crypt_worktree::{
    clear_unlock_session, git_common_dir, git_toplevel, read_unlock_session, write_unlock_session,
};
use rand::RngCore;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliAlgorithm {
    AesSiv,
}

impl From<CliAlgorithm> for EncryptionAlgorithm {
    fn from(value: CliAlgorithm) -> Self {
        match value {
            CliAlgorithm::AesSiv => Self::AesSivV1,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "git-ssh-crypt")]
#[command(about = "Git-transparent encryption using SSH-oriented workflows")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        #[arg(long = "pattern")]
        patterns: Vec<String>,
        #[arg(long, value_enum, default_value_t = CliAlgorithm::AesSiv)]
        algorithm: CliAlgorithm,
    },
    Unlock {
        #[arg(long)]
        key_hex: Option<String>,
    },
    Lock,
    Status,
    AddUser {
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        github_keys_url: Option<String>,
    },
    Clean {
        #[arg(long)]
        path: String,
    },
    Smudge {
        #[arg(long)]
        path: String,
    },
    Diff {
        #[arg(long)]
        path: String,
    },
    FilterProcess,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init {
            patterns,
            algorithm,
        } => cmd_init(patterns, algorithm),
        Command::Unlock { key_hex } => cmd_unlock(key_hex),
        Command::Lock => cmd_lock(),
        Command::Status => cmd_status(),
        Command::AddUser {
            key,
            github_keys_url,
        } => cmd_add_user(key, github_keys_url),
        Command::Clean { path } => cmd_clean(&path),
        Command::Smudge { path } => cmd_smudge(&path),
        Command::Diff { path } => cmd_diff(&path),
        Command::FilterProcess => cmd_filter_process(),
    }
}

fn current_repo_root() -> Result<PathBuf> {
    git_toplevel(&std::env::current_dir().context("failed to read current dir")?)
}

fn current_common_dir() -> Result<PathBuf> {
    git_common_dir(&std::env::current_dir().context("failed to read current dir")?)
}

fn local_repo_key_file(repo_root: &std::path::Path) -> PathBuf {
    metadata_dir(repo_root).join("repo-key.hex")
}

fn read_local_repo_key(repo_root: &std::path::Path) -> Result<Vec<u8>> {
    let file = local_repo_key_file(repo_root);
    let key_hex = fs::read_to_string(&file)
        .with_context(|| format!("failed to read local key file {}", file.display()))?;
    let bytes = hex::decode(key_hex.trim()).context("invalid local repo key hex")?;
    Ok(bytes)
}

fn cmd_init(patterns: Vec<String>, algorithm: CliAlgorithm) -> Result<()> {
    let repo_root = current_repo_root()?;

    let init = InitOptions {
        protected_patterns: if patterns.is_empty() {
            vec!["secrets/**".to_string()]
        } else {
            patterns
        },
        algorithm: algorithm.into(),
    };

    let manifest = RepositoryManifest {
        manifest_version: 1,
        encryption_algorithm: init.algorithm,
        protected_patterns: init.protected_patterns,
    };

    write_manifest(&repo_root, &manifest)?;
    install_gitattributes(&repo_root, &manifest.protected_patterns)?;
    install_git_filters(&repo_root)?;

    // Temporary bootstrap key storage for local development. Recipient wrapping
    // support is next and will replace this tracked-local fallback.
    let mut key = [0_u8; 32];
    rand::rng().fill_bytes(&mut key);
    let key_file = local_repo_key_file(&repo_root);
    fs::write(&key_file, hex::encode(key))
        .with_context(|| format!("failed to write local key file {}", key_file.display()))?;

    println!("initialized git-ssh-crypt in {}", repo_root.display());
    println!("algorithm: {:?}", manifest.encryption_algorithm);
    println!("patterns: {}", manifest.protected_patterns.join(", "));
    Ok(())
}

fn cmd_unlock(key_hex: Option<String>) -> Result<()> {
    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;

    let key = if let Some(hex_value) = key_hex {
        hex::decode(hex_value.trim()).context("--key-hex must be valid hex")?
    } else {
        read_local_repo_key(&repo_root)
            .context("no key provided and local bootstrap key missing; provide --key-hex")?
    };

    write_unlock_session(&common_dir, &key, "local")?;
    println!(
        "unlocked repository across worktrees via {}",
        common_dir.display()
    );
    Ok(())
}

fn cmd_lock() -> Result<()> {
    let common_dir = current_common_dir()?;
    clear_unlock_session(&common_dir)?;
    println!("locked repository across worktrees");
    Ok(())
}

fn cmd_status() -> Result<()> {
    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;
    let manifest = read_manifest(&repo_root)?;
    let identity = detect_identity()?;
    let session = read_unlock_session(&common_dir)?;

    println!("repo: {}", repo_root.display());
    println!(
        "state: {}",
        if session.is_some() {
            "UNLOCKED"
        } else {
            "LOCKED"
        }
    );
    println!("scope: all worktrees via {}", common_dir.display());
    println!("algorithm: {:?}", manifest.encryption_algorithm);
    println!("identity: {} ({:?})", identity.label, identity.source);
    println!(
        "protected patterns: {}",
        manifest.protected_patterns.join(", ")
    );
    Ok(())
}

fn cmd_add_user(key: Option<String>, github_keys_url: Option<String>) -> Result<()> {
    let repo_root = current_repo_root()?;

    if let Some(url) = github_keys_url {
        let added = add_recipients_from_github_keys(&repo_root, &url)?;
        println!("added {} recipients from {}", added.len(), url);
        return Ok(());
    }

    if let Some(key_input) = key {
        let key_line = if key_input.ends_with(".pub") {
            fs::read_to_string(&key_input)
                .with_context(|| format!("failed to read key file {key_input}"))?
        } else {
            key_input
        };

        let recipient =
            add_recipient_from_public_key(&repo_root, &key_line, RecipientSource::LocalFile)?;
        println!(
            "added recipient {} ({})",
            recipient.fingerprint, recipient.key_type
        );
        return Ok(());
    }

    anyhow::bail!("provide --key <pubkey|path.pub> or --github-keys-url <url>")
}

fn repo_key_from_session() -> Result<Option<Vec<u8>>> {
    let common_dir = current_common_dir()?;
    let maybe_session = read_unlock_session(&common_dir)?;
    let Some(session) = maybe_session else {
        return Ok(None);
    };
    let key = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(session.key_b64)
        .context("invalid session key encoding")?;
    Ok(Some(key))
}

fn read_stdin_all() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("failed to read stdin")?;
    Ok(input)
}

fn write_stdout_all(bytes: &[u8]) -> Result<()> {
    std::io::stdout()
        .write_all(bytes)
        .context("failed to write stdout")?;
    Ok(())
}

fn cmd_clean(path: &str) -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;
    let key = repo_key_from_session()?;
    let input = read_stdin_all()?;
    let output = clean(&manifest, key.as_deref(), path, &input)?;
    write_stdout_all(&output)
}

fn cmd_smudge(path: &str) -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;
    let key = repo_key_from_session()?;
    let input = read_stdin_all()?;
    let output = smudge(&manifest, key.as_deref(), path, &input)?;
    write_stdout_all(&output)
}

fn cmd_diff(path: &str) -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;
    let key = repo_key_from_session()?;
    let input = read_stdin_all()?;
    let output = diff(&manifest, key.as_deref(), path, &input)?;
    write_stdout_all(&output)
}

fn cmd_filter_process() -> Result<()> {
    anyhow::bail!(
        "filter-process protocol is not yet implemented; use clean/smudge commands in filter config for now"
    )
}
