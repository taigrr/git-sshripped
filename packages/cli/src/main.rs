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
use git_ssh_crypt_recipient::{
    add_recipient_from_public_key, add_recipients_from_github_keys, list_recipients,
    wrap_repo_key_for_all_recipients, wrap_repo_key_for_recipient, wrapped_store_dir,
};
use git_ssh_crypt_recipient_models::RecipientSource;
use git_ssh_crypt_repository::{
    install_git_filters, install_gitattributes, read_manifest, write_manifest,
};
use git_ssh_crypt_repository_models::RepositoryManifest;
use git_ssh_crypt_ssh_identity::{
    default_private_key_candidates, default_public_key_candidates, detect_identity,
    unwrap_repo_key_from_wrapped_files,
};
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
        #[arg(long = "recipient-key")]
        recipient_keys: Vec<String>,
        #[arg(long = "github-keys-url")]
        github_keys_urls: Vec<String>,
    },
    Unlock {
        #[arg(long)]
        key_hex: Option<String>,
        #[arg(long = "identity")]
        identities: Vec<String>,
    },
    Lock,
    Status,
    Rewrap,
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
            recipient_keys,
            github_keys_urls,
        } => cmd_init(patterns, algorithm, recipient_keys, github_keys_urls),
        Command::Unlock {
            key_hex,
            identities,
        } => cmd_unlock(key_hex, identities),
        Command::Lock => cmd_lock(),
        Command::Status => cmd_status(),
        Command::Rewrap => cmd_rewrap(),
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

fn wrapped_key_files(repo_root: &std::path::Path) -> Result<Vec<PathBuf>> {
    let dir = wrapped_store_dir(repo_root);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(&dir)
        .with_context(|| format!("failed to read wrapped dir {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed reading entry in {}", dir.display()))?;
        if entry
            .file_type()
            .with_context(|| format!("failed to read file type for {}", entry.path().display()))?
            .is_file()
        {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

fn cmd_init(
    patterns: Vec<String>,
    algorithm: CliAlgorithm,
    recipient_keys: Vec<String>,
    github_keys_urls: Vec<String>,
) -> Result<()> {
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

    let mut added_recipients = Vec::new();

    for key in recipient_keys {
        let key_line = if key.ends_with(".pub") {
            fs::read_to_string(&key)
                .with_context(|| format!("failed to read recipient key file {key}"))?
        } else {
            key
        };
        let recipient =
            add_recipient_from_public_key(&repo_root, &key_line, RecipientSource::LocalFile)?;
        added_recipients.push(recipient);
    }

    for url in github_keys_urls {
        let recipients = add_recipients_from_github_keys(&repo_root, &url)?;
        added_recipients.extend(recipients);
    }

    for path in default_public_key_candidates() {
        if !path.exists() {
            continue;
        }
        let key_line = fs::read_to_string(&path)
            .with_context(|| format!("failed to read default public key {}", path.display()))?;
        let recipient =
            add_recipient_from_public_key(&repo_root, &key_line, RecipientSource::LocalFile)?;
        added_recipients.push(recipient);
    }

    let recipients = list_recipients(&repo_root)?;
    if recipients.is_empty() {
        anyhow::bail!(
            "no recipients available; provide --recipient-key, --github-keys-url, or ensure ~/.ssh/id_ed25519.pub exists"
        );
    }

    let mut key = [0_u8; 32];
    rand::rng().fill_bytes(&mut key);
    let wrapped = wrap_repo_key_for_all_recipients(&repo_root, &key)?;

    println!("initialized git-ssh-crypt in {}", repo_root.display());
    println!("algorithm: {:?}", manifest.encryption_algorithm);
    println!("patterns: {}", manifest.protected_patterns.join(", "));
    println!("recipients: {}", recipients.len());
    println!("wrapped keys written: {}", wrapped.len());
    if added_recipients.is_empty() {
        println!("note: reused existing recipient definitions");
    }
    Ok(())
}

fn cmd_unlock(key_hex: Option<String>, identities: Vec<String>) -> Result<()> {
    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;

    let (key, key_source) = if let Some(hex_value) = key_hex {
        (
            hex::decode(hex_value.trim()).context("--key-hex must be valid hex")?,
            "key-hex".to_string(),
        )
    } else {
        let identity_files = if identities.is_empty() {
            default_private_key_candidates()
        } else {
            identities.into_iter().map(PathBuf::from).collect()
        };

        let wrapped_files = wrapped_key_files(&repo_root)?;
        if wrapped_files.is_empty() {
            anyhow::bail!(
                "no wrapped key files found in {}; run init or rewrap first",
                wrapped_store_dir(&repo_root).display()
            );
        }

        let Some((unwrapped, descriptor)) =
            unwrap_repo_key_from_wrapped_files(&wrapped_files, &identity_files)?
        else {
            anyhow::bail!("could not decrypt any wrapped key with provided/default identities");
        };
        (unwrapped, descriptor.label)
    };

    write_unlock_session(&common_dir, &key, &key_source)?;
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
    let recipients = list_recipients(&repo_root)?;
    let wrapped_files = wrapped_key_files(&repo_root)?;

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
    println!("recipients: {}", recipients.len());
    println!("wrapped keys: {}", wrapped_files.len());
    if let Some(session) = session {
        println!("unlock source: {}", session.key_source);
    }
    println!(
        "protected patterns: {}",
        manifest.protected_patterns.join(", ")
    );
    Ok(())
}

fn cmd_add_user(key: Option<String>, github_keys_url: Option<String>) -> Result<()> {
    let repo_root = current_repo_root()?;
    let session_key = repo_key_from_session()?;

    let mut new_recipients = Vec::new();

    if let Some(url) = github_keys_url {
        let added = add_recipients_from_github_keys(&repo_root, &url)?;
        new_recipients.extend(added);
        println!("added {} recipients from {}", new_recipients.len(), url);
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
        new_recipients.push(recipient);
    }

    if new_recipients.is_empty() {
        anyhow::bail!("provide --key <pubkey|path.pub> or --github-keys-url <url>");
    }

    if let Some(key) = session_key {
        let mut wrapped_count = 0;
        for recipient in &new_recipients {
            wrap_repo_key_for_recipient(&repo_root, recipient, &key)?;
            wrapped_count += 1;
        }
        println!("wrapped repo key for {} new recipients", wrapped_count);
    } else {
        println!(
            "warning: repository is locked; run `git-ssh-crypt unlock` then `git-ssh-crypt rewrap` to grant access"
        );
    }

    Ok(())
}

fn cmd_rewrap() -> Result<()> {
    let repo_root = current_repo_root()?;
    let Some(key) = repo_key_from_session()? else {
        anyhow::bail!("repository is locked; run `git-ssh-crypt unlock` first");
    };
    let wrapped = wrap_repo_key_for_all_recipients(&repo_root, &key)?;
    println!("rewrapped repository key for {} recipients", wrapped.len());
    Ok(())
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
