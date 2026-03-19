#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use git_ssh_crypt_cli_models::InitOptions;
use git_ssh_crypt_encryption_models::{ENCRYPTED_MAGIC, EncryptionAlgorithm};
use git_ssh_crypt_filter::{clean, diff, is_protected_path, smudge};
use git_ssh_crypt_recipient::{
    add_recipient_from_public_key, add_recipients_from_github_keys,
    add_recipients_from_github_source, add_recipients_from_github_username,
    fetch_github_team_members, list_recipients, remove_recipient_by_fingerprint,
    remove_recipients_by_fingerprints, wrap_repo_key_for_all_recipients,
    wrap_repo_key_for_recipient, wrapped_store_dir,
};
use git_ssh_crypt_recipient_models::RecipientSource;
use git_ssh_crypt_repository::{
    install_git_filters, install_gitattributes, read_github_sources, read_manifest,
    write_github_sources, write_manifest,
};
use git_ssh_crypt_repository_models::{
    GithubSourceRegistry, GithubTeamSource, GithubUserSource, RepositoryManifest,
};
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
        #[arg(long)]
        strict: bool,
    },
    Unlock {
        #[arg(long)]
        key_hex: Option<String>,
        #[arg(long = "identity")]
        identities: Vec<String>,
        #[arg(long = "github-user")]
        github_user: Option<String>,
    },
    Lock,
    Status {
        #[arg(long)]
        json: bool,
    },
    Doctor {
        #[arg(long)]
        json: bool,
    },
    Rewrap,
    RotateKey {
        #[arg(long = "auto-reencrypt")]
        auto_reencrypt: bool,
    },
    Reencrypt,
    AddUser {
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        github_keys_url: Option<String>,
        #[arg(long)]
        github_user: Option<String>,
    },
    ListUsers {
        #[arg(long)]
        verbose: bool,
    },
    AddGithubUser {
        #[arg(long)]
        username: String,
        #[arg(long)]
        auto_wrap: bool,
    },
    ListGithubUsers {
        #[arg(long)]
        verbose: bool,
    },
    RemoveGithubUser {
        #[arg(long)]
        username: String,
        #[arg(long)]
        force: bool,
    },
    RefreshGithubKeys {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    AddGithubTeam {
        #[arg(long)]
        org: String,
        #[arg(long)]
        team: String,
        #[arg(long)]
        auto_wrap: bool,
    },
    ListGithubTeams,
    RemoveGithubTeam {
        #[arg(long)]
        org: String,
        #[arg(long)]
        team: String,
    },
    RefreshGithubTeams {
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    AccessAudit {
        #[arg(long = "identity")]
        identities: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    RemoveUser {
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        force: bool,
    },
    Install,
    MigrateFromGitCrypt {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        reencrypt: bool,
        #[arg(long)]
        verify: bool,
        #[arg(long)]
        json: bool,
    },
    ExportRepoKey {
        #[arg(long)]
        out: String,
    },
    ImportRepoKey {
        #[arg(long)]
        input: String,
    },
    Verify {
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        json: bool,
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
            strict,
        } => cmd_init(
            patterns,
            algorithm,
            recipient_keys,
            github_keys_urls,
            strict,
        ),
        Command::Unlock {
            key_hex,
            identities,
            github_user,
        } => cmd_unlock(key_hex, identities, github_user),
        Command::Lock => cmd_lock(),
        Command::Status { json } => cmd_status(json),
        Command::Doctor { json } => cmd_doctor(json),
        Command::Rewrap => cmd_rewrap(),
        Command::RotateKey { auto_reencrypt } => cmd_rotate_key(auto_reencrypt),
        Command::Reencrypt => cmd_reencrypt(),
        Command::AddUser {
            key,
            github_keys_url,
            github_user,
        } => cmd_add_user(key, github_keys_url, github_user),
        Command::ListUsers { verbose } => cmd_list_users(verbose),
        Command::AddGithubUser {
            username,
            auto_wrap,
        } => cmd_add_github_user(&username, auto_wrap),
        Command::ListGithubUsers { verbose } => cmd_list_github_users(verbose),
        Command::RemoveGithubUser { username, force } => cmd_remove_github_user(&username, force),
        Command::RefreshGithubKeys {
            username,
            dry_run,
            json,
        } => cmd_refresh_github_keys(username, dry_run, json),
        Command::AddGithubTeam {
            org,
            team,
            auto_wrap,
        } => cmd_add_github_team(&org, &team, auto_wrap),
        Command::ListGithubTeams => cmd_list_github_teams(),
        Command::RemoveGithubTeam { org, team } => cmd_remove_github_team(&org, &team),
        Command::RefreshGithubTeams {
            org,
            team,
            dry_run,
            json,
        } => cmd_refresh_github_teams(org, team, dry_run, json),
        Command::AccessAudit { identities, json } => cmd_access_audit(identities, json),
        Command::RemoveUser { fingerprint, force } => cmd_remove_user(&fingerprint, force),
        Command::Install => cmd_install(),
        Command::MigrateFromGitCrypt {
            dry_run,
            reencrypt,
            verify,
            json,
        } => cmd_migrate_from_git_crypt(dry_run, reencrypt, verify, json),
        Command::ExportRepoKey { out } => cmd_export_repo_key(&out),
        Command::ImportRepoKey { input } => cmd_import_repo_key(&input),
        Command::Verify { strict, json } => cmd_verify(strict, json),
        Command::Clean { path } => cmd_clean(&path),
        Command::Smudge { path } => cmd_smudge(&path),
        Command::Diff { path } => cmd_diff(&path),
        Command::FilterProcess => cmd_filter_process(),
    }
}

fn current_repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("failed to read current dir")?;
    resolve_repo_root_for_command(&cwd)
}

fn current_common_dir() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("failed to read current dir")?;
    resolve_common_dir_for_command(&cwd)
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

fn snapshot_wrapped_files(repo_root: &std::path::Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let dir = wrapped_store_dir(repo_root);
    let mut snapshot = BTreeMap::new();
    if !dir.exists() {
        return Ok(snapshot);
    }

    for file in wrapped_key_files(repo_root)? {
        let Some(name) = file.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let bytes = fs::read(&file)
            .with_context(|| format!("failed to read wrapped file {}", file.display()))?;
        snapshot.insert(name.to_string(), bytes);
    }

    Ok(snapshot)
}

fn restore_wrapped_files(
    repo_root: &std::path::Path,
    snapshot: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let dir = wrapped_store_dir(repo_root);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create wrapped directory {}", dir.display()))?;

    for file in wrapped_key_files(repo_root)? {
        fs::remove_file(&file)
            .with_context(|| format!("failed to remove wrapped file {}", file.display()))?;
    }

    for (name, bytes) in snapshot {
        let path = dir.join(name);
        fs::write(&path, bytes)
            .with_context(|| format!("failed to restore wrapped file {}", path.display()))?;
    }

    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn fingerprint_in_other_sources(
    registry: &GithubSourceRegistry,
    fingerprint: &str,
    skip_user: Option<&str>,
    skip_team: Option<(&str, &str)>,
) -> bool {
    let in_users = registry.users.iter().any(|source| {
        if skip_user.is_some_and(|u| u == source.username) {
            return false;
        }
        source.fingerprints.iter().any(|f| f == fingerprint)
    });
    if in_users {
        return true;
    }
    registry.teams.iter().any(|source| {
        if skip_team.is_some_and(|(org, team)| org == source.org && team == source.team) {
            return false;
        }
        source.fingerprints.iter().any(|f| f == fingerprint)
    })
}

fn cmd_init(
    patterns: Vec<String>,
    algorithm: CliAlgorithm,
    recipient_keys: Vec<String>,
    github_keys_urls: Vec<String>,
    strict: bool,
) -> Result<()> {
    let repo_root = current_repo_root()?;

    let init = InitOptions {
        protected_patterns: if patterns.is_empty() {
            vec!["secrets/**".to_string()]
        } else {
            patterns
        },
        algorithm: algorithm.into(),
        strict_mode: strict,
    };

    let manifest = RepositoryManifest {
        manifest_version: 1,
        encryption_algorithm: init.algorithm,
        protected_patterns: init.protected_patterns,
        strict_mode: init.strict_mode,
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
        let recipients = add_recipients_from_github_source(&repo_root, &url, None)?;
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
    println!("strict_mode: {}", manifest.strict_mode);
    println!("patterns: {}", manifest.protected_patterns.join(", "));
    println!("recipients: {}", recipients.len());
    println!("wrapped keys written: {}", wrapped.len());
    if added_recipients.is_empty() {
        println!("note: reused existing recipient definitions");
    }
    Ok(())
}

fn cmd_unlock(
    key_hex: Option<String>,
    identities: Vec<String>,
    github_user: Option<String>,
) -> Result<()> {
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

        let mut wrapped_files = wrapped_key_files(&repo_root)?;
        if let Some(user) = github_user {
            let recipients = list_recipients(&repo_root)?;
            let allowed: std::collections::HashSet<String> = recipients
                .iter()
                .filter_map(|recipient| match &recipient.source {
                    RecipientSource::GithubKeys { username, .. }
                        if username.as_deref() == Some(&user) =>
                    {
                        Some(format!("{}.age", recipient.fingerprint))
                    }
                    _ => None,
                })
                .collect();
            wrapped_files.retain(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| allowed.contains(name))
            });
        }
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

fn cmd_status(json: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;
    let manifest = read_manifest(&repo_root)?;
    let identity = detect_identity()?;
    let session = read_unlock_session(&common_dir)?;
    let recipients = list_recipients(&repo_root)?;
    let wrapped_files = wrapped_key_files(&repo_root)?;

    if json {
        let payload = serde_json::json!({
            "repo": repo_root.display().to_string(),
            "common_dir": common_dir.display().to_string(),
            "state": if session.is_some() { "UNLOCKED" } else { "LOCKED" },
            "algorithm": format!("{:?}", manifest.encryption_algorithm),
            "strict_mode": manifest.strict_mode,
            "identity": {"label": identity.label, "source": format!("{:?}", identity.source)},
            "recipients": recipients.len(),
            "wrapped_keys": wrapped_files.len(),
            "unlock_source": session.as_ref().map(|s| s.key_source.clone()),
            "protected_patterns": manifest.protected_patterns,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

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
    println!("strict_mode: {}", manifest.strict_mode);
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

fn cmd_add_user(
    key: Option<String>,
    github_keys_url: Option<String>,
    github_user: Option<String>,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let session_key = repo_key_from_session()?;

    let mut new_recipients = Vec::new();

    if let Some(url) = github_keys_url {
        let added = add_recipients_from_github_keys(&repo_root, &url)?;
        new_recipients.extend(added);
        println!("added {} recipients from {}", new_recipients.len(), url);
    }

    if let Some(username) = github_user {
        let added = add_recipients_from_github_username(&repo_root, &username)?;
        println!(
            "added {} recipients from github user {}",
            added.len(),
            username
        );
        new_recipients.extend(added);
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
        anyhow::bail!(
            "provide --key <pubkey|path.pub>, --github-keys-url <url>, or --github-user <username>"
        );
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

fn cmd_list_users(verbose: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let recipients = list_recipients(&repo_root)?;
    if recipients.is_empty() {
        println!("no recipients configured");
        return Ok(());
    }

    let wrapped = wrapped_key_files(&repo_root)?;
    let wrapped_names: std::collections::HashSet<String> = wrapped
        .iter()
        .filter_map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(ToString::to_string)
        })
        .collect();

    for recipient in recipients {
        let wrapped_name = format!("{}.age", recipient.fingerprint);
        let has_wrapped = wrapped_names.contains(&wrapped_name);
        if verbose {
            println!(
                "{} key_type={} wrapped={} source={:?}",
                recipient.fingerprint, recipient.key_type, has_wrapped, recipient.source
            );
        } else {
            println!("{} {}", recipient.fingerprint, recipient.key_type);
        }
    }
    Ok(())
}

fn cmd_remove_user(fingerprint: &str, force: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let recipients = list_recipients(&repo_root)?;

    let exists = recipients
        .iter()
        .any(|recipient| recipient.fingerprint == fingerprint);
    if !exists {
        anyhow::bail!("recipient not found: {fingerprint}");
    }

    if recipients.len() <= 1 && !force {
        anyhow::bail!(
            "refusing to remove the last recipient; pass --force to override (risking lockout)"
        );
    }

    let removed = remove_recipient_by_fingerprint(&repo_root, fingerprint)?;
    if !removed {
        anyhow::bail!("no files were removed for recipient {fingerprint}");
    }

    println!("removed recipient {fingerprint}");
    Ok(())
}

fn cmd_add_github_user(username: &str, auto_wrap: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let mut registry = read_github_sources(&repo_root)?;
    let session_key = repo_key_from_session()?;

    let recipients = add_recipients_from_github_username(&repo_root, username)?;
    let fingerprints: Vec<String> = recipients
        .iter()
        .map(|recipient| recipient.fingerprint.clone())
        .collect();

    if auto_wrap && let Some(key) = session_key.as_deref() {
        for recipient in &recipients {
            wrap_repo_key_for_recipient(&repo_root, recipient, key)?;
        }
    }

    registry.users.retain(|source| source.username != username);
    registry.users.push(GithubUserSource {
        username: username.to_string(),
        url: format!("https://github.com/{username}.keys"),
        fingerprints,
        last_refreshed_unix: now_unix(),
    });
    write_github_sources(&repo_root, &registry)?;

    println!("add-github-user: added source for {username}");
    Ok(())
}

fn cmd_list_github_users(verbose: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let registry = read_github_sources(&repo_root)?;
    if registry.users.is_empty() {
        println!("no github user sources configured");
        return Ok(());
    }
    for source in registry.users {
        if verbose {
            println!(
                "username={} url={} fingerprints={} refreshed={}",
                source.username,
                source.url,
                source.fingerprints.len(),
                source.last_refreshed_unix
            );
        } else {
            println!("{}", source.username);
        }
    }
    Ok(())
}

fn cmd_remove_github_user(username: &str, force: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let mut registry = read_github_sources(&repo_root)?;
    let Some(source) = registry
        .users
        .iter()
        .find(|source| source.username == username)
        .cloned()
    else {
        anyhow::bail!("github user source not found: {username}");
    };

    let recipients = list_recipients(&repo_root)?;
    if recipients.len() <= 1 && !force {
        anyhow::bail!("refusing to remove final recipient/source without --force");
    }

    for fingerprint in &source.fingerprints {
        if !fingerprint_in_other_sources(&registry, fingerprint, Some(username), None) {
            let _ = remove_recipient_by_fingerprint(&repo_root, fingerprint)?;
        }
    }

    registry.users.retain(|entry| entry.username != username);
    write_github_sources(&repo_root, &registry)?;
    println!("remove-github-user: removed source for {username}");
    Ok(())
}

fn cmd_add_github_team(org: &str, team: &str, auto_wrap: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let mut registry = read_github_sources(&repo_root)?;
    let session_key = repo_key_from_session()?;
    let (members, _) = fetch_github_team_members(org, team)?;

    let mut fingerprints = std::collections::BTreeSet::new();
    for member in &members {
        let recipients = add_recipients_from_github_username(&repo_root, member)?;
        if auto_wrap && let Some(key) = session_key.as_deref() {
            for recipient in &recipients {
                wrap_repo_key_for_recipient(&repo_root, recipient, key)?;
            }
        }
        for recipient in recipients {
            fingerprints.insert(recipient.fingerprint);
        }
    }

    registry
        .teams
        .retain(|source| !(source.org == org && source.team == team));
    registry.teams.push(GithubTeamSource {
        org: org.to_string(),
        team: team.to_string(),
        member_usernames: members,
        fingerprints: fingerprints.into_iter().collect(),
        last_refreshed_unix: now_unix(),
    });
    write_github_sources(&repo_root, &registry)?;
    println!("add-github-team: added source for {org}/{team}");
    Ok(())
}

fn cmd_list_github_teams() -> Result<()> {
    let repo_root = current_repo_root()?;
    let registry = read_github_sources(&repo_root)?;
    if registry.teams.is_empty() {
        println!("no github team sources configured");
        return Ok(());
    }
    for source in registry.teams {
        println!(
            "{}/{} members={} fingerprints={} refreshed={}",
            source.org,
            source.team,
            source.member_usernames.len(),
            source.fingerprints.len(),
            source.last_refreshed_unix
        );
    }
    Ok(())
}

fn cmd_remove_github_team(org: &str, team: &str) -> Result<()> {
    let repo_root = current_repo_root()?;
    let mut registry = read_github_sources(&repo_root)?;
    let Some(source) = registry
        .teams
        .iter()
        .find(|source| source.org == org && source.team == team)
        .cloned()
    else {
        anyhow::bail!("github team source not found: {org}/{team}");
    };

    for fingerprint in &source.fingerprints {
        if !fingerprint_in_other_sources(&registry, fingerprint, None, Some((org, team))) {
            let _ = remove_recipient_by_fingerprint(&repo_root, fingerprint)?;
        }
    }

    registry
        .teams
        .retain(|entry| !(entry.org == org && entry.team == team));
    write_github_sources(&repo_root, &registry)?;
    println!("remove-github-team: removed source for {org}/{team}");
    Ok(())
}

fn cmd_refresh_github_keys(username: Option<String>, dry_run: bool, json: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let mut registry = read_github_sources(&repo_root)?;
    let mut targets: Vec<_> = registry.users.clone();
    if let Some(user) = username.as_deref() {
        targets.retain(|source| source.username == user);
    }

    if targets.is_empty() {
        println!("refresh-github-keys: no matching GitHub user sources configured");
        return Ok(());
    }

    let session_key = repo_key_from_session()?;
    let mut events = Vec::new();

    for source in targets {
        let before_set: std::collections::HashSet<String> =
            source.fingerprints.iter().cloned().collect();
        let fetched = add_recipients_from_github_source(
            &repo_root,
            &source.url,
            Some(source.username.clone()),
        )?;
        let after_set: std::collections::HashSet<String> = fetched
            .iter()
            .map(|recipient| recipient.fingerprint.clone())
            .collect();

        let added: Vec<String> = after_set.difference(&before_set).cloned().collect();
        let removed: Vec<String> = before_set.difference(&after_set).cloned().collect();
        let unchanged = before_set.intersection(&after_set).count();

        if !dry_run {
            let mut safe_remove = Vec::new();
            for fingerprint in &removed {
                if !fingerprint_in_other_sources(
                    &registry,
                    fingerprint,
                    Some(&source.username),
                    None,
                ) {
                    safe_remove.push(fingerprint.clone());
                }
            }
            let _ = remove_recipients_by_fingerprints(&repo_root, &safe_remove)?;

            if let Some(key) = session_key.as_deref() {
                for recipient in &fetched {
                    wrap_repo_key_for_recipient(&repo_root, recipient, key)?;
                }
            }

            if let Some(entry) = registry
                .users
                .iter_mut()
                .find(|entry| entry.username == source.username)
            {
                entry.fingerprints = after_set.iter().cloned().collect();
                entry.last_refreshed_unix = now_unix();
            }
        }

        events.push(serde_json::json!({
            "username": source.username,
            "added": added,
            "removed": removed,
            "unchanged": unchanged,
            "dry_run": dry_run,
        }));
    }

    if !dry_run {
        write_github_sources(&repo_root, &registry)?;
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"events": events}))?
        );
    } else {
        for event in events {
            println!("refresh-github-keys: {}", event);
        }
    }

    Ok(())
}

fn cmd_refresh_github_teams(
    org: Option<String>,
    team: Option<String>,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let mut registry = read_github_sources(&repo_root)?;
    let mut targets = registry.teams.clone();
    if let Some(org) = org.as_deref() {
        targets.retain(|source| source.org == org);
    }
    if let Some(team) = team.as_deref() {
        targets.retain(|source| source.team == team);
    }
    if targets.is_empty() {
        println!("refresh-github-teams: no matching team sources configured");
        return Ok(());
    }

    let session_key = repo_key_from_session()?;
    let mut events = Vec::new();

    for source in targets {
        let (members, _) = fetch_github_team_members(&source.org, &source.team)?;
        let mut fetched_fingerprints = std::collections::HashSet::new();

        for member in &members {
            let imported = add_recipients_from_github_username(&repo_root, member)?;
            if let Some(key) = session_key.as_deref()
                && !dry_run
            {
                for recipient in &imported {
                    wrap_repo_key_for_recipient(&repo_root, recipient, key)?;
                }
            }
            for recipient in imported {
                fetched_fingerprints.insert(recipient.fingerprint);
            }
        }

        let before_set: std::collections::HashSet<String> =
            source.fingerprints.iter().cloned().collect();
        let added: Vec<String> = fetched_fingerprints
            .difference(&before_set)
            .cloned()
            .collect();
        let removed: Vec<String> = before_set
            .difference(&fetched_fingerprints)
            .cloned()
            .collect();
        let unchanged = before_set.intersection(&fetched_fingerprints).count();

        if !dry_run {
            let mut safe_remove = Vec::new();
            for fingerprint in &removed {
                if !fingerprint_in_other_sources(
                    &registry,
                    fingerprint,
                    None,
                    Some((&source.org, &source.team)),
                ) {
                    safe_remove.push(fingerprint.clone());
                }
            }
            let _ = remove_recipients_by_fingerprints(&repo_root, &safe_remove)?;

            if let Some(entry) = registry
                .teams
                .iter_mut()
                .find(|entry| entry.org == source.org && entry.team == source.team)
            {
                entry.member_usernames = members;
                entry.fingerprints = fetched_fingerprints.iter().cloned().collect();
                entry.last_refreshed_unix = now_unix();
            }
        }

        events.push(serde_json::json!({
            "org": source.org,
            "team": source.team,
            "added": added,
            "removed": removed,
            "unchanged": unchanged,
            "dry_run": dry_run,
        }));
    }

    if !dry_run {
        write_github_sources(&repo_root, &registry)?;
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"events": events}))?
        );
    } else {
        for event in events {
            println!("refresh-github-teams: {}", event);
        }
    }

    Ok(())
}

fn cmd_access_audit(identities: Vec<String>, json: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let recipients = list_recipients(&repo_root)?;
    let identities = if identities.is_empty() {
        default_private_key_candidates()
    } else {
        identities.into_iter().map(PathBuf::from).collect()
    };

    let mut accessible = 0usize;
    let mut rows = Vec::new();
    for recipient in recipients {
        let wrapped = wrapped_store_dir(&repo_root).join(format!("{}.age", recipient.fingerprint));
        let can = unwrap_repo_key_from_wrapped_files(&[wrapped], &identities)?.is_some();
        if can {
            accessible += 1;
        }
        rows.push(serde_json::json!({
            "fingerprint": recipient.fingerprint,
            "key_type": recipient.key_type,
            "source": format!("{:?}", recipient.source),
            "accessible": can,
        }));
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "accessible": accessible,
                "rows": rows,
            }))?
        );
    } else {
        for row in &rows {
            println!("{}", row);
        }
        println!("access-audit: accessible recipients={accessible}");
    }

    Ok(())
}

fn cmd_install() -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;
    install_gitattributes(&repo_root, &manifest.protected_patterns)?;
    install_git_filters(&repo_root)?;
    println!("install: refreshed gitattributes and git filter configuration");
    Ok(())
}

fn cmd_migrate_from_git_crypt(
    dry_run: bool,
    reencrypt: bool,
    verify: bool,
    json: bool,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let path = repo_root.join(".gitattributes");
    let text =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;

    let mut patterns = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.contains("filter=git-crypt") {
            continue;
        }
        if let Some(pattern) = trimmed.split_whitespace().next()
            && !pattern.is_empty()
        {
            patterns.push(pattern.to_string());
        }
    }

    if patterns.is_empty() {
        anyhow::bail!("no git-crypt patterns found in .gitattributes");
    }

    patterns.sort();
    patterns.dedup();

    let mut manifest_before = read_manifest(&repo_root).unwrap_or_default();
    let old_patterns = manifest_before.protected_patterns.clone();
    manifest_before.protected_patterns = patterns;
    let manifest_after = manifest_before;

    let imported_patterns = manifest_after.protected_patterns.len();
    let changed_patterns = old_patterns != manifest_after.protected_patterns;

    if !dry_run {
        write_manifest(&repo_root, &manifest_after)?;
        install_gitattributes(&repo_root, &manifest_after.protected_patterns)?;
        install_git_filters(&repo_root)?;
    }

    let mut reencrypted_files = 0usize;
    if reencrypt {
        if dry_run {
            reencrypted_files = protected_tracked_files(&repo_root, &manifest_after)?.len();
        } else {
            reencrypted_files = reencrypt_with_current_session(&repo_root, &manifest_after)?;
        }
    }

    let mut verify_failures = Vec::new();
    if verify {
        verify_failures = verify_failures_with_manifest(&repo_root, &manifest_after)?;
        if !verify_failures.is_empty() {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "dry_run": dry_run,
                        "verify_failures": verify_failures,
                    }))?
                );
            } else {
                println!("migrate-from-git-crypt: verify failed");
                for failure in &verify_failures {
                    eprintln!("- {failure}");
                }
            }
            anyhow::bail!("migration verification failed");
        }
    }

    let report = serde_json::json!({
        "ok": true,
        "dry_run": dry_run,
        "imported_patterns": imported_patterns,
        "changed_patterns": changed_patterns,
        "reencrypt_requested": reencrypt,
        "reencrypted_files": reencrypted_files,
        "verify_requested": verify,
        "verify_failures": verify_failures,
    });

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "migrate-from-git-crypt: patterns={} changed={} dry_run={} reencrypted={} verify={}",
            imported_patterns, changed_patterns, dry_run, reencrypted_files, verify
        );
    }

    Ok(())
}

fn cmd_export_repo_key(out: &str) -> Result<()> {
    let Some(key) = repo_key_from_session()? else {
        anyhow::bail!("repository is locked; run `git-ssh-crypt unlock` first");
    };
    let encoded = hex::encode(key);
    fs::write(out, format!("{encoded}\n")).with_context(|| format!("failed to write {out}"))?;
    println!("export-repo-key: wrote key material to {out}");
    Ok(())
}

fn cmd_import_repo_key(input: &str) -> Result<()> {
    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;
    let text = fs::read_to_string(input).with_context(|| format!("failed to read {input}"))?;
    let key = hex::decode(text.trim()).context("import key file must contain hex key bytes")?;
    if key.len() != 32 {
        anyhow::bail!("imported key length must be 32 bytes, got {}", key.len());
    }

    let wrapped = wrap_repo_key_for_all_recipients(&repo_root, &key)?;
    write_unlock_session(&common_dir, &key, "import")?;
    println!(
        "import-repo-key: imported key and wrapped for {} recipients",
        wrapped.len()
    );
    Ok(())
}

fn git_ls_files(repo_root: &std::path::Path) -> Result<Vec<String>> {
    let output = std::process::Command::new("git")
        .current_dir(repo_root)
        .args(["ls-files", "-z"])
        .output()
        .context("failed to run git ls-files")?;
    if !output.status.success() {
        anyhow::bail!("git ls-files failed");
    }

    let mut paths = Vec::new();
    for raw in output.stdout.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let path = String::from_utf8(raw.to_vec()).context("non-utf8 path from git ls-files")?;
        paths.push(path);
    }
    Ok(paths)
}

fn git_show_index_path(repo_root: &std::path::Path, path: &str) -> Result<Vec<u8>> {
    let output = std::process::Command::new("git")
        .current_dir(repo_root)
        .args(["show", &format!(":{path}")])
        .output()
        .with_context(|| format!("failed to run git show :{path}"))?;

    if !output.status.success() {
        anyhow::bail!("git show :{path} failed");
    }

    Ok(output.stdout)
}

fn git_add_paths(repo_root: &std::path::Path, paths: &[String], renormalize: bool) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }

    let mut args = vec!["add".to_string()];
    if renormalize {
        args.push("--renormalize".to_string());
    }
    args.push("--".to_string());
    args.extend(paths.iter().cloned());

    let output = std::process::Command::new("git")
        .current_dir(repo_root)
        .args(args)
        .output()
        .context("failed to run git add")?;

    if !output.status.success() {
        anyhow::bail!(
            "git add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn protected_tracked_files(
    repo_root: &std::path::Path,
    manifest: &RepositoryManifest,
) -> Result<Vec<String>> {
    let files = git_ls_files(repo_root)?;
    let mut protected = Vec::new();
    for path in files {
        if is_protected_path(manifest, &path)? {
            protected.push(path);
        }
    }
    Ok(protected)
}

fn verify_failures_with_manifest(
    repo_root: &std::path::Path,
    manifest: &RepositoryManifest,
) -> Result<Vec<String>> {
    let files = protected_tracked_files(repo_root, manifest)?;
    let mut failures = Vec::new();
    for path in files {
        let blob = git_show_index_path(repo_root, &path)?;
        if !blob.starts_with(&ENCRYPTED_MAGIC) {
            failures.push(path);
        }
    }
    Ok(failures)
}

fn cmd_verify(strict: bool, json: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;
    let strict = strict || manifest.strict_mode;

    let failures = verify_failures_with_manifest(&repo_root, &manifest)?;

    if !failures.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": false,
                    "failures": failures,
                }))?
            );
        } else {
            println!("verify: FAIL ({})", failures.len());
            for file in &failures {
                eprintln!("- plaintext protected file in index: {file}");
            }
        }
        anyhow::bail!("verify failed");
    }

    if strict {
        let process_cfg = git_local_config(&repo_root, "filter.git-ssh-crypt.process")?;
        let required_cfg = git_local_config(&repo_root, "filter.git-ssh-crypt.required")?;
        if process_cfg.is_none() || required_cfg.as_deref() != Some("true") {
            anyhow::bail!(
                "strict verify failed: filter.git-ssh-crypt.process and required=true must be configured"
            );
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"ok": true}))?
        );
    } else {
        println!("verify: OK");
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

fn reencrypt_with_current_session(
    repo_root: &std::path::Path,
    manifest: &RepositoryManifest,
) -> Result<usize> {
    if repo_key_from_session()?.is_none() {
        anyhow::bail!("repository is locked; run `git-ssh-crypt unlock` first");
    }

    let protected = protected_tracked_files(repo_root, manifest)?;
    if protected.is_empty() {
        return Ok(0);
    }

    const CHUNK: usize = 100;
    for chunk in protected.chunks(CHUNK) {
        git_add_paths(repo_root, chunk, true)?;
    }

    Ok(protected.len())
}

fn cmd_reencrypt() -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;

    let refreshed = reencrypt_with_current_session(&repo_root, &manifest)?;
    if refreshed == 0 {
        println!("reencrypt: no protected tracked files found");
        return Ok(());
    }

    println!("reencrypt: refreshed {} protected files", refreshed);
    Ok(())
}

fn cmd_rotate_key(auto_reencrypt: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;
    let Some(previous_key) = repo_key_from_session()? else {
        anyhow::bail!("repository is locked; run `git-ssh-crypt unlock` first");
    };
    let manifest = read_manifest(&repo_root)?;

    let recipients = list_recipients(&repo_root)?;
    if recipients.is_empty() {
        anyhow::bail!("no recipients configured; cannot rotate repository key");
    }

    let wrapped_snapshot = snapshot_wrapped_files(&repo_root)?;

    let mut key = [0_u8; 32];
    rand::rng().fill_bytes(&mut key);
    let wrapped = match wrap_repo_key_for_all_recipients(&repo_root, &key) {
        Ok(wrapped) => wrapped,
        Err(err) => {
            restore_wrapped_files(&repo_root, &wrapped_snapshot)?;
            anyhow::bail!(
                "rotate-key failed while wrapping new key; previous wrapped files restored: {err:#}"
            );
        }
    };
    write_unlock_session(&common_dir, &key, "rotated")?;

    println!(
        "rotate-key: generated new repository key and wrapped for {} recipients",
        wrapped.len()
    );
    if auto_reencrypt {
        match reencrypt_with_current_session(&repo_root, &manifest) {
            Ok(count) => {
                println!(
                    "rotate-key: auto-reencrypt refreshed {} protected files",
                    count
                );
            }
            Err(err) => {
                let mut rollback_errors = Vec::new();
                if let Err(rollback_wrap_err) = restore_wrapped_files(&repo_root, &wrapped_snapshot)
                {
                    rollback_errors.push(format!(
                        "wrapped-file rollback failed: {rollback_wrap_err:#}"
                    ));
                }
                if let Err(rollback_session_err) =
                    write_unlock_session(&common_dir, &previous_key, "rollback")
                {
                    rollback_errors
                        .push(format!("session rollback failed: {rollback_session_err:#}"));
                }
                if rollback_errors.is_empty() {
                    if let Err(restore_err) = reencrypt_with_current_session(&repo_root, &manifest)
                    {
                        rollback_errors.push(format!("reencrypt rollback failed: {restore_err:#}"));
                    }
                }

                if rollback_errors.is_empty() {
                    anyhow::bail!("rotate-key auto-reencrypt failed and was rolled back: {err:#}");
                }

                anyhow::bail!(
                    "rotate-key auto-reencrypt failed: {err:#}; rollback encountered issues: {}",
                    rollback_errors.join("; ")
                );
            }
        }
    } else {
        println!("rotate-key: run `git-ssh-crypt reencrypt` and commit to complete rotation");
    }

    Ok(())
}

fn repo_key_from_session_in(common_dir: &std::path::Path) -> Result<Option<Vec<u8>>> {
    let maybe_session = read_unlock_session(common_dir)?;
    let Some(session) = maybe_session else {
        return Ok(None);
    };
    let key = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(session.key_b64)
        .context("invalid session key encoding")?;
    Ok(Some(key))
}

fn repo_key_from_session() -> Result<Option<Vec<u8>>> {
    let common_dir = current_common_dir()?;
    repo_key_from_session_in(&common_dir)
}

fn git_local_config(repo_root: &std::path::Path, key: &str) -> Result<Option<String>> {
    let output = std::process::Command::new("git")
        .current_dir(repo_root)
        .args(["config", "--local", "--get", key])
        .output()
        .with_context(|| format!("failed to run git config --get {key}"))?;

    if !output.status.success() {
        return Ok(None);
    }

    let value = String::from_utf8(output.stdout)
        .with_context(|| format!("git config value for {key} is not utf8"))?
        .trim()
        .to_string();
    Ok(Some(value))
}

fn cmd_doctor(json: bool) -> Result<()> {
    let mut failures = Vec::new();

    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;
    if !json {
        println!("doctor: repo root {}", repo_root.display());
        println!("doctor: common dir {}", common_dir.display());
    }

    let manifest = match read_manifest(&repo_root) {
        Ok(manifest) => {
            if !json {
                println!("check manifest: PASS");
            }
            manifest
        }
        Err(err) => {
            if !json {
                println!("check manifest: FAIL");
            }
            failures.push(format!("manifest unreadable: {err:#}"));
            RepositoryManifest::default()
        }
    };

    let process_cfg = git_local_config(&repo_root, "filter.git-ssh-crypt.process")?;
    if process_cfg
        .as_ref()
        .is_some_and(|value| value.contains("filter-process"))
    {
        if !json {
            println!("check filter.process: PASS");
        }
    } else {
        if !json {
            println!("check filter.process: FAIL");
        }
        failures.push("filter.git-ssh-crypt.process is missing or invalid".to_string());
    }

    let required_cfg = git_local_config(&repo_root, "filter.git-ssh-crypt.required")?;
    if required_cfg.as_deref() == Some("true") {
        if !json {
            println!("check filter.required: PASS");
        }
    } else {
        if !json {
            println!("check filter.required: FAIL");
        }
        failures.push("filter.git-ssh-crypt.required should be true".to_string());
    }

    let gitattributes = repo_root.join(".gitattributes");
    match fs::read_to_string(&gitattributes) {
        Ok(text) if text.contains("filter=git-ssh-crypt") => {
            if !json {
                println!("check gitattributes wiring: PASS");
            }
        }
        Ok(_) => {
            if !json {
                println!("check gitattributes wiring: FAIL");
            }
            failures.push(".gitattributes has no filter=git-ssh-crypt entries".to_string());
        }
        Err(err) => {
            if !json {
                println!("check gitattributes wiring: FAIL");
            }
            failures.push(format!("cannot read {}: {err}", gitattributes.display()));
        }
    }

    let recipients = list_recipients(&repo_root)?;
    if recipients.is_empty() {
        if !json {
            println!("check recipients: FAIL");
        }
        failures.push("no recipients configured".to_string());
    } else {
        if !json {
            println!("check recipients: PASS ({})", recipients.len());
        }
        for recipient in &recipients {
            if recipient.key_type != "ssh-ed25519" && recipient.key_type != "ssh-rsa" {
                failures.push(format!(
                    "recipient {} uses unsupported key type {}",
                    recipient.fingerprint, recipient.key_type
                ));
            }
        }
    }

    let wrapped_files = wrapped_key_files(&repo_root)?;
    if wrapped_files.is_empty() {
        if !json {
            println!("check wrapped keys: FAIL");
        }
        failures.push("no wrapped keys found".to_string());
    } else {
        if !json {
            println!("check wrapped keys: PASS ({})", wrapped_files.len());
        }
    }

    for recipient in &recipients {
        let wrapped = wrapped_store_dir(&repo_root).join(format!("{}.age", recipient.fingerprint));
        if !wrapped.exists() {
            failures.push(format!(
                "missing wrapped key for recipient {}",
                recipient.fingerprint
            ));
        }
    }

    let session = read_unlock_session(&common_dir)?;
    if let Some(session) = session {
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(session.key_b64)
            .context("unlock session key is invalid base64")?;
        if decoded.len() == 32 {
            if !json {
                println!("check unlock session: PASS (UNLOCKED)");
            }
        } else {
            if !json {
                println!("check unlock session: FAIL");
            }
            failures.push(format!(
                "unlock session key length is {}, expected 32",
                decoded.len()
            ));
        }
    } else {
        if !json {
            println!("check unlock session: PASS (LOCKED)");
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": failures.is_empty(),
                "repo": repo_root.display().to_string(),
                "common_dir": common_dir.display().to_string(),
                "algorithm": format!("{:?}", manifest.encryption_algorithm),
                "strict_mode": manifest.strict_mode,
                "protected_patterns": manifest.protected_patterns,
                "failures": failures,
            }))?
        );
    } else {
        println!("doctor: algorithm {:?}", manifest.encryption_algorithm);
        println!("doctor: strict_mode {}", manifest.strict_mode);
        println!(
            "doctor: protected patterns {}",
            manifest.protected_patterns.join(", ")
        );
    }

    if failures.is_empty() {
        if !json {
            println!("doctor: OK");
        }
        return Ok(());
    }

    if !json {
        println!("doctor: {} issue(s) found", failures.len());
        for failure in failures {
            eprintln!("- {failure}");
        }
    }

    anyhow::bail!("doctor checks failed")
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
    let cwd = std::env::current_dir().context("failed to read current dir")?;
    let repo_root = resolve_repo_root_for_filter(&cwd)?;
    let common_dir = resolve_common_dir_for_filter(&cwd)?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    let mut pending_headers = handle_filter_handshake(&mut reader, &mut writer)?;

    loop {
        let headers = if let Some(headers) = pending_headers.take() {
            headers
        } else {
            let Some(headers) = read_pkt_kv_list(&mut reader)? else {
                break;
            };
            headers
        };

        if headers.is_empty() {
            continue;
        }

        let command = headers
            .iter()
            .find_map(|(k, v)| (k == "command").then_some(v.clone()));

        let Some(command) = command else {
            write_status_only(&mut writer, "error")?;
            continue;
        };

        if command == "list_available_blobs" {
            write_empty_success_list_available_blobs(&mut writer)?;
            continue;
        }

        let pathname = headers
            .iter()
            .find_map(|(k, v)| (k == "pathname").then_some(v.clone()))
            .unwrap_or_default();

        let input = read_pkt_content(&mut reader)?;

        let result = run_filter_command(&repo_root, &common_dir, &command, &pathname, &input);
        match result {
            Ok(output) => write_filter_success(&mut writer, &output)?,
            Err(err) => {
                eprintln!("Error: {err:#}");
                write_status_only(&mut writer, "error")?
            }
        }
    }

    writer
        .flush()
        .context("failed to flush filter-process writer")?;
    Ok(())
}

fn resolve_repo_root_for_filter(cwd: &std::path::Path) -> Result<PathBuf> {
    if let Some(work_tree) = std::env::var_os("GIT_WORK_TREE") {
        let p = PathBuf::from(work_tree);
        if p.is_absolute() {
            return Ok(p);
        }
        return Ok(cwd.join(p));
    }

    if std::env::var_os("GIT_DIR").is_some() {
        return Ok(cwd.to_path_buf());
    }

    Ok(cwd.to_path_buf())
}

fn resolve_common_dir_for_filter(cwd: &std::path::Path) -> Result<PathBuf> {
    if let Some(common_dir) = std::env::var_os("GIT_COMMON_DIR") {
        let p = PathBuf::from(common_dir);
        if p.is_absolute() {
            return Ok(p);
        }
        if let Some(git_dir) = std::env::var_os("GIT_DIR") {
            let git_dir = PathBuf::from(git_dir);
            let git_dir_abs = if git_dir.is_absolute() {
                git_dir
            } else {
                cwd.join(git_dir)
            };
            let base = git_dir_abs
                .parent()
                .map_or_else(|| cwd.to_path_buf(), std::path::Path::to_path_buf);
            return Ok(base.join(p));
        }
        return Ok(cwd.join(p));
    }

    if let Some(git_dir) = std::env::var_os("GIT_DIR") {
        let p = PathBuf::from(git_dir);
        let git_dir_abs = if p.is_absolute() { p } else { cwd.join(p) };
        if let Some(parent) = git_dir_abs.parent()
            && parent.file_name().is_some_and(|name| name == "worktrees")
            && let Some(common) = parent.parent()
        {
            return Ok(common.to_path_buf());
        }
        return Ok(git_dir_abs);
    }

    Ok(cwd.join(".git"))
}

fn resolve_repo_root_for_command(cwd: &std::path::Path) -> Result<PathBuf> {
    if std::env::var_os("GIT_DIR").is_some() {
        return resolve_repo_root_for_filter(cwd);
    }
    git_toplevel(cwd)
}

fn resolve_common_dir_for_command(cwd: &std::path::Path) -> Result<PathBuf> {
    if std::env::var_os("GIT_DIR").is_some() {
        return resolve_common_dir_for_filter(cwd);
    }
    git_common_dir(cwd)
}

#[derive(Debug)]
enum PktRead {
    Data(Vec<u8>),
    Flush,
    Eof,
}

fn read_pkt_line(reader: &mut impl Read) -> Result<PktRead> {
    let mut len_buf = [0_u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(PktRead::Eof),
        Err(err) => return Err(err).context("failed reading pkt-line length"),
    }

    let len_str = std::str::from_utf8(&len_buf).context("pkt-line header is not utf8 hex")?;
    let len = usize::from_str_radix(len_str, 16).context("invalid pkt-line length")?;

    if len == 0 {
        return Ok(PktRead::Flush);
    }
    if len < 4 {
        anyhow::bail!("invalid pkt-line length < 4");
    }

    let data_len = len - 4;
    let mut data = vec![0_u8; data_len];
    reader
        .read_exact(&mut data)
        .context("failed reading pkt-line payload")?;
    Ok(PktRead::Data(data))
}

fn write_pkt_data_line(writer: &mut impl Write, data: &[u8]) -> Result<()> {
    if data.len() > 65516 {
        anyhow::bail!("pkt-line payload too large");
    }
    let total = data.len() + 4;
    writer
        .write_all(format!("{total:04x}").as_bytes())
        .context("failed writing pkt-line length")?;
    writer
        .write_all(data)
        .context("failed writing pkt-line payload")?;
    Ok(())
}

fn write_pkt_text_line(writer: &mut impl Write, text: &str) -> Result<()> {
    let mut line = String::with_capacity(text.len() + 1);
    line.push_str(text);
    line.push('\n');
    write_pkt_data_line(writer, line.as_bytes())
}

fn write_pkt_flush(writer: &mut impl Write) -> Result<()> {
    writer
        .write_all(b"0000")
        .context("failed writing pkt-line flush")?;
    Ok(())
}

fn read_pkt_kv_list(reader: &mut impl Read) -> Result<Option<Vec<(String, String)>>> {
    let first = read_pkt_line(reader)?;
    let mut items = Vec::new();

    match first {
        PktRead::Eof => return Ok(None),
        PktRead::Flush => return Ok(Some(items)),
        PktRead::Data(data) => items.push(parse_kv(&data)?),
    }

    loop {
        match read_pkt_line(reader)? {
            PktRead::Data(data) => items.push(parse_kv(&data)?),
            PktRead::Flush => return Ok(Some(items)),
            PktRead::Eof => anyhow::bail!("unexpected EOF while reading key/value pkt-list"),
        }
    }
}

fn parse_kv(data: &[u8]) -> Result<(String, String)> {
    let text = std::str::from_utf8(data)
        .context("pkt key/value line is not utf8")?
        .trim_end_matches('\n');
    let mut split = text.splitn(2, '=');
    let key = split.next().unwrap_or_default();
    let value = split
        .next()
        .ok_or_else(|| anyhow::anyhow!("pkt key/value line missing '='"))?;
    Ok((key.to_string(), value.to_string()))
}

fn read_pkt_content(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut content = Vec::new();
    loop {
        match read_pkt_line(reader)? {
            PktRead::Data(data) => content.extend_from_slice(&data),
            PktRead::Flush => return Ok(content),
            PktRead::Eof => anyhow::bail!("unexpected EOF while reading pkt content"),
        }
    }
}

fn write_pkt_content(writer: &mut impl Write, content: &[u8]) -> Result<()> {
    const CHUNK: usize = 65516;
    for chunk in content.chunks(CHUNK) {
        write_pkt_data_line(writer, chunk)?;
    }
    write_pkt_flush(writer)
}

fn handle_filter_handshake(
    reader: &mut impl Read,
    writer: &mut impl Write,
) -> Result<Option<Vec<(String, String)>>> {
    let hello = read_pkt_kv_or_literal_list(reader)?;
    let has_client = hello.iter().any(|s| s == "git-filter-client");
    let has_v2 = hello.iter().any(|s| s == "version=2");

    if !has_client || !has_v2 {
        anyhow::bail!("unsupported filter-process handshake");
    }

    write_pkt_text_line(writer, "git-filter-server")?;
    write_pkt_text_line(writer, "version=2")?;
    write_pkt_flush(writer)?;
    writer
        .flush()
        .context("failed flushing version negotiation response")?;

    let mut client_capabilities: Vec<String> = hello
        .iter()
        .filter(|line| line.starts_with("capability="))
        .cloned()
        .collect();
    let mut pending_headers: Option<Vec<(String, String)>> = None;
    let mut has_capability_exchange = !client_capabilities.is_empty();

    if client_capabilities.is_empty() {
        let next_list = read_pkt_kv_or_literal_list(reader)?;
        if next_list.iter().any(|line| line.starts_with("capability=")) {
            client_capabilities = next_list;
            has_capability_exchange = true;
        } else if !next_list.is_empty() {
            let mut parsed = Vec::new();
            for line in next_list {
                parsed.push(parse_kv(line.as_bytes())?);
            }
            pending_headers = Some(parsed);
        }
    }

    let supports_clean =
        client_capabilities.iter().any(|s| s == "capability=clean") || pending_headers.is_some();
    let supports_smudge =
        client_capabilities.iter().any(|s| s == "capability=smudge") || pending_headers.is_some();

    if !supports_clean || !supports_smudge {
        anyhow::bail!("git filter client did not advertise clean+smudge capabilities");
    }

    if has_capability_exchange {
        write_pkt_text_line(writer, "capability=clean")?;
        write_pkt_text_line(writer, "capability=smudge")?;
        write_pkt_flush(writer)?;
    }
    writer
        .flush()
        .context("failed flushing handshake response")?;
    Ok(pending_headers)
}

fn read_pkt_kv_or_literal_list(reader: &mut impl Read) -> Result<Vec<String>> {
    let mut out = Vec::new();
    loop {
        match read_pkt_line(reader)? {
            PktRead::Data(data) => {
                let text = String::from_utf8(data)
                    .context("handshake packet not utf8")?
                    .trim_end_matches('\n')
                    .to_string();
                out.push(text);
            }
            PktRead::Flush => return Ok(out),
            PktRead::Eof => anyhow::bail!("unexpected EOF during handshake"),
        }
    }
}

fn run_filter_command(
    repo_root: &std::path::Path,
    common_dir: &std::path::Path,
    command: &str,
    pathname: &str,
    input: &[u8],
) -> Result<Vec<u8>> {
    let manifest = read_manifest(repo_root)?;
    let key = repo_key_from_session_in(common_dir)?;

    match command {
        "clean" => clean(&manifest, key.as_deref(), pathname, input),
        "smudge" => smudge(&manifest, key.as_deref(), pathname, input),
        _ => anyhow::bail!("unsupported filter command: {command}"),
    }
}

fn write_status_only(writer: &mut impl Write, status: &str) -> Result<()> {
    write_pkt_text_line(writer, &format!("status={status}"))?;
    write_pkt_flush(writer)?;
    writer
        .flush()
        .context("failed flushing status-only response")?;
    Ok(())
}

fn write_filter_success(writer: &mut impl Write, content: &[u8]) -> Result<()> {
    write_pkt_text_line(writer, "status=success")?;
    write_pkt_flush(writer)?;
    write_pkt_content(writer, content)?;
    write_pkt_flush(writer)?;
    writer.flush().context("failed flushing success response")?;
    Ok(())
}

fn write_empty_success_list_available_blobs(writer: &mut impl Write) -> Result<()> {
    write_pkt_flush(writer)?;
    write_pkt_text_line(writer, "status=success")?;
    write_pkt_flush(writer)?;
    writer
        .flush()
        .context("failed flushing list_available_blobs response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    #[test]
    fn pkt_text_roundtrip_includes_newline_and_trims_on_read() {
        let mut buf = Vec::new();
        write_pkt_text_line(&mut buf, "command=clean").expect("write should succeed");
        write_pkt_flush(&mut buf).expect("flush should succeed");

        let mut cursor = Cursor::new(buf);
        let list = read_pkt_kv_or_literal_list(&mut cursor).expect("read should succeed");
        assert_eq!(list, vec!["command=clean".to_string()]);
    }

    #[test]
    fn parse_kv_trims_lf_and_parses_value_with_equals() {
        let (key, value) = parse_kv(b"pathname=secrets/a=b.env\n").expect("kv parse should work");
        assert_eq!(key, "pathname");
        assert_eq!(value, "secrets/a=b.env");
    }

    #[test]
    fn handshake_with_capability_exchange_succeeds() {
        let mut input = Vec::new();
        write_pkt_text_line(&mut input, "git-filter-client").expect("write should succeed");
        write_pkt_text_line(&mut input, "version=2").expect("write should succeed");
        write_pkt_flush(&mut input).expect("flush should succeed");
        write_pkt_text_line(&mut input, "capability=clean").expect("write should succeed");
        write_pkt_text_line(&mut input, "capability=smudge").expect("write should succeed");
        write_pkt_flush(&mut input).expect("flush should succeed");

        let mut reader = Cursor::new(input);
        let mut output = Vec::new();
        let pending =
            handle_filter_handshake(&mut reader, &mut output).expect("handshake should work");
        assert!(pending.is_none());
        assert!(!output.is_empty());
    }

    proptest! {
        #[test]
        fn parse_kv_accepts_well_formed_lines(
            key in "[a-z]{1,16}",
            value in "[a-zA-Z0-9_./=-]{0,64}"
        ) {
            let line = format!("{key}={value}\n");
            let (parsed_key, parsed_value) = parse_kv(line.as_bytes()).expect("parse should work");
            prop_assert_eq!(parsed_key, key);
            prop_assert_eq!(parsed_value, value);
        }

        #[test]
        fn read_pkt_line_rejects_invalid_short_lengths(raw in 1_u8..4_u8) {
            let len = format!("{:04x}", raw);
            let mut cursor = Cursor::new(len.into_bytes());
            let result = read_pkt_line(&mut cursor);
            prop_assert!(result.is_err());
        }
    }
}
