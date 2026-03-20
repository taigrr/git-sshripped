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
use git_sshripped_cli_models::InitOptions;
use git_sshripped_encryption_models::{ENCRYPTED_MAGIC, EncryptionAlgorithm};
use git_sshripped_filter::{clean, diff, smudge};
use git_sshripped_recipient::{
    GithubAuthMode, GithubFetchOptions, add_recipient_from_public_key,
    add_recipients_from_github_source_with_options,
    add_recipients_from_github_username_with_options, fetch_github_team_members_with_options,
    fetch_github_user_keys_with_options, list_recipients, remove_recipient_by_fingerprint,
    remove_recipients_by_fingerprints, wrap_repo_key_for_all_recipients,
    wrap_repo_key_for_recipient, wrapped_store_dir,
};
use git_sshripped_recipient_models::{RecipientKey, RecipientSource};
use git_sshripped_repository::{
    install_git_filters, install_gitattributes, read_github_sources, read_local_config,
    read_manifest, write_github_sources, write_local_config, write_manifest,
};
use git_sshripped_repository_models::{
    GithubSourceRegistry, GithubTeamSource, GithubUserSource, RepositoryLocalConfig,
    RepositoryManifest,
};
use git_sshripped_ssh_identity::{
    default_private_key_candidates, detect_identity, discover_ssh_key_files,
    private_keys_matching_agent, unwrap_repo_key_from_wrapped_files,
    unwrap_repo_key_with_agent_helper, well_known_public_key_paths,
};
use git_sshripped_worktree::{
    clear_unlock_session, git_common_dir, git_toplevel, read_unlock_session, write_unlock_session,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

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
#[command(name = "git-sshripped", version)]
#[command(about = "Git-transparent encryption using SSH-oriented workflows")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    SetAgentHelper { path: String },
    SetGithubApiBase { url: String },
    SetGithubWebBase { url: String },
    SetGithubAuthMode { mode: String },
    SetGithubPrivateSourceHardFail { enabled: String },
    Show,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Show {
        #[arg(long)]
        json: bool,
    },
    Verify {
        #[arg(long)]
        json: bool,
    },
    Set {
        #[arg(long)]
        min_recipients: Option<usize>,
        #[arg(long = "allow-key-type")]
        allow_key_types: Vec<String>,
        #[arg(long)]
        require_doctor_clean_for_rotate: Option<bool>,
        #[arg(long)]
        require_verify_strict_clean_for_rotate_revoke: Option<bool>,
        #[arg(long)]
        max_source_staleness_hours: Option<u64>,
    },
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
        #[arg(long)]
        prefer_agent: bool,
        #[arg(long)]
        no_agent: bool,
    },
    Lock {
        #[arg(long)]
        force: bool,
        #[arg(long)]
        no_scrub: bool,
    },
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
        #[arg(long, conflicts_with = "auto_wrap")]
        no_auto_wrap: bool,
        /// Add all GitHub keys for the user, not just those matching local private keys
        #[arg(long, conflicts_with_all = ["key", "key_file"])]
        all: bool,
        /// Only add the GitHub key matching this public key line
        #[arg(long, conflicts_with_all = ["all", "key_file"])]
        key: Option<String>,
        /// Read the public key from a file instead of passing it inline
        #[arg(long, conflicts_with_all = ["all", "key"])]
        key_file: Option<String>,
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
        fail_on_drift: bool,
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
        #[arg(long, conflicts_with = "auto_wrap")]
        no_auto_wrap: bool,
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
        fail_on_drift: bool,
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
    RevokeUser {
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long = "github-user")]
        github_user: Option<String>,
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        all_keys_for_user: bool,
        #[arg(long)]
        force: bool,
        #[arg(long = "auto-reencrypt")]
        auto_reencrypt: bool,
        #[arg(long)]
        json: bool,
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
        #[arg(long = "write-report")]
        write_report: Option<String>,
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
        /// Temp file provided by git's textconv; if absent, read stdin
        file: Option<String>,
    },
    FilterProcess,
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

pub fn run() -> Result<()> {
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
            prefer_agent,
            no_agent,
        } => cmd_unlock(key_hex, identities, github_user, prefer_agent, no_agent),
        Command::Lock { force, no_scrub } => cmd_lock(force, no_scrub),
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
            no_auto_wrap,
            all,
            key,
            key_file,
        } => cmd_add_github_user(&username, auto_wrap || !no_auto_wrap, all, key, key_file),
        Command::ListGithubUsers { verbose } => cmd_list_github_users(verbose),
        Command::RemoveGithubUser { username, force } => cmd_remove_github_user(&username, force),
        Command::RefreshGithubKeys {
            username,
            dry_run,
            fail_on_drift,
            json,
        } => cmd_refresh_github_keys(username, dry_run, fail_on_drift, json),
        Command::AddGithubTeam {
            org,
            team,
            auto_wrap,
            no_auto_wrap,
        } => cmd_add_github_team(&org, &team, auto_wrap || !no_auto_wrap),
        Command::ListGithubTeams => cmd_list_github_teams(),
        Command::RemoveGithubTeam { org, team } => cmd_remove_github_team(&org, &team),
        Command::RefreshGithubTeams {
            org,
            team,
            dry_run,
            fail_on_drift,
            json,
        } => cmd_refresh_github_teams(org, team, dry_run, fail_on_drift, json),
        Command::AccessAudit { identities, json } => cmd_access_audit(identities, json),
        Command::RemoveUser { fingerprint, force } => cmd_remove_user(&fingerprint, force),
        Command::RevokeUser {
            fingerprint,
            github_user,
            org,
            team,
            all_keys_for_user,
            force,
            auto_reencrypt,
            json,
        } => cmd_revoke_user(
            fingerprint,
            github_user,
            org,
            team,
            all_keys_for_user,
            force,
            auto_reencrypt,
            json,
        ),
        Command::Install => cmd_install(),
        Command::MigrateFromGitCrypt {
            dry_run,
            reencrypt,
            verify,
            json,
            write_report,
        } => cmd_migrate_from_git_crypt(dry_run, reencrypt, verify, json, write_report),
        Command::ExportRepoKey { out } => cmd_export_repo_key(&out),
        Command::ImportRepoKey { input } => cmd_import_repo_key(&input),
        Command::Verify { strict, json } => cmd_verify(strict, json),
        Command::Clean { path } => cmd_clean(&path),
        Command::Smudge { path } => cmd_smudge(&path),
        Command::Diff { path, file } => cmd_diff(&path, file.as_deref()),
        Command::FilterProcess => cmd_filter_process(),
        Command::Policy { command } => cmd_policy(command),
        Command::Config { command } => cmd_config(command),
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

fn current_bin_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(ToString::to_string))
        .unwrap_or_else(|| "git-sshripped".to_string())
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

fn is_executable(path: &std::path::Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            return meta.permissions().mode() & 0o111 != 0;
        }
        false
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_helper_in_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn resolve_agent_helper(repo_root: &std::path::Path) -> Result<Option<(PathBuf, String)>> {
    if let Ok(path) = std::env::var("GSC_SSH_AGENT_HELPER") {
        let candidate = PathBuf::from(path);
        if is_executable(&candidate) {
            return Ok(Some((candidate, "env".to_string())));
        }
    }

    if let Some(cfg_value) = git_local_config(repo_root, "git-sshripped.agentHelper")? {
        let candidate = PathBuf::from(cfg_value);
        if is_executable(&candidate) {
            return Ok(Some((candidate, "git-config".to_string())));
        }
    }

    let local_cfg = read_local_config(repo_root)?;
    if let Some(helper) = local_cfg.agent_helper {
        let candidate = PathBuf::from(helper);
        if is_executable(&candidate) {
            return Ok(Some((candidate, "repo-config".to_string())));
        }
    }

    for name in [
        "git-sshripped-agent-helper",
        "age-plugin-ssh-agent",
        "age-plugin-ssh",
    ] {
        if let Some(path) = find_helper_in_path(name) {
            return Ok(Some((path, "path".to_string())));
        }
    }

    Ok(None)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn classify_github_refresh_error(err: &anyhow::Error) -> &'static str {
    let text = format!("{err:#}").to_ascii_lowercase();
    if text.contains("status 401") || text.contains("unauthorized") {
        return "auth_missing";
    }
    if text.contains("requires github_token") {
        return "auth_missing";
    }
    if text.contains("status 403") || text.contains("forbidden") {
        return "permission_denied";
    }
    if text.contains("status 404") || text.contains("not found") {
        return "not_found";
    }
    if text.contains("status 429") || text.contains("rate limit") {
        return "rate_limited";
    }
    if text.contains("timed out") || text.contains("connection") || text.contains("dns") {
        return "backend_unavailable";
    }
    "unknown"
}

fn enforce_verify_clean_for_sensitive_actions(
    repo_root: &std::path::Path,
    manifest: &RepositoryManifest,
    action: &str,
) -> Result<()> {
    if !manifest.require_verify_strict_clean_for_rotate_revoke {
        return Ok(());
    }
    let failures = verify_failures(repo_root)?;
    if failures.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{action} blocked by manifest policy require_verify_strict_clean_for_rotate_revoke=true; run `git-sshripped verify --strict` and fix: {}",
        failures.join("; ")
    )
}

fn parse_github_auth_mode(raw: &str) -> Result<GithubAuthMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(GithubAuthMode::Auto),
        "gh" => Ok(GithubAuthMode::Gh),
        "token" => Ok(GithubAuthMode::Token),
        "anonymous" => Ok(GithubAuthMode::Anonymous),
        other => anyhow::bail!(
            "unsupported github auth mode '{other}'; expected auto|gh|token|anonymous"
        ),
    }
}

fn github_fetch_options(repo_root: &std::path::Path) -> Result<GithubFetchOptions> {
    let cfg = read_local_config(repo_root)?;
    let mut options = GithubFetchOptions::default();
    if let Some(api_base) = cfg.github_api_base {
        options.api_base_url = api_base.trim_end_matches('/').to_string();
    }
    if let Some(web_base) = cfg.github_web_base {
        options.web_base_url = web_base.trim_end_matches('/').to_string();
    }
    if let Some(mode) = cfg.github_auth_mode {
        options.auth_mode = parse_github_auth_mode(&mode)?;
    }
    if let Some(hard_fail) = cfg.github_private_source_hard_fail {
        options.private_source_hard_fail = hard_fail;
    }
    Ok(options)
}

fn github_auth_mode_label(mode: GithubAuthMode) -> &'static str {
    match mode {
        GithubAuthMode::Auto => "auto",
        GithubAuthMode::Gh => "gh",
        GithubAuthMode::Token => "token",
        GithubAuthMode::Anonymous => "anonymous",
    }
}

fn repo_key_id_from_bytes(key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hex::encode(hasher.finalize())
}

fn allowed_key_types_set(manifest: &RepositoryManifest) -> std::collections::HashSet<&str> {
    manifest
        .allowed_key_types
        .iter()
        .map(String::as_str)
        .collect()
}

fn enforce_allowed_key_types_for_added_recipients(
    repo_root: &std::path::Path,
    manifest: &RepositoryManifest,
    existing_fingerprints: &std::collections::HashSet<String>,
    added: &[RecipientKey],
    action: &str,
) -> Result<()> {
    let allowed = allowed_key_types_set(manifest);
    let mut invalid_existing = Vec::new();
    let mut invalid_new = Vec::new();

    for recipient in added {
        if allowed.contains(recipient.key_type.as_str()) {
            continue;
        }
        if existing_fingerprints.contains(&recipient.fingerprint) {
            invalid_existing.push(format!(
                "{} ({})",
                recipient.fingerprint, recipient.key_type
            ));
        } else {
            invalid_new.push(recipient.fingerprint.clone());
        }
    }

    if !invalid_new.is_empty() {
        let _ = remove_recipients_by_fingerprints(repo_root, &invalid_new)?;
    }

    if invalid_existing.is_empty() && invalid_new.is_empty() {
        return Ok(());
    }

    let mut invalid_all = invalid_existing;
    invalid_all.extend(invalid_new.into_iter().map(|fingerprint| {
        let key_type = added
            .iter()
            .find(|recipient| recipient.fingerprint == fingerprint)
            .map(|recipient| recipient.key_type.clone())
            .unwrap_or_else(|| "unknown".to_string());
        format!("{fingerprint} ({key_type})")
    }));

    anyhow::bail!(
        "{action} blocked by manifest policy: disallowed key types [{}]; allowed key types are [{}]",
        invalid_all.join(", "),
        manifest.allowed_key_types.join(", ")
    );
}

fn enforce_min_recipients(
    manifest: &RepositoryManifest,
    resulting_count: usize,
    action: &str,
) -> Result<()> {
    if resulting_count < manifest.min_recipients {
        anyhow::bail!(
            "{action} blocked by manifest policy: min_recipients={} but resulting recipients would be {}",
            manifest.min_recipients,
            resulting_count
        );
    }
    Ok(())
}

fn enforce_existing_recipient_policy(
    repo_root: &std::path::Path,
    manifest: &RepositoryManifest,
    action: &str,
) -> Result<()> {
    let recipients = list_recipients(repo_root)?;
    enforce_min_recipients(manifest, recipients.len(), action)?;
    let allowed = allowed_key_types_set(manifest);
    let disallowed: Vec<String> = recipients
        .iter()
        .filter(|recipient| !allowed.contains(recipient.key_type.as_str()))
        .map(|recipient| format!("{} ({})", recipient.fingerprint, recipient.key_type))
        .collect();
    if disallowed.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{action} blocked by manifest policy: disallowed existing recipient key types [{}]; allowed key types are [{}]",
        disallowed.join(", "),
        manifest.allowed_key_types.join(", ")
    )
}

fn collect_doctor_failures(
    repo_root: &std::path::Path,
    common_dir: &std::path::Path,
    manifest: &RepositoryManifest,
) -> Result<Vec<String>> {
    let mut failures = Vec::new();

    if manifest.min_recipients == 0 {
        failures.push("manifest min_recipients must be at least 1".to_string());
    }
    if manifest.allowed_key_types.is_empty() {
        failures.push("manifest allowed_key_types cannot be empty".to_string());
    }
    if manifest.max_source_staleness_hours == Some(0) {
        failures.push("manifest max_source_staleness_hours must be > 0 when set".to_string());
    }
    if manifest.repo_key_id.is_none() {
        failures.push(
            "manifest repo_key_id is missing; run `git-sshripped unlock` to bind current key"
                .to_string(),
        );
    }

    let process_cfg = git_local_config(repo_root, "filter.git-sshripped.process")?;
    if !process_cfg
        .as_ref()
        .is_some_and(|value| value.contains("filter-process"))
    {
        failures.push("filter.git-sshripped.process is missing or invalid".to_string());
    }

    let required_cfg = git_local_config(repo_root, "filter.git-sshripped.required")?;
    if required_cfg.as_deref() != Some("true") {
        failures.push("filter.git-sshripped.required should be true".to_string());
    }

    let gitattributes = repo_root.join(".gitattributes");
    match fs::read_to_string(&gitattributes) {
        Ok(text) if text.contains("filter=git-sshripped") => {}
        Ok(_) => failures.push(".gitattributes has no filter=git-sshripped entries".to_string()),
        Err(err) => failures.push(format!("cannot read {}: {err}", gitattributes.display())),
    }

    let recipients = list_recipients(repo_root)?;
    if recipients.is_empty() {
        failures.push("no recipients configured".to_string());
    }
    if recipients.len() < manifest.min_recipients {
        failures.push(format!(
            "recipient count {} is below manifest min_recipients {}",
            recipients.len(),
            manifest.min_recipients
        ));
    }

    let allowed_types = allowed_key_types_set(manifest);
    for recipient in &recipients {
        if !allowed_types.contains(recipient.key_type.as_str()) {
            failures.push(format!(
                "recipient {} uses disallowed key type {}",
                recipient.fingerprint, recipient.key_type
            ));
        }
    }

    if let Some(max_hours) = manifest.max_source_staleness_hours {
        let registry = read_github_sources(repo_root)?;
        let max_age_secs = max_hours.saturating_mul(3600);
        let now = now_unix();
        for user in &registry.users {
            if user.last_refreshed_unix == 0 {
                failures.push(format!(
                    "github user source {} has never been refreshed",
                    user.username
                ));
                continue;
            }
            let age = now.saturating_sub(user.last_refreshed_unix);
            if age > max_age_secs {
                failures.push(format!(
                    "github user source {} is stale ({}s > {}s)",
                    user.username, age, max_age_secs
                ));
            }
        }
        for team in &registry.teams {
            if team.last_refreshed_unix == 0 {
                failures.push(format!(
                    "github team source {}/{} has never been refreshed",
                    team.org, team.team
                ));
                continue;
            }
            let age = now.saturating_sub(team.last_refreshed_unix);
            if age > max_age_secs {
                failures.push(format!(
                    "github team source {}/{} is stale ({}s > {}s)",
                    team.org, team.team, age, max_age_secs
                ));
            }
        }
    }

    let wrapped_files = wrapped_key_files(repo_root)?;
    if wrapped_files.is_empty() {
        failures.push("no wrapped keys found".to_string());
    }

    for recipient in &recipients {
        let wrapped = wrapped_store_dir(repo_root).join(format!("{}.age", recipient.fingerprint));
        if !wrapped.exists() {
            failures.push(format!(
                "missing wrapped key for recipient {}",
                recipient.fingerprint
            ));
        }
    }

    if let Some(session) = read_unlock_session(common_dir)? {
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(session.key_b64)
            .context("unlock session key is invalid base64")?;
        if decoded.len() != 32 {
            failures.push(format!(
                "unlock session key length is {}, expected 32",
                decoded.len()
            ));
        }

        if let Some(expected) = &manifest.repo_key_id {
            let actual = repo_key_id_from_bytes(&decoded);
            if &actual != expected {
                failures.push(format!(
                    "unlock session repo key mismatch: expected {}, got {}",
                    expected, actual
                ));
            }
            if session.repo_key_id.as_deref() != Some(expected.as_str()) {
                failures.push(format!(
                    "unlock session metadata repo_key_id mismatch: expected {}, got {}",
                    expected,
                    session.repo_key_id.as_deref().unwrap_or("missing")
                ));
            }
        }
    }

    Ok(failures)
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
    let github_options = github_fetch_options(&repo_root)?;

    let init = InitOptions {
        algorithm: algorithm.into(),
        strict_mode: strict,
    };

    let manifest = RepositoryManifest {
        manifest_version: 1,
        encryption_algorithm: init.algorithm,
        strict_mode: init.strict_mode,
        ..RepositoryManifest::default()
    };

    write_manifest(&repo_root, &manifest)?;
    install_gitattributes(&repo_root, &patterns)?;
    install_git_filters(&repo_root, &current_bin_path())?;

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
        let recipients = add_recipients_from_github_source_with_options(
            &repo_root,
            &url,
            None,
            &github_options,
        )?;
        added_recipients.extend(recipients);
    }

    for path in well_known_public_key_paths() {
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

    let mut key = [0_u8; 32];
    rand::rng().fill_bytes(&mut key);
    let mut manifest = manifest;
    manifest.repo_key_id = Some(repo_key_id_from_bytes(&key));
    write_manifest(&repo_root, &manifest)?;

    let wrapped_count = if recipients.is_empty() {
        // No recipients yet — store the repo key in a local unlock session so that
        // subsequent `add-github-user` / `add-user` can wrap it for new recipients.
        let common_dir = current_common_dir()?;
        let key_id = repo_key_id_from_bytes(&key);
        write_unlock_session(&common_dir, &key, "init", Some(key_id))?;
        0
    } else {
        let wrapped = wrap_repo_key_for_all_recipients(&repo_root, &key)?;
        wrapped.len()
    };

    println!("initialized git-sshripped in {}", repo_root.display());
    println!("algorithm: {:?}", manifest.encryption_algorithm);
    println!("strict_mode: {}", manifest.strict_mode);
    println!("patterns: {}", patterns.join(", "));
    println!("recipients: {}", recipients.len());
    println!("wrapped keys written: {}", wrapped_count);
    if added_recipients.is_empty() && !recipients.is_empty() {
        println!("note: reused existing recipient definitions");
    }
    if recipients.is_empty() {
        eprintln!(
            "warning: no recipients configured; the repo key exists only in your local session"
        );
        eprintln!(
            "warning: add a recipient before the session is lost (e.g. git-sshripped add-github-user --username <user>)"
        );
    }
    Ok(())
}

fn cmd_unlock(
    key_hex: Option<String>,
    identities: Vec<String>,
    github_user: Option<String>,
    prefer_agent: bool,
    no_agent: bool,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;
    let mut manifest = read_manifest(&repo_root)?;

    // If there is already a valid unlock session, skip the expensive key-unwrap path.
    if key_hex.is_none() {
        if let Ok(Some(_)) = repo_key_from_session_in(&common_dir, Some(&manifest)) {
            install_git_filters(&repo_root, &current_bin_path())?;
            println!("repository is already unlocked");
            return Ok(());
        }
    }

    let (key, key_source) = if let Some(hex_value) = key_hex {
        (
            hex::decode(hex_value.trim()).context("--key-hex must be valid hex")?,
            "key-hex".to_string(),
        )
    } else {
        let explicit_identities: Vec<PathBuf> = identities.into_iter().map(PathBuf::from).collect();
        let interactive_set: std::collections::HashSet<PathBuf> =
            explicit_identities.iter().cloned().collect();
        let mut identity_files = Vec::new();

        if !no_agent {
            let mut agent_matches = private_keys_matching_agent()?;
            identity_files.append(&mut agent_matches);
        }

        if !explicit_identities.is_empty() {
            if prefer_agent {
                identity_files.extend(explicit_identities);
            } else {
                let mut merged = explicit_identities;
                merged.extend(identity_files);
                identity_files = merged;
            }
        } else {
            identity_files.extend(default_private_key_candidates());
        }

        identity_files.sort();
        identity_files.dedup();

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

        let resolved_helper = if no_agent {
            None
        } else {
            resolve_agent_helper(&repo_root)?
        };

        if let Some((helper_path, source)) = resolved_helper
            && let Some((unwrapped, descriptor)) =
                unwrap_repo_key_with_agent_helper(&wrapped_files, &helper_path, 3000)?
        {
            (
                unwrapped,
                format!("agent-helper[{source}]: {}", descriptor.label),
            )
        } else {
            let Some((unwrapped, descriptor)) = unwrap_repo_key_from_wrapped_files(
                &wrapped_files,
                &identity_files,
                &interactive_set,
            )?
            else {
                anyhow::bail!(
                    "could not decrypt any wrapped key with agent helper or provided identity files; set GSC_SSH_AGENT_HELPER for true ssh-agent decrypt, or pass --identity"
                );
            };
            (unwrapped, descriptor.label)
        }
    };

    let key_id = repo_key_id_from_bytes(&key);
    if let Some(expected) = &manifest.repo_key_id {
        if expected != &key_id {
            anyhow::bail!(
                "unlock failed: derived repo key does not match manifest repo_key_id; expected {}, got {}; run from the correct branch/worktree or re-import/rotate key",
                expected,
                key_id
            );
        }
    } else {
        manifest.repo_key_id = Some(key_id.clone());
        write_manifest(&repo_root, &manifest)?;
    }

    write_unlock_session(&common_dir, &key, &key_source, Some(key_id))?;
    install_git_filters(&repo_root, &current_bin_path())?;

    let mut decrypted_count = 0usize;
    if let Ok(protected) = protected_tracked_files(&repo_root) {
        if !protected.is_empty() {
            println!(
                "decrypting {} protected files in working tree...",
                protected.len()
            );
        }
        for path in &protected {
            let full = repo_root.join(path);
            if let Ok(content) = fs::read(&full) {
                if content.starts_with(&ENCRYPTED_MAGIC) {
                    match git_sshripped_encryption::decrypt(&key, path, &content) {
                        Ok(plaintext) => {
                            if fs::write(&full, &plaintext).is_ok() {
                                decrypted_count += 1;
                            }
                        }
                        Err(e) => {
                            eprintln!("warning: failed to decrypt {path}: {e}");
                        }
                    }
                }
            }
        }
    }

    println!(
        "unlocked repository across worktrees via {}",
        common_dir.display()
    );
    if decrypted_count > 0 {
        println!("decrypted {decrypted_count} protected files in working tree");
    }
    Ok(())
}

fn cmd_lock(force: bool, no_scrub: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;
    let previous_session = read_unlock_session(&common_dir)?;

    let protected = if no_scrub {
        Vec::new()
    } else {
        println!("scanning protected files...");
        let protected = protected_tracked_files(&repo_root)?;
        if protected.is_empty() {
            println!("no protected tracked files found");
        } else {
            println!("found {} protected tracked files", protected.len());
        }
        let dirty = protected_dirty_paths(&repo_root, &protected)?;
        if !dirty.is_empty() && !force {
            let preview = dirty.iter().take(8).cloned().collect::<Vec<_>>().join(", ");
            anyhow::bail!(
                "lock refused: protected files have local changes ({preview}); commit/stash/reset them or re-run with --force"
            );
        }
        protected
    };

    clear_unlock_session(&common_dir)?;
    if !no_scrub {
        println!("scrubbing protected files in working tree...");
        if let Err(scrub_err) = scrub_protected_paths(&repo_root, &protected) {
            if let Some(previous_session) = previous_session {
                let rollback = base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(previous_session.key_b64)
                    .context("failed to decode previous unlock session key while rolling back lock")
                    .and_then(|key| {
                        write_unlock_session(
                            &common_dir,
                            &key,
                            &previous_session.key_source,
                            previous_session.repo_key_id,
                        )
                    });

                if let Err(rollback_err) = rollback {
                    anyhow::bail!(
                        "lock scrub failed: {scrub_err:#}; failed to restore previous unlock session: {rollback_err:#}"
                    );
                }
            }
            anyhow::bail!("lock scrub failed: {scrub_err:#}; previous session restored");
        }
    }

    if no_scrub {
        println!("locked repository across worktrees (no scrub)");
    } else {
        println!("locked repository across worktrees; scrubbed protected files in this worktree");
    }
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
    let helper = resolve_agent_helper(&repo_root)?;
    let protected_count = protected_tracked_files(&repo_root)?.len();
    let drift_count = verify_failures(&repo_root)?.len();
    let session_matches_manifest = if let Some(s) = session.as_ref() {
        if let Some(expected) = manifest.repo_key_id.as_ref() {
            s.repo_key_id.as_deref() == Some(expected.as_str())
        } else {
            true
        }
    } else {
        true
    };

    if json {
        let payload = serde_json::json!({
            "repo": repo_root.display().to_string(),
            "common_dir": common_dir.display().to_string(),
            "state": if session.is_some() { "UNLOCKED" } else { "LOCKED" },
            "algorithm": format!("{:?}", manifest.encryption_algorithm),
            "strict_mode": manifest.strict_mode,
            "repo_key_id": manifest.repo_key_id,
            "min_recipients": manifest.min_recipients,
            "allowed_key_types": manifest.allowed_key_types,
            "require_doctor_clean_for_rotate": manifest.require_doctor_clean_for_rotate,
            "require_verify_strict_clean_for_rotate_revoke": manifest.require_verify_strict_clean_for_rotate_revoke,
            "max_source_staleness_hours": manifest.max_source_staleness_hours,
            "identity": {"label": identity.label, "source": format!("{:?}", identity.source)},
            "recipients": recipients.len(),
            "wrapped_keys": wrapped_files.len(),
            "protected_tracked_files": protected_count,
            "drift_failures": drift_count,
            "unlock_source": session.as_ref().map(|s| s.key_source.clone()),
            "unlock_repo_key_id": session.as_ref().and_then(|s| s.repo_key_id.clone()),
            "session_matches_manifest": session_matches_manifest,
            "agent_helper_resolved": helper.as_ref().map(|(path, _)| path.display().to_string()),
            "agent_helper_source": helper.as_ref().map(|(_, source)| source.clone()),
                "protected_patterns": read_gitattributes_patterns(&repo_root),
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
    println!(
        "repo_key_id: {}",
        manifest.repo_key_id.as_deref().unwrap_or("missing")
    );
    println!("min_recipients: {}", manifest.min_recipients);
    println!(
        "allowed_key_types: {}",
        manifest.allowed_key_types.join(", ")
    );
    println!(
        "require_doctor_clean_for_rotate: {}",
        manifest.require_doctor_clean_for_rotate
    );
    println!(
        "require_verify_strict_clean_for_rotate_revoke: {}",
        manifest.require_verify_strict_clean_for_rotate_revoke
    );
    println!(
        "max_source_staleness_hours: {}",
        manifest
            .max_source_staleness_hours
            .map_or_else(|| "none".to_string(), |v| v.to_string())
    );
    println!("identity: {} ({:?})", identity.label, identity.source);
    println!("recipients: {}", recipients.len());
    println!("wrapped keys: {}", wrapped_files.len());
    println!("protected tracked files: {}", protected_count);
    println!("drift failures: {}", drift_count);
    if let Some(session) = session {
        println!("unlock source: {}", session.key_source);
        println!(
            "unlock repo_key_id: {}",
            session.repo_key_id.as_deref().unwrap_or("missing")
        );
        if !session_matches_manifest {
            println!("unlock session: stale (run `git-sshripped unlock` in this worktree)");
        }
    }
    match helper {
        Some((path, source)) => println!("agent helper: {} ({})", path.display(), source),
        None => println!("agent helper: none"),
    }
    println!(
        "protected patterns: {}",
        read_gitattributes_patterns(&repo_root).join(", ")
    );
    Ok(())
}

fn cmd_add_user(
    key: Option<String>,
    github_keys_url: Option<String>,
    github_user: Option<String>,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let github_options = github_fetch_options(&repo_root)?;
    let manifest = read_manifest(&repo_root)?;
    let session_key = repo_key_from_session()?;
    let existing_fingerprints: std::collections::HashSet<String> = list_recipients(&repo_root)?
        .into_iter()
        .map(|recipient| recipient.fingerprint)
        .collect();

    let mut new_recipients = Vec::new();

    if let Some(url) = github_keys_url {
        let added = add_recipients_from_github_source_with_options(
            &repo_root,
            &url,
            None,
            &github_options,
        )?;
        new_recipients.extend(added);
        println!("added {} recipients from {}", new_recipients.len(), url);
    }

    if let Some(username) = github_user {
        let added = add_recipients_from_github_username_with_options(
            &repo_root,
            &username,
            &github_options,
        )?;
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

    enforce_allowed_key_types_for_added_recipients(
        &repo_root,
        &manifest,
        &existing_fingerprints,
        &new_recipients,
        "add-user",
    )?;

    if let Some(key) = session_key {
        let mut wrapped_count = 0;
        for recipient in &new_recipients {
            wrap_repo_key_for_recipient(&repo_root, recipient, &key)?;
            wrapped_count += 1;
        }
        println!("wrapped repo key for {} new recipients", wrapped_count);
    } else {
        println!(
            "warning: repository is locked; run `git-sshripped unlock` then `git-sshripped rewrap` to grant access"
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
    let manifest = read_manifest(&repo_root)?;
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

    enforce_min_recipients(&manifest, recipients.len().saturating_sub(1), "remove-user")?;

    let removed = remove_recipient_by_fingerprint(&repo_root, fingerprint)?;
    if !removed {
        anyhow::bail!("no files were removed for recipient {fingerprint}");
    }

    println!("removed recipient {fingerprint}");
    Ok(())
}

fn cmd_revoke_user(
    fingerprint: Option<String>,
    github_user: Option<String>,
    org: Option<String>,
    team: Option<String>,
    all_keys_for_user: bool,
    force: bool,
    auto_reencrypt: bool,
    json: bool,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;
    enforce_verify_clean_for_sensitive_actions(&repo_root, &manifest, "revoke-user")?;
    let mut removed_fingerprints = Vec::new();

    let selectors = usize::from(fingerprint.is_some())
        + usize::from(github_user.is_some())
        + usize::from(org.is_some() || team.is_some());
    if selectors != 1 {
        anyhow::bail!(
            "revoke-user requires exactly one selector: --fingerprint, --github-user, or --org/--team"
        );
    }
    if org.is_some() != team.is_some() {
        anyhow::bail!("--org and --team must be specified together");
    }

    let target = if let Some(fingerprint) = fingerprint {
        cmd_remove_user(&fingerprint, force)?;
        removed_fingerprints.push(fingerprint.clone());
        format!("fingerprint:{fingerprint}")
    } else if let Some(username) = github_user {
        let registry = read_github_sources(&repo_root)?;
        if all_keys_for_user {
            let user_fingerprints: Vec<String> = list_recipients(&repo_root)?
                .into_iter()
                .filter_map(|recipient| {
                    if let RecipientSource::GithubKeys {
                        username: Some(ref u),
                        ..
                    } = recipient.source
                        && *u == username
                    {
                        return Some(recipient.fingerprint);
                    }
                    None
                })
                .collect();
            if user_fingerprints.is_empty() {
                anyhow::bail!("no recipient keys found for github user {username}");
            }
            let recipients_count = list_recipients(&repo_root)?.len();
            let would_remove = user_fingerprints
                .iter()
                .filter(|fp| !fingerprint_in_other_sources(&registry, fp, Some(&username), None))
                .count();
            enforce_min_recipients(
                &manifest,
                recipients_count.saturating_sub(would_remove),
                "revoke-user",
            )?;

            for fp in &user_fingerprints {
                if !fingerprint_in_other_sources(&registry, fp, Some(&username), None) {
                    let _ = remove_recipient_by_fingerprint(&repo_root, fp)?;
                    removed_fingerprints.push(fp.clone());
                }
            }

            let mut updated_registry = registry;
            updated_registry
                .users
                .retain(|entry| entry.username != username);
            write_github_sources(&repo_root, &updated_registry)?;
        } else {
            let source = registry
                .users
                .iter()
                .find(|entry| entry.username == username)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("github user source not found: {username}"))?;
            removed_fingerprints = source.fingerprints;
            cmd_remove_github_user(&username, force)?;
        }
        format!("github-user:{username}")
    } else {
        let Some(org) = org else {
            anyhow::bail!("--org is required with --team")
        };
        let Some(team) = team else {
            anyhow::bail!("--team is required with --org")
        };
        let registry = read_github_sources(&repo_root)?;
        let source = registry
            .teams
            .iter()
            .find(|entry| entry.org == org && entry.team == team)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("github team source not found: {org}/{team}"))?;
        removed_fingerprints = source.fingerprints;
        cmd_remove_github_team(&org, &team)?;
        format!("github-team:{org}/{team}")
    };

    let mut refreshed = 0usize;
    if auto_reencrypt {
        refreshed = reencrypt_with_current_session(&repo_root)?;
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "target": target,
                "removed_fingerprints": removed_fingerprints,
                "auto_reencrypt": auto_reencrypt,
                "reencrypted_files": refreshed,
            }))?
        );
    } else if auto_reencrypt {
        println!(
            "revoke-user: auto-reencrypt refreshed {} protected files",
            refreshed
        );
    } else {
        println!("revoke-user: run `git-sshripped reencrypt` and commit to complete offboarding");
    }

    Ok(())
}

fn cmd_add_github_user(
    username: &str,
    auto_wrap: bool,
    all: bool,
    key: Option<String>,
    key_file: Option<String>,
) -> Result<()> {
    let effective_key = match (key, key_file) {
        (Some(k), _) => Some(k),
        (_, Some(source))
            if {
                let lower = source.to_lowercase();
                lower.starts_with("http://") || lower.starts_with("https://")
            } =>
        {
            let contents = reqwest::blocking::get(&source)
                .with_context(|| format!("failed to fetch key from '{source}'"))?
                .error_for_status()
                .with_context(|| format!("HTTP error fetching key from '{source}'"))?
                .text()
                .with_context(|| format!("failed to read response body from '{source}'"))?;
            Some(contents.trim().to_string())
        }
        (_, Some(path)) => {
            let contents = fs::read_to_string(&path)
                .with_context(|| format!("failed to read key file '{path}'"))?;
            Some(contents.trim().to_string())
        }
        _ => None,
    };

    let repo_root = current_repo_root()?;
    let github_options = github_fetch_options(&repo_root)?;
    let manifest = read_manifest(&repo_root)?;
    let mut registry = read_github_sources(&repo_root)?;
    let session_key = repo_key_from_session()?;
    let existing_fingerprints: std::collections::HashSet<String> = list_recipients(&repo_root)?
        .into_iter()
        .map(|recipient| recipient.fingerprint)
        .collect();

    let fetched = fetch_github_user_keys_with_options(username, &github_options, None)?;
    let fetched_keys: Vec<&str> = fetched
        .keys
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(String::as_str)
        .collect();

    println!(
        "add-github-user: fetched {} keys for {username}",
        fetched_keys.len()
    );

    let keys_to_add: Vec<&str> = if all {
        fetched_keys.clone()
    } else if let Some(ref provided_key) = effective_key {
        // Match the provided public key against the fetched GitHub keys.
        let provided_prefix = ssh_key_prefix(provided_key);
        let matched: Vec<&str> = fetched_keys
            .iter()
            .filter(|github_key| ssh_key_prefix(github_key) == provided_prefix)
            .copied()
            .collect();

        if matched.is_empty() {
            anyhow::bail!("the provided key does not match any of {username}'s GitHub keys");
        }
        matched
    } else {
        // Discover local public keys and filter fetched keys to only those with a
        // matching local private key.
        let local_pub_keys = local_public_key_contents();
        let matched: Vec<&str> = fetched_keys
            .iter()
            .filter(|github_key| {
                let github_prefix = ssh_key_prefix(github_key);
                local_pub_keys
                    .iter()
                    .any(|local_key| ssh_key_prefix(local_key) == github_prefix)
            })
            .copied()
            .collect();

        let skipped = fetched_keys.len() - matched.len();
        if matched.is_empty() {
            anyhow::bail!(
                "none of {username}'s GitHub keys match a local private key in ~/.ssh/; pass --all to add all keys, or --key to specify one"
            );
        }
        if skipped > 0 {
            println!(
                "add-github-user: matched {} key(s) to local private keys (skipped {skipped})",
                matched.len()
            );
        }
        matched
    };

    let mut recipients = Vec::new();
    for line in &keys_to_add {
        let recipient = add_recipient_from_public_key(
            &repo_root,
            line,
            RecipientSource::GithubKeys {
                url: fetched.url.clone(),
                username: Some(username.to_string()),
            },
        )
        .with_context(|| format!("failed to add recipient from key line '{line}'"))?;
        recipients.push(recipient);
    }

    enforce_allowed_key_types_for_added_recipients(
        &repo_root,
        &manifest,
        &existing_fingerprints,
        &recipients,
        "add-github-user",
    )?;
    let fingerprints: Vec<String> = recipients
        .iter()
        .map(|recipient| recipient.fingerprint.clone())
        .collect();

    if auto_wrap {
        if let Some(key) = session_key.as_deref() {
            for recipient in &recipients {
                wrap_repo_key_for_recipient(&repo_root, recipient, key)?;
            }
        } else {
            println!(
                "add-github-user: repository is locked; recipients were added but not wrapped (run unlock + rewrap)"
            );
        }
    }

    registry.users.retain(|source| source.username != username);
    registry.users.push(GithubUserSource {
        username: username.to_string(),
        url: format!("{}/{}.keys", github_options.web_base_url, username),
        fingerprints,
        last_refreshed_unix: now_unix(),
        etag: None,
        last_refresh_status_code: Some("ok".to_string()),
        last_refresh_message: Some("added source".to_string()),
    });
    write_github_sources(&repo_root, &registry)?;

    println!(
        "add-github-user: added source for {username} ({} recipient(s))",
        recipients.len()
    );
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
                "username={} url={} fingerprints={} refreshed={} status={} message={}",
                source.username,
                source.url,
                source.fingerprints.len(),
                source.last_refreshed_unix,
                source
                    .last_refresh_status_code
                    .as_deref()
                    .unwrap_or("unknown"),
                source.last_refresh_message.as_deref().unwrap_or("none")
            );
        } else {
            println!("{}", source.username);
        }
    }
    Ok(())
}

fn cmd_remove_github_user(username: &str, force: bool) -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;
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

    let would_remove = source
        .fingerprints
        .iter()
        .filter(|fingerprint| {
            !fingerprint_in_other_sources(&registry, fingerprint, Some(username), None)
        })
        .count();
    enforce_min_recipients(
        &manifest,
        recipients.len().saturating_sub(would_remove),
        "remove-github-user",
    )?;

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
    let github_options = github_fetch_options(&repo_root)?;
    let manifest = read_manifest(&repo_root)?;
    let mut registry = read_github_sources(&repo_root)?;
    let session_key = repo_key_from_session()?;
    let fetched_team = fetch_github_team_members_with_options(org, team, &github_options, None)?;
    let team_etag = fetched_team.metadata.etag.clone();
    let members = fetched_team.members;

    let mut fingerprints = std::collections::BTreeSet::new();
    for member in &members {
        let existing_fingerprints: std::collections::HashSet<String> = list_recipients(&repo_root)?
            .into_iter()
            .map(|recipient| recipient.fingerprint)
            .collect();
        let recipients =
            add_recipients_from_github_username_with_options(&repo_root, member, &github_options)?;
        enforce_allowed_key_types_for_added_recipients(
            &repo_root,
            &manifest,
            &existing_fingerprints,
            &recipients,
            "add-github-team",
        )?;
        if auto_wrap {
            if let Some(key) = session_key.as_deref() {
                for recipient in &recipients {
                    wrap_repo_key_for_recipient(&repo_root, recipient, key)?;
                }
            } else {
                println!(
                    "add-github-team: repository is locked; recipients were added but not wrapped (run unlock + rewrap)"
                );
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
        etag: team_etag,
        last_refresh_status_code: Some("ok".to_string()),
        last_refresh_message: Some("added source".to_string()),
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
            "{}/{} members={} fingerprints={} refreshed={} status={} message={}",
            source.org,
            source.team,
            source.member_usernames.len(),
            source.fingerprints.len(),
            source.last_refreshed_unix,
            source
                .last_refresh_status_code
                .as_deref()
                .unwrap_or("unknown"),
            source.last_refresh_message.as_deref().unwrap_or("none")
        );
    }
    Ok(())
}

fn cmd_remove_github_team(org: &str, team: &str) -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;
    let mut registry = read_github_sources(&repo_root)?;
    let Some(source) = registry
        .teams
        .iter()
        .find(|source| source.org == org && source.team == team)
        .cloned()
    else {
        anyhow::bail!("github team source not found: {org}/{team}");
    };

    let recipients = list_recipients(&repo_root)?;
    let would_remove = source
        .fingerprints
        .iter()
        .filter(|fingerprint| {
            !fingerprint_in_other_sources(&registry, fingerprint, None, Some((org, team)))
        })
        .count();
    enforce_min_recipients(
        &manifest,
        recipients.len().saturating_sub(would_remove),
        "remove-github-team",
    )?;

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

fn cmd_refresh_github_keys(
    username: Option<String>,
    dry_run: bool,
    fail_on_drift: bool,
    json: bool,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let github_options = github_fetch_options(&repo_root)?;
    let manifest = read_manifest(&repo_root)?;
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
    let mut drift_detected = false;
    let mut refresh_errors = Vec::new();

    for source in targets {
        let existing_fingerprints: std::collections::HashSet<String> = list_recipients(&repo_root)?
            .into_iter()
            .map(|recipient| recipient.fingerprint)
            .collect();
        let before_set: std::collections::HashSet<String> =
            source.fingerprints.iter().cloned().collect();
        let fetched_user = match fetch_github_user_keys_with_options(
            &source.username,
            &github_options,
            source.etag.as_deref(),
        ) {
            Ok(value) => value,
            Err(err) => {
                let code = classify_github_refresh_error(&err).to_string();
                let message = format!("{err:#}");
                if !dry_run
                    && let Some(entry) = registry
                        .users
                        .iter_mut()
                        .find(|entry| entry.username == source.username)
                {
                    entry.last_refresh_status_code = Some(code.clone());
                    entry.last_refresh_message = Some(message.clone());
                    entry.last_refreshed_unix = now_unix();
                }
                refresh_errors.push(format!("{}({}): {}", source.username, code, message));
                events.push(serde_json::json!({
                    "username": source.username,
                    "ok": false,
                    "error_code": code,
                    "error": message,
                    "dry_run": dry_run,
                }));
                continue;
            }
        };

        if fetched_user.metadata.not_modified {
            if !dry_run
                && let Some(entry) = registry
                    .users
                    .iter_mut()
                    .find(|entry| entry.username == source.username)
            {
                entry.last_refresh_status_code = Some("not_modified".to_string());
                entry.last_refresh_message = Some("source unchanged (etag)".to_string());
                entry.last_refreshed_unix = now_unix();
            }
            events.push(serde_json::json!({
                "username": source.username,
                "ok": true,
                "added": Vec::<String>::new(),
                "removed": Vec::<String>::new(),
                "unchanged": before_set.len(),
                "dry_run": dry_run,
                "backend": format!("{:?}", fetched_user.backend),
                "authenticated": fetched_user.authenticated,
                "auth_mode": github_auth_mode_label(fetched_user.auth_mode),
                "not_modified": true,
                "rate_limit_remaining": fetched_user.metadata.rate_limit_remaining,
                "rate_limit_reset_unix": fetched_user.metadata.rate_limit_reset_unix,
            }));
            continue;
        }

        let fetched = fetched_user
            .keys
            .iter()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                add_recipient_from_public_key(
                    &repo_root,
                    line,
                    RecipientSource::GithubKeys {
                        url: source.url.clone(),
                        username: Some(source.username.clone()),
                    },
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let after_set: std::collections::HashSet<String> = fetched
            .iter()
            .map(|recipient| recipient.fingerprint.clone())
            .collect();

        enforce_allowed_key_types_for_added_recipients(
            &repo_root,
            &manifest,
            &existing_fingerprints,
            &fetched,
            "refresh-github-keys",
        )?;

        let added: Vec<String> = after_set.difference(&before_set).cloned().collect();
        let removed: Vec<String> = before_set.difference(&after_set).cloned().collect();
        let unchanged = before_set.intersection(&after_set).count();
        if !added.is_empty() || !removed.is_empty() {
            drift_detected = true;
        }

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
            let current_count = list_recipients(&repo_root)?.len();
            enforce_min_recipients(
                &manifest,
                current_count.saturating_sub(safe_remove.len()),
                "refresh-github-keys",
            )?;
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
                entry.etag = fetched_user.metadata.etag.clone();
                entry.last_refresh_status_code = Some("ok".to_string());
                entry.last_refresh_message = Some("refresh succeeded".to_string());
            }
        }

        events.push(serde_json::json!({
            "username": source.username,
            "ok": true,
            "added": added,
            "removed": removed,
            "unchanged": unchanged,
            "dry_run": dry_run,
            "backend": format!("{:?}", fetched_user.backend),
            "authenticated": fetched_user.authenticated,
            "auth_mode": github_auth_mode_label(fetched_user.auth_mode),
            "not_modified": false,
            "rate_limit_remaining": fetched_user.metadata.rate_limit_remaining,
            "rate_limit_reset_unix": fetched_user.metadata.rate_limit_reset_unix,
        }));
    }

    if !dry_run {
        write_github_sources(&repo_root, &registry)?;
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "events": events,
                "drift_detected": drift_detected,
            }))?
        );
    } else {
        for event in events {
            println!("refresh-github-keys: {}", event);
        }
    }

    if fail_on_drift && drift_detected {
        anyhow::bail!("refresh-github-keys detected access drift");
    }

    if !refresh_errors.is_empty() {
        anyhow::bail!(
            "refresh-github-keys failed for {} source(s): {}",
            refresh_errors.len(),
            refresh_errors.join(" | ")
        );
    }

    Ok(())
}

fn cmd_refresh_github_teams(
    org: Option<String>,
    team: Option<String>,
    dry_run: bool,
    fail_on_drift: bool,
    json: bool,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let github_options = github_fetch_options(&repo_root)?;
    let manifest = read_manifest(&repo_root)?;
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
    let mut drift_detected = false;
    let mut refresh_errors = Vec::new();

    for source in targets {
        let fetched_team = match fetch_github_team_members_with_options(
            &source.org,
            &source.team,
            &github_options,
            source.etag.as_deref(),
        ) {
            Ok(value) => value,
            Err(err) => {
                let code = classify_github_refresh_error(&err).to_string();
                let message = format!("{err:#}");
                if !dry_run
                    && let Some(entry) = registry
                        .teams
                        .iter_mut()
                        .find(|entry| entry.org == source.org && entry.team == source.team)
                {
                    entry.last_refresh_status_code = Some(code.clone());
                    entry.last_refresh_message = Some(message.clone());
                    entry.last_refreshed_unix = now_unix();
                }
                refresh_errors.push(format!(
                    "{}/{}({}): {}",
                    source.org, source.team, code, message
                ));
                events.push(serde_json::json!({
                    "org": source.org,
                    "team": source.team,
                    "ok": false,
                    "error_code": code,
                    "error": message,
                    "dry_run": dry_run,
                }));
                continue;
            }
        };
        let fetched_team_metadata = fetched_team.metadata.clone();
        let fetched_team_auth_mode = fetched_team.auth_mode;
        let members = fetched_team.members;
        let backend = fetched_team.backend;
        let authenticated = fetched_team.authenticated;
        let mut fetched_fingerprints = std::collections::HashSet::new();

        let before_set: std::collections::HashSet<String> =
            source.fingerprints.iter().cloned().collect();
        if fetched_team_metadata.not_modified {
            if !dry_run
                && let Some(entry) = registry
                    .teams
                    .iter_mut()
                    .find(|entry| entry.org == source.org && entry.team == source.team)
            {
                entry.last_refresh_status_code = Some("not_modified".to_string());
                entry.last_refresh_message = Some("source unchanged (etag)".to_string());
                entry.last_refreshed_unix = now_unix();
            }
            events.push(serde_json::json!({
                "org": source.org,
                "team": source.team,
                "ok": true,
                "added": Vec::<String>::new(),
                "removed": Vec::<String>::new(),
                "unchanged": before_set.len(),
                "dry_run": dry_run,
                "backend": format!("{:?}", backend),
                "authenticated": authenticated,
                "auth_mode": github_auth_mode_label(fetched_team_auth_mode),
                "not_modified": true,
                "rate_limit_remaining": fetched_team_metadata.rate_limit_remaining,
                "rate_limit_reset_unix": fetched_team_metadata.rate_limit_reset_unix,
            }));
            continue;
        }

        for member in &members {
            let existing_fingerprints: std::collections::HashSet<String> =
                list_recipients(&repo_root)?
                    .into_iter()
                    .map(|recipient| recipient.fingerprint)
                    .collect();
            let imported = add_recipients_from_github_username_with_options(
                &repo_root,
                member,
                &github_options,
            )?;
            enforce_allowed_key_types_for_added_recipients(
                &repo_root,
                &manifest,
                &existing_fingerprints,
                &imported,
                "refresh-github-teams",
            )?;
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

        let added: Vec<String> = fetched_fingerprints
            .difference(&before_set)
            .cloned()
            .collect();
        let removed: Vec<String> = before_set
            .difference(&fetched_fingerprints)
            .cloned()
            .collect();
        let unchanged = before_set.intersection(&fetched_fingerprints).count();
        if !added.is_empty() || !removed.is_empty() {
            drift_detected = true;
        }

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
            let current_count = list_recipients(&repo_root)?.len();
            enforce_min_recipients(
                &manifest,
                current_count.saturating_sub(safe_remove.len()),
                "refresh-github-teams",
            )?;
            let _ = remove_recipients_by_fingerprints(&repo_root, &safe_remove)?;

            if let Some(entry) = registry
                .teams
                .iter_mut()
                .find(|entry| entry.org == source.org && entry.team == source.team)
            {
                entry.member_usernames = members;
                entry.fingerprints = fetched_fingerprints.iter().cloned().collect();
                entry.last_refreshed_unix = now_unix();
                entry.etag = fetched_team_metadata.etag.clone();
                entry.last_refresh_status_code = Some("ok".to_string());
                entry.last_refresh_message = Some("refresh succeeded".to_string());
            }
        }

        events.push(serde_json::json!({
            "org": source.org,
            "team": source.team,
            "ok": true,
            "added": added,
            "removed": removed,
            "unchanged": unchanged,
            "dry_run": dry_run,
            "backend": format!("{:?}", backend),
            "authenticated": authenticated,
            "auth_mode": github_auth_mode_label(fetched_team_auth_mode),
            "not_modified": false,
            "rate_limit_remaining": fetched_team_metadata.rate_limit_remaining,
            "rate_limit_reset_unix": fetched_team_metadata.rate_limit_reset_unix,
        }));
    }

    if !dry_run {
        write_github_sources(&repo_root, &registry)?;
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "events": events,
                "drift_detected": drift_detected,
            }))?
        );
    } else {
        for event in events {
            println!("refresh-github-teams: {}", event);
        }
    }

    if fail_on_drift && drift_detected {
        anyhow::bail!("refresh-github-teams detected access drift");
    }

    if !refresh_errors.is_empty() {
        anyhow::bail!(
            "refresh-github-teams failed for {} source(s): {}",
            refresh_errors.len(),
            refresh_errors.join(" | ")
        );
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
        let can = unwrap_repo_key_from_wrapped_files(
            &[wrapped],
            &identities,
            &std::collections::HashSet::new(),
        )?
        .is_some();
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
    let _manifest = read_manifest(&repo_root)?;
    install_git_filters(&repo_root, &current_bin_path())?;
    println!("install: refreshed git filter configuration");
    Ok(())
}

fn cmd_config(command: ConfigCommand) -> Result<()> {
    let repo_root = current_repo_root()?;
    match command {
        ConfigCommand::SetAgentHelper { path } => {
            let helper = PathBuf::from(&path);
            if !is_executable(&helper) {
                anyhow::bail!("agent helper path is not executable: {}", helper.display());
            }
            let mut cfg: RepositoryLocalConfig = read_local_config(&repo_root)?;
            cfg.agent_helper = Some(path);
            write_local_config(&repo_root, &cfg)?;
            println!("config: set agent helper to {}", helper.display());
            Ok(())
        }
        ConfigCommand::SetGithubApiBase { url } => {
            let mut cfg: RepositoryLocalConfig = read_local_config(&repo_root)?;
            cfg.github_api_base = Some(url.trim_end_matches('/').to_string());
            write_local_config(&repo_root, &cfg)?;
            println!(
                "config: set github api base to {}",
                cfg.github_api_base.as_deref().unwrap_or_default()
            );
            Ok(())
        }
        ConfigCommand::SetGithubWebBase { url } => {
            let mut cfg: RepositoryLocalConfig = read_local_config(&repo_root)?;
            cfg.github_web_base = Some(url.trim_end_matches('/').to_string());
            write_local_config(&repo_root, &cfg)?;
            println!(
                "config: set github web base to {}",
                cfg.github_web_base.as_deref().unwrap_or_default()
            );
            Ok(())
        }
        ConfigCommand::SetGithubAuthMode { mode } => {
            let normalized = mode.trim().to_ascii_lowercase();
            let _ = parse_github_auth_mode(&normalized)?;
            let mut cfg: RepositoryLocalConfig = read_local_config(&repo_root)?;
            cfg.github_auth_mode = Some(normalized.clone());
            write_local_config(&repo_root, &cfg)?;
            println!("config: set github auth mode to {normalized}");
            Ok(())
        }
        ConfigCommand::SetGithubPrivateSourceHardFail { enabled } => {
            let enabled = match enabled.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                other => anyhow::bail!(
                    "invalid boolean value '{other}' for set-github-private-source-hard-fail"
                ),
            };
            let mut cfg: RepositoryLocalConfig = read_local_config(&repo_root)?;
            cfg.github_private_source_hard_fail = Some(enabled);
            write_local_config(&repo_root, &cfg)?;
            println!("config: set github private-source hard-fail to {enabled}");
            Ok(())
        }
        ConfigCommand::Show => {
            let cfg: RepositoryLocalConfig = read_local_config(&repo_root)?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
            Ok(())
        }
    }
}

fn cmd_policy(command: PolicyCommand) -> Result<()> {
    let repo_root = current_repo_root()?;
    match command {
        PolicyCommand::Show { json } => {
            let manifest = read_manifest(&repo_root)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            } else {
                println!("policy: min_recipients {}", manifest.min_recipients);
                println!(
                    "policy: allowed_key_types {}",
                    manifest.allowed_key_types.join(", ")
                );
                println!(
                    "policy: require_doctor_clean_for_rotate {}",
                    manifest.require_doctor_clean_for_rotate
                );
                println!(
                    "policy: require_verify_strict_clean_for_rotate_revoke {}",
                    manifest.require_verify_strict_clean_for_rotate_revoke
                );
                println!(
                    "policy: max_source_staleness_hours {}",
                    manifest
                        .max_source_staleness_hours
                        .map_or_else(|| "none".to_string(), |v| v.to_string())
                );
            }
            Ok(())
        }
        PolicyCommand::Verify { json } => {
            let manifest = read_manifest(&repo_root)?;
            let common_dir = current_common_dir()?;
            let failures = collect_doctor_failures(&repo_root, &common_dir, &manifest)?;
            let ok = failures.is_empty();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": ok,
                        "failures": failures,
                    }))?
                );
            } else if ok {
                println!("policy verify: OK");
            } else {
                println!("policy verify: FAIL ({})", failures.len());
                for failure in &failures {
                    eprintln!("- {failure}");
                }
            }
            if ok {
                Ok(())
            } else {
                anyhow::bail!("policy verification failed")
            }
        }
        PolicyCommand::Set {
            min_recipients,
            allow_key_types,
            require_doctor_clean_for_rotate,
            require_verify_strict_clean_for_rotate_revoke,
            max_source_staleness_hours,
        } => {
            let mut manifest = read_manifest(&repo_root)?;
            if let Some(min) = min_recipients {
                manifest.min_recipients = min;
            }
            if !allow_key_types.is_empty() {
                manifest.allowed_key_types = allow_key_types;
            }
            if let Some(required) = require_doctor_clean_for_rotate {
                manifest.require_doctor_clean_for_rotate = required;
            }
            if let Some(required) = require_verify_strict_clean_for_rotate_revoke {
                manifest.require_verify_strict_clean_for_rotate_revoke = required;
            }
            if let Some(hours) = max_source_staleness_hours {
                if hours == 0 {
                    anyhow::bail!("policy set rejected: max_source_staleness_hours must be > 0");
                }
                manifest.max_source_staleness_hours = Some(hours);
            }
            if manifest.min_recipients == 0 {
                anyhow::bail!("policy set rejected: min_recipients must be at least 1");
            }
            if manifest.allowed_key_types.is_empty() {
                anyhow::bail!("policy set rejected: allowed_key_types cannot be empty");
            }
            write_manifest(&repo_root, &manifest)?;
            println!("policy set: updated manifest policy");
            Ok(())
        }
    }
}

#[derive(Debug)]
struct GitattributesMigrationPlan {
    rewritten_text: String,
    patterns: Vec<String>,
    legacy_lines_found: usize,
    legacy_lines_replaced: usize,
    duplicate_lines_removed: usize,
    rewritable_lines: usize,
    ambiguous_lines: Vec<String>,
    manual_intervention_lines: Vec<String>,
    idempotent_rewrite: bool,
}

fn build_gitattributes_migration_plan(text: &str) -> GitattributesMigrationPlan {
    let mut output_lines = Vec::new();
    let mut seen_lines = std::collections::HashSet::new();
    let mut patterns = std::collections::BTreeSet::new();
    let mut legacy_lines_found = 0usize;
    let mut legacy_lines_replaced = 0usize;
    let mut duplicate_lines_removed = 0usize;
    let mut rewritable_lines = 0usize;
    let mut ambiguous_lines = Vec::new();
    let mut manual_intervention_lines = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            output_lines.push(line.to_string());
            continue;
        }

        let Some(pattern) = trimmed.split_whitespace().next().filter(|p| !p.is_empty()) else {
            output_lines.push(line.to_string());
            continue;
        };

        if trimmed.contains("filter=git-crypt") {
            legacy_lines_found += 1;
            let mut tokens = trimmed.split_whitespace();
            let _ = tokens.next();
            let attrs: Vec<&str> = tokens.collect();
            let non_standard_attrs = attrs
                .iter()
                .filter(|attr| {
                    !attr.starts_with("filter=")
                        && !attr.starts_with("diff=")
                        && !attr.starts_with("text")
                })
                .count();
            if non_standard_attrs > 0 {
                ambiguous_lines.push(trimmed.to_string());
            } else {
                rewritable_lines += 1;
            }

            legacy_lines_replaced += 1;
            patterns.insert(pattern.to_string());
            let normalized = format!("{pattern} filter=git-sshripped diff=git-sshripped");
            if seen_lines.insert(normalized.clone()) {
                output_lines.push(normalized);
            } else {
                duplicate_lines_removed += 1;
            }
            continue;
        }

        if trimmed.contains("filter=git-sshripped") {
            patterns.insert(pattern.to_string());
            if seen_lines.insert(trimmed.to_string()) {
                output_lines.push(trimmed.to_string());
            } else {
                duplicate_lines_removed += 1;
            }
            continue;
        }

        if trimmed.contains("!filter") || trimmed.contains("!diff") {
            patterns.insert(format!("!{pattern}"));
            output_lines.push(line.to_string());
            continue;
        }

        if trimmed.contains("git-crypt") {
            manual_intervention_lines.push(trimmed.to_string());
        }
        output_lines.push(line.to_string());
    }

    let mut rewritten_text = output_lines.join("\n");
    if !rewritten_text.ends_with('\n') {
        rewritten_text.push('\n');
    }
    let idempotent_rewrite = rewritten_text == text;

    GitattributesMigrationPlan {
        rewritten_text,
        patterns: patterns.into_iter().collect(),
        legacy_lines_found,
        legacy_lines_replaced,
        duplicate_lines_removed,
        rewritable_lines,
        ambiguous_lines,
        manual_intervention_lines,
        idempotent_rewrite,
    }
}

fn cmd_migrate_from_git_crypt(
    dry_run: bool,
    reencrypt: bool,
    verify: bool,
    json: bool,
    write_report: Option<String>,
) -> Result<()> {
    let repo_root = current_repo_root()?;
    let manifest_policy = read_manifest(&repo_root).unwrap_or_default();
    enforce_existing_recipient_policy(&repo_root, &manifest_policy, "migrate-from-git-crypt")?;
    let path = repo_root.join(".gitattributes");
    let text =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;

    let plan = build_gitattributes_migration_plan(&text);
    if plan.patterns.is_empty() {
        let payload = serde_json::json!({
            "ok": true,
            "dry_run": dry_run,
            "noop": true,
            "reason": "no git-crypt or git-sshripped patterns found",
            "migration_analysis": {
                "rewritable_lines": plan.rewritable_lines,
                "ambiguous": plan.ambiguous_lines,
                "manual_intervention": plan.manual_intervention_lines,
                "idempotent_rewrite": plan.idempotent_rewrite,
            }
        });
        if json {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            println!("migrate-from-git-crypt: no matching patterns found; nothing to do");
        }
        return Ok(());
    }

    let mut manifest_before = read_manifest(&repo_root).unwrap_or_default();
    if let Some(key) = repo_key_from_session().ok().flatten() {
        manifest_before.repo_key_id = Some(repo_key_id_from_bytes(&key));
    }
    let manifest_after = manifest_before;

    let imported_patterns = plan.patterns.len();
    let changed_patterns = true;

    if !dry_run {
        fs::write(&path, &plan.rewritten_text)
            .with_context(|| format!("failed to rewrite {}", path.display()))?;
        write_manifest(&repo_root, &manifest_after)?;
        install_gitattributes(
            &repo_root,
            &plan.patterns.iter().cloned().collect::<Vec<_>>(),
        )?;
        install_git_filters(&repo_root, &current_bin_path())?;
    }

    let mut reencrypted_files = 0usize;
    if reencrypt {
        if dry_run {
            reencrypted_files = protected_tracked_files(&repo_root)?.len();
        } else {
            reencrypted_files = reencrypt_with_current_session(&repo_root)?;
        }
    }

    let mut verify_failures_list = Vec::new();
    if verify {
        verify_failures_list = verify_failures(&repo_root)?;
        if !verify_failures_list.is_empty() && !dry_run {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "dry_run": dry_run,
                        "verify_failures": verify_failures_list,
                    }))?
                );
            } else {
                println!("migrate-from-git-crypt: verify failed");
                for failure in &verify_failures_list {
                    eprintln!("- {failure}");
                }
            }
            anyhow::bail!("migration verification failed");
        }
    }

    let mut report = serde_json::json!({
        "ok": true,
        "dry_run": dry_run,
        "gitattributes": {
            "legacy_lines_found": plan.legacy_lines_found,
            "legacy_lines_replaced": plan.legacy_lines_replaced,
            "duplicate_lines_removed": plan.duplicate_lines_removed,
        },
        "migration_analysis": {
            "rewritable_lines": plan.rewritable_lines,
            "ambiguous": plan.ambiguous_lines,
            "manual_intervention": plan.manual_intervention_lines,
            "idempotent_rewrite": plan.idempotent_rewrite,
        },
        "imported_patterns": imported_patterns,
        "changed_patterns": changed_patterns,
        "repo_key_id": manifest_after.repo_key_id,
        "reencrypt_requested": reencrypt,
        "reencrypted_files": reencrypted_files,
        "verify_requested": verify,
        "verify_failures": if dry_run { vec![] } else { verify_failures_list.clone() },
        "files_requiring_reencrypt": if dry_run { verify_failures_list.clone() } else { vec![] },
    });

    if let Some(path) = write_report {
        let report_text = format!("{}\n", serde_json::to_string_pretty(&report)?);
        fs::write(&path, report_text)
            .with_context(|| format!("failed to write migration report {path}"))?;
        if let Some(object) = report.as_object_mut() {
            object.insert("report_written_to".to_string(), serde_json::json!(path));
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "migrate-from-git-crypt: patterns={} changed={} legacy_replaced={} duplicates_removed={} rewritable={} ambiguous={} manual={} dry_run={} reencrypted={} verify={}",
            imported_patterns,
            changed_patterns,
            plan.legacy_lines_replaced,
            plan.duplicate_lines_removed,
            plan.rewritable_lines,
            plan.ambiguous_lines.len(),
            plan.manual_intervention_lines.len(),
            dry_run,
            reencrypted_files,
            verify
        );
    }

    Ok(())
}

fn cmd_export_repo_key(out: &str) -> Result<()> {
    let Some(key) = repo_key_from_session()? else {
        anyhow::bail!("repository is locked; run `git-sshripped unlock` first");
    };
    let encoded = hex::encode(key);
    fs::write(out, format!("{encoded}\n")).with_context(|| format!("failed to write {out}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(out)
            .with_context(|| format!("failed to read metadata for {out}"))?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(out, perms)
            .with_context(|| format!("failed to set secure permissions on {out}"))?;
    }

    println!("export-repo-key: wrote key material to {out}");
    Ok(())
}

fn cmd_import_repo_key(input: &str) -> Result<()> {
    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;
    let mut manifest = read_manifest(&repo_root)?;
    enforce_existing_recipient_policy(&repo_root, &manifest, "import-repo-key")?;
    let text = fs::read_to_string(input).with_context(|| format!("failed to read {input}"))?;
    let key = hex::decode(text.trim()).context("import key file must contain hex key bytes")?;
    if key.len() != 32 {
        anyhow::bail!("imported key length must be 32 bytes, got {}", key.len());
    }

    let key_id = repo_key_id_from_bytes(&key);
    manifest.repo_key_id = Some(key_id.clone());
    write_manifest(&repo_root, &manifest)?;

    let wrapped = wrap_repo_key_for_all_recipients(&repo_root, &key)?;
    write_unlock_session(&common_dir, &key, "import", Some(key_id))?;
    println!(
        "import-repo-key: imported key and wrapped for {} recipients",
        wrapped.len()
    );
    Ok(())
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

fn git_changed_paths(
    repo_root: &std::path::Path,
    paths: &[String],
    cached: bool,
) -> Result<std::collections::BTreeSet<String>> {
    if paths.is_empty() {
        return Ok(std::collections::BTreeSet::new());
    }

    let mut dirty = std::collections::BTreeSet::new();
    const CHUNK: usize = 100;

    for chunk in paths.chunks(CHUNK) {
        let mut args = vec!["diff".to_string(), "--name-only".to_string()];
        if cached {
            args.push("--cached".to_string());
        }
        args.push("--".to_string());
        args.extend(chunk.iter().cloned());

        let output = std::process::Command::new("git")
            .current_dir(repo_root)
            .args(args)
            .output()
            .context("failed to run git diff --name-only")?;

        if !output.status.success() {
            anyhow::bail!(
                "git diff --name-only failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let text = String::from_utf8(output.stdout).context("git diff output is not utf8")?;
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            dirty.insert(line.to_string());
        }
    }

    Ok(dirty)
}

fn protected_dirty_paths(
    repo_root: &std::path::Path,
    protected: &[String],
) -> Result<std::collections::BTreeSet<String>> {
    let mut dirty = git_changed_paths(repo_root, protected, false)?;
    dirty.extend(git_changed_paths(repo_root, protected, true)?);
    Ok(dirty)
}

fn scrub_protected_paths(repo_root: &std::path::Path, protected: &[String]) -> Result<()> {
    for path in protected {
        let blob = git_show_index_path(repo_root, path)
            .with_context(|| format!("failed reading index blob for protected path {path}"))?;
        let full_path = repo_root.join(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating parent dir {}", parent.display()))?;
        }
        fs::write(&full_path, blob).with_context(|| {
            format!(
                "failed writing scrubbed protected file {}",
                full_path.display()
            )
        })?;
    }

    Ok(())
}

fn read_gitattributes_patterns(repo_root: &std::path::Path) -> Vec<String> {
    let path = repo_root.join(".gitattributes");
    let Ok(text) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut patterns = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains("filter=git-sshripped") {
            if let Some(pattern) = trimmed.split_whitespace().next() {
                patterns.push(pattern.to_string());
            }
        } else if trimmed.contains("!filter") || trimmed.contains("!diff") {
            if let Some(pattern) = trimmed.split_whitespace().next() {
                patterns.push(format!("!{pattern}"));
            }
        }
    }
    patterns
}

fn protected_tracked_files(repo_root: &std::path::Path) -> Result<Vec<String>> {
    // Fast path: if .gitattributes has no filter=git-sshripped patterns, there are no
    // protected files.  This avoids piping every tracked file (potentially thousands)
    // through git check-attr.
    let attr_patterns = read_gitattributes_patterns(repo_root);
    let positive_patterns: Vec<&str> = attr_patterns
        .iter()
        .filter(|p| !p.starts_with('!'))
        .map(String::as_str)
        .collect();
    if positive_patterns.is_empty() {
        return Ok(Vec::new());
    }

    // Scope git ls-files to only the gitattributes patterns so we avoid listing the
    // entire repository.
    let mut cmd = std::process::Command::new("git");
    cmd.current_dir(repo_root).args(["ls-files", "-z", "--"]);
    for pattern in &positive_patterns {
        cmd.arg(pattern);
    }
    let ls_output = cmd.output().context("failed to run git ls-files")?;
    if !ls_output.status.success() {
        anyhow::bail!("git ls-files failed");
    }

    let mut files = Vec::new();
    for raw in ls_output.stdout.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let path = String::from_utf8(raw.to_vec()).context("non-utf8 path from git ls-files")?;
        files.push(path);
    }

    if files.is_empty() {
        return Ok(Vec::new());
    }

    let mut child = std::process::Command::new("git")
        .current_dir(repo_root)
        .args(["check-attr", "-z", "--stdin", "filter"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn git check-attr")?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open check-attr stdin")?;
        for path in &files {
            std::io::Write::write_all(stdin, path.as_bytes())?;
            std::io::Write::write_all(stdin, b"\0")?;
        }
    }

    let output = child.wait_with_output().context("git check-attr failed")?;
    if !output.status.success() {
        anyhow::bail!("git check-attr exited non-zero");
    }

    let mut protected = Vec::new();
    let fields: Vec<&[u8]> = output.stdout.split(|b| *b == 0).collect();
    let mut i = 0;
    while i + 2 < fields.len() {
        let path = std::str::from_utf8(fields[i]).context("non-utf8 path from check-attr")?;
        let value =
            std::str::from_utf8(fields[i + 2]).context("non-utf8 attr value from check-attr")?;
        if value == "git-sshripped" {
            protected.push(path.to_string());
        }
        i += 3;
    }

    Ok(protected)
}

fn verify_failures(repo_root: &std::path::Path) -> Result<Vec<String>> {
    let files = protected_tracked_files(repo_root)?;
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

    let failures = verify_failures(&repo_root)?;

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
        let process_cfg = git_local_config(&repo_root, "filter.git-sshripped.process")?;
        let required_cfg = git_local_config(&repo_root, "filter.git-sshripped.required")?;
        if process_cfg.is_none() || required_cfg.as_deref() != Some("true") {
            anyhow::bail!(
                "strict verify failed: filter.git-sshripped.process and required=true must be configured"
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
        anyhow::bail!("repository is locked; run `git-sshripped unlock` first");
    };
    let wrapped = wrap_repo_key_for_all_recipients(&repo_root, &key)?;
    println!("rewrapped repository key for {} recipients", wrapped.len());
    Ok(())
}

fn reencrypt_with_current_session(repo_root: &std::path::Path) -> Result<usize> {
    if repo_key_from_session()?.is_none() {
        anyhow::bail!("repository is locked; run `git-sshripped unlock` first");
    }

    let protected = protected_tracked_files(repo_root)?;
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

    let refreshed = reencrypt_with_current_session(&repo_root)?;
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
        anyhow::bail!("repository is locked; run `git-sshripped unlock` first");
    };
    let previous_key_id = repo_key_id_from_bytes(&previous_key);
    let mut manifest = read_manifest(&repo_root)?;

    if manifest.require_doctor_clean_for_rotate {
        let failures = collect_doctor_failures(&repo_root, &common_dir, &manifest)?;
        if !failures.is_empty() {
            anyhow::bail!(
                "rotate-key blocked by manifest policy require_doctor_clean_for_rotate=true; run `git-sshripped doctor` and fix: {}",
                failures.join("; ")
            );
        }
    }
    enforce_verify_clean_for_sensitive_actions(&repo_root, &manifest, "rotate-key")?;

    let recipients = list_recipients(&repo_root)?;
    if recipients.is_empty() {
        anyhow::bail!("no recipients configured; cannot rotate repository key");
    }

    let wrapped_snapshot = snapshot_wrapped_files(&repo_root)?;

    let mut key = [0_u8; 32];
    rand::rng().fill_bytes(&mut key);
    let key_id = repo_key_id_from_bytes(&key);
    let wrapped = match wrap_repo_key_for_all_recipients(&repo_root, &key) {
        Ok(wrapped) => wrapped,
        Err(err) => {
            restore_wrapped_files(&repo_root, &wrapped_snapshot)?;
            anyhow::bail!(
                "rotate-key failed while wrapping new key; previous wrapped files restored: {err:#}"
            );
        }
    };

    manifest.repo_key_id = Some(key_id.clone());
    if let Err(err) = write_manifest(&repo_root, &manifest) {
        restore_wrapped_files(&repo_root, &wrapped_snapshot)?;
        anyhow::bail!(
            "rotate-key failed while writing updated manifest; previous wrapped files restored: {err:#}"
        );
    }

    write_unlock_session(&common_dir, &key, "rotated", Some(key_id.clone()))?;

    println!(
        "rotate-key: generated new repository key and wrapped for {} recipients",
        wrapped.len()
    );
    if auto_reencrypt {
        match reencrypt_with_current_session(&repo_root) {
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
                if let Err(rollback_session_err) = write_unlock_session(
                    &common_dir,
                    &previous_key,
                    "rollback",
                    Some(previous_key_id.clone()),
                ) {
                    rollback_errors
                        .push(format!("session rollback failed: {rollback_session_err:#}"));
                }
                manifest.repo_key_id = Some(previous_key_id.clone());
                if let Err(manifest_rollback_err) = write_manifest(&repo_root, &manifest) {
                    rollback_errors.push(format!(
                        "manifest rollback failed: {manifest_rollback_err:#}"
                    ));
                }
                if rollback_errors.is_empty() {
                    if let Err(restore_err) = reencrypt_with_current_session(&repo_root) {
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
        println!("rotate-key: run `git-sshripped reencrypt` and commit to complete rotation");
    }

    Ok(())
}

fn repo_key_from_session_in(
    common_dir: &std::path::Path,
    manifest: Option<&RepositoryManifest>,
) -> Result<Option<Vec<u8>>> {
    let maybe_session = read_unlock_session(common_dir)?;
    let Some(session) = maybe_session else {
        return Ok(None);
    };
    let key = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(session.key_b64)
        .context("invalid session key encoding")?;
    if key.len() != 32 {
        anyhow::bail!("unlock session key length is {}, expected 32", key.len());
    }

    if let Some(manifest) = manifest
        && let Some(expected) = &manifest.repo_key_id
    {
        let actual = repo_key_id_from_bytes(&key);
        if &actual != expected {
            anyhow::bail!(
                "unlock session key does not match this worktree manifest (expected repo_key_id {}, got {}); run `git-sshripped unlock`",
                expected,
                actual
            );
        }
    }

    Ok(Some(key))
}

fn repo_key_from_session() -> Result<Option<Vec<u8>>> {
    let repo_root = current_repo_root()?;
    let manifest = read_manifest(&repo_root)?;
    let common_dir = current_common_dir()?;
    repo_key_from_session_in(&common_dir, Some(&manifest))
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

    if manifest.min_recipients == 0 {
        failures.push("manifest min_recipients must be at least 1".to_string());
    }
    if manifest.allowed_key_types.is_empty() {
        failures.push("manifest allowed_key_types cannot be empty".to_string());
    }

    let process_cfg = git_local_config(&repo_root, "filter.git-sshripped.process")?;
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
        failures.push("filter.git-sshripped.process is missing or invalid".to_string());
    }

    let required_cfg = git_local_config(&repo_root, "filter.git-sshripped.required")?;
    if required_cfg.as_deref() == Some("true") {
        if !json {
            println!("check filter.required: PASS");
        }
    } else {
        if !json {
            println!("check filter.required: FAIL");
        }
        failures.push("filter.git-sshripped.required should be true".to_string());
    }

    let gitattributes = repo_root.join(".gitattributes");
    match fs::read_to_string(&gitattributes) {
        Ok(text) if text.contains("filter=git-sshripped") => {
            if !json {
                println!("check gitattributes wiring: PASS");
            }
        }
        Ok(_) => {
            if !json {
                println!("check gitattributes wiring: FAIL");
            }
            failures.push(".gitattributes has no filter=git-sshripped entries".to_string());
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
        let allowed_types = allowed_key_types_set(&manifest);
        for recipient in &recipients {
            if !allowed_types.contains(recipient.key_type.as_str()) {
                failures.push(format!(
                    "recipient {} uses disallowed key type {}",
                    recipient.fingerprint, recipient.key_type
                ));
            }
        }
    }
    if recipients.len() < manifest.min_recipients {
        failures.push(format!(
            "recipient count {} is below manifest min_recipients {}",
            recipients.len(),
            manifest.min_recipients
        ));
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

    let helper = resolve_agent_helper(&repo_root)?;
    if !json {
        match &helper {
            Some((path, source)) => {
                println!(
                    "check agent helper: PASS ({} from {})",
                    path.display(),
                    source
                );
            }
            None => {
                println!("check agent helper: PASS (none detected)");
            }
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

        if let Some(expected) = &manifest.repo_key_id {
            let actual = repo_key_id_from_bytes(&decoded);
            if &actual != expected {
                failures.push(format!(
                    "unlock session repo key mismatch: expected {}, got {}",
                    expected, actual
                ));
            }
            if session.repo_key_id.as_deref() != Some(expected.as_str()) {
                failures.push(format!(
                    "unlock session metadata repo_key_id mismatch: expected {}, got {}",
                    expected,
                    session.repo_key_id.as_deref().unwrap_or("missing")
                ));
            }
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
                "repo_key_id": manifest.repo_key_id,
            "protected_patterns": read_gitattributes_patterns(&repo_root),
                "min_recipients": manifest.min_recipients,
                "allowed_key_types": manifest.allowed_key_types,
                "require_doctor_clean_for_rotate": manifest.require_doctor_clean_for_rotate,
                "require_verify_strict_clean_for_rotate_revoke": manifest.require_verify_strict_clean_for_rotate_revoke,
                "max_source_staleness_hours": manifest.max_source_staleness_hours,
                "agent_helper_resolved": helper.as_ref().map(|(path, _)| path.display().to_string()),
                "agent_helper_source": helper.as_ref().map(|(_, source)| source.clone()),
                "failures": failures,
            }))?
        );
    } else {
        println!("doctor: algorithm {:?}", manifest.encryption_algorithm);
        println!("doctor: strict_mode {}", manifest.strict_mode);
        println!(
            "doctor: repo_key_id {}",
            manifest.repo_key_id.as_deref().unwrap_or("missing")
        );
        println!(
            "doctor: protected patterns {}",
            read_gitattributes_patterns(&repo_root).join(", ")
        );
        println!("doctor: min_recipients {}", manifest.min_recipients);
        println!(
            "doctor: allowed_key_types {}",
            manifest.allowed_key_types.join(", ")
        );
        println!(
            "doctor: require_doctor_clean_for_rotate {}",
            manifest.require_doctor_clean_for_rotate
        );
        println!(
            "doctor: require_verify_strict_clean_for_rotate_revoke {}",
            manifest.require_verify_strict_clean_for_rotate_revoke
        );
        println!(
            "doctor: max_source_staleness_hours {}",
            manifest
                .max_source_staleness_hours
                .map_or_else(|| "none".to_string(), |v| v.to_string())
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
    let output = clean(manifest.encryption_algorithm, key.as_deref(), path, &input)?;
    write_stdout_all(&output)
}

fn cmd_smudge(path: &str) -> Result<()> {
    let key = repo_key_from_session()?;
    let input = read_stdin_all()?;
    let output = smudge(key.as_deref(), path, &input)?;
    write_stdout_all(&output)
}

fn cmd_diff(path: &str, file: Option<&str>) -> Result<()> {
    let key = repo_key_from_session()?;
    let input = if let Some(file_path) = file {
        fs::read(file_path)
            .with_context(|| format!("failed to read diff input file {file_path}"))?
    } else {
        read_stdin_all()?
    };
    let output = diff(key.as_deref(), path, &input)?;
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
            && common.join("HEAD").exists()
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
    let key = repo_key_from_session_in(common_dir, Some(&manifest))?;

    match command {
        "clean" => clean(
            manifest.encryption_algorithm,
            key.as_deref(),
            pathname,
            input,
        ),
        "smudge" => smudge(key.as_deref(), pathname, input),
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

/// Returns the "type base64" prefix of an SSH public key line, stripping the comment.
/// e.g. "ssh-ed25519 AAAA...abc user@host" → "ssh-ed25519 AAAA...abc"
fn ssh_key_prefix(key_line: &str) -> String {
    let parts: Vec<&str> = key_line.split_whitespace().collect();
    if parts.len() >= 2 {
        format!("{} {}", parts[0], parts[1])
    } else {
        key_line.trim().to_string()
    }
}

/// Reads all `.pub` files in `~/.ssh/` that have a matching private key file,
/// returning their contents as strings.
fn local_public_key_contents() -> Vec<String> {
    discover_ssh_key_files()
        .into_iter()
        .filter_map(|(_private, pub_path)| std::fs::read_to_string(&pub_path).ok())
        .flat_map(|contents| {
            contents
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .collect()
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

    #[test]
    fn gitattributes_migration_rewrites_git_crypt_lines() {
        let input = "# comment\nsecret.env filter=git-crypt diff=git-crypt\nsecret.env filter=git-crypt diff=git-crypt\nplain.txt text\n";
        let plan = build_gitattributes_migration_plan(input);
        assert_eq!(plan.legacy_lines_found, 2);
        assert_eq!(plan.legacy_lines_replaced, 2);
        assert_eq!(plan.duplicate_lines_removed, 1);
        assert_eq!(plan.rewritable_lines, 2);
        assert!(plan.ambiguous_lines.is_empty());
        assert!(
            plan.rewritten_text
                .contains("secret.env filter=git-sshripped diff=git-sshripped")
        );
        assert!(!plan.rewritten_text.contains("filter=git-crypt"));
        assert_eq!(plan.patterns, vec!["secret.env".to_string()]);
    }

    #[test]
    fn gitattributes_migration_classifies_ambiguous_lines() {
        let input = "secrets/** filter=git-crypt diff=git-crypt merge=binary\n";
        let plan = build_gitattributes_migration_plan(input);
        assert_eq!(plan.legacy_lines_found, 1);
        assert_eq!(plan.rewritable_lines, 0);
        assert_eq!(plan.ambiguous_lines.len(), 1);
    }

    #[test]
    fn gitattributes_migration_collects_negation_lines() {
        let input = "hosts/** filter=git-crypt diff=git-crypt\nhosts/meta.nix !filter !diff\n";
        let plan = build_gitattributes_migration_plan(input);
        assert_eq!(plan.legacy_lines_found, 1);
        assert_eq!(plan.legacy_lines_replaced, 1);
        assert!(plan.patterns.contains(&"hosts/**".to_string()));
        assert!(plan.patterns.contains(&"!hosts/meta.nix".to_string()));
        assert_eq!(plan.patterns.len(), 2);
        assert!(
            plan.rewritten_text
                .contains("hosts/** filter=git-sshripped diff=git-sshripped")
        );
        assert!(plan.rewritten_text.contains("hosts/meta.nix !filter !diff"));
    }

    #[test]
    fn gitattributes_migration_handles_only_diff_negation() {
        let input = "data/** filter=git-crypt diff=git-crypt\ndata/public.txt !diff\n";
        let plan = build_gitattributes_migration_plan(input);
        assert!(plan.patterns.contains(&"!data/public.txt".to_string()));
    }

    #[test]
    fn github_refresh_error_classification_works() {
        let auth = anyhow::anyhow!("request failed with status 401");
        let perm = anyhow::anyhow!("request failed with status 403");
        let rate = anyhow::anyhow!("request failed with status 429");
        assert_eq!(classify_github_refresh_error(&auth), "auth_missing");
        assert_eq!(classify_github_refresh_error(&perm), "permission_denied");
        assert_eq!(classify_github_refresh_error(&rate), "rate_limited");
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
