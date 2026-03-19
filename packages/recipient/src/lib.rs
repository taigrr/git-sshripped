#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::fs;
use std::io::Write;
use std::iter;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use age::Encryptor;
use age::ssh::Recipient as SshRecipient;
use anyhow::{Context, Result, bail};
use base64::Engine;
use git_sshripped_recipient_models::{RecipientKey, RecipientSource};
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH, USER_AGENT};
use sha2::{Digest, Sha256};

const SUPPORTED_KEY_TYPES: [&str; 2] = ["ssh-ed25519", "ssh-rsa"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubBackend {
    Gh,
    Rest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubAuthMode {
    Auto,
    Gh,
    Token,
    Anonymous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubFetchOptions {
    pub api_base_url: String,
    pub web_base_url: String,
    pub auth_mode: GithubAuthMode,
    pub private_source_hard_fail: bool,
}

impl Default for GithubFetchOptions {
    fn default() -> Self {
        Self {
            api_base_url: "https://api.github.com".to_string(),
            web_base_url: "https://github.com".to_string(),
            auth_mode: GithubAuthMode::Auto,
            private_source_hard_fail: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GithubFetchMetadata {
    pub rate_limit_remaining: Option<u32>,
    pub rate_limit_reset_unix: Option<u64>,
    pub etag: Option<String>,
    pub not_modified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubUserKeys {
    pub username: String,
    pub url: String,
    pub keys: Vec<String>,
    pub backend: GithubBackend,
    pub authenticated: bool,
    pub auth_mode: GithubAuthMode,
    pub metadata: GithubFetchMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubTeamMembers {
    pub org: String,
    pub team: String,
    pub members: Vec<String>,
    pub backend: GithubBackend,
    pub authenticated: bool,
    pub auth_mode: GithubAuthMode,
    pub metadata: GithubFetchMetadata,
}

fn fingerprint_for_public_key(key_type: &str, key_body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key_type.as_bytes());
    hasher.update([b':']);
    hasher.update(key_body.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[must_use]
pub fn fingerprint_for_public_key_line(public_key_line: &str) -> Option<String> {
    let mut parts = public_key_line.split_whitespace();
    let key_type = parts.next()?;
    let key_body = parts.next()?;
    Some(fingerprint_for_public_key(key_type, key_body))
}

fn gh_installed() -> bool {
    Command::new("gh")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn parse_auth_mode(raw: &str) -> Result<GithubAuthMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(GithubAuthMode::Auto),
        "gh" => Ok(GithubAuthMode::Gh),
        "token" => Ok(GithubAuthMode::Token),
        "anonymous" => Ok(GithubAuthMode::Anonymous),
        other => bail!("unsupported github auth mode '{other}'; expected auto|gh|token|anonymous"),
    }
}

fn env_bool(name: &str) -> Option<bool> {
    let raw = std::env::var(name).ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn fetch_options_from_env() -> Result<GithubFetchOptions> {
    let mut options = GithubFetchOptions::default();

    if let Ok(api_base) = std::env::var("GSC_GITHUB_API_BASE")
        && !api_base.trim().is_empty()
    {
        options.api_base_url = api_base.trim_end_matches('/').to_string();
    }
    if let Ok(web_base) = std::env::var("GSC_GITHUB_WEB_BASE")
        && !web_base.trim().is_empty()
    {
        options.web_base_url = web_base.trim_end_matches('/').to_string();
    }
    if let Ok(mode) = std::env::var("GSC_GITHUB_AUTH_MODE")
        && !mode.trim().is_empty()
    {
        options.auth_mode = parse_auth_mode(&mode)?;
    }
    if let Some(hard_fail) = env_bool("GSC_GITHUB_PRIVATE_SOURCE_HARD_FAIL") {
        options.private_source_hard_fail = hard_fail;
    }

    Ok(options)
}

fn github_web_keys_url(web_base_url: &str, username: &str) -> String {
    format!("{}/{username}.keys", web_base_url.trim_end_matches('/'))
}

fn parse_rate_limit(headers: &reqwest::header::HeaderMap) -> (Option<u32>, Option<u64>) {
    let remaining = headers
        .get("x-ratelimit-remaining")
        .and_then(|value| value.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok());
    let reset = headers
        .get("x-ratelimit-reset")
        .and_then(|value| value.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    (remaining, reset)
}

fn gh_api_lines(path: &str, jq: &str, paginate: bool) -> Result<Vec<String>> {
    let mut cmd = Command::new("gh");
    cmd.arg("api");
    if paginate {
        cmd.arg("--paginate");
    }
    cmd.arg(path).arg("--jq").arg(jq);

    let output = cmd
        .output()
        .with_context(|| format!("failed to execute gh api {path}"))?;
    if !output.status.success() {
        bail!(
            "gh api {} failed: {}",
            path,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let text = String::from_utf8(output.stdout).context("gh api output is not utf8")?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn rest_headers(mode: GithubAuthMode, if_none_match: Option<&str>) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("git-sshripped"));

    if let Some(etag) = if_none_match
        && !etag.trim().is_empty()
    {
        let hv =
            HeaderValue::from_str(etag.trim()).context("invalid If-None-Match header value")?;
        headers.insert(IF_NONE_MATCH, hv);
    }

    if mode != GithubAuthMode::Anonymous {
        if let Ok(token) = std::env::var("GITHUB_TOKEN")
            && !token.trim().is_empty()
        {
            let value = format!("Bearer {}", token.trim());
            let hv = HeaderValue::from_str(&value).context("invalid GITHUB_TOKEN header value")?;
            headers.insert(AUTHORIZATION, hv);
        } else if mode == GithubAuthMode::Token {
            bail!("github auth mode 'token' requires GITHUB_TOKEN");
        }
    }

    Ok(headers)
}

fn rest_authenticated(mode: GithubAuthMode) -> bool {
    if mode == GithubAuthMode::Anonymous {
        return false;
    }
    std::env::var("GITHUB_TOKEN")
        .map(|token| !token.trim().is_empty())
        .unwrap_or(false)
}

fn rest_get_with_retry(
    client: &reqwest::blocking::Client,
    url: &str,
    mode: GithubAuthMode,
    if_none_match: Option<&str>,
) -> Result<reqwest::blocking::Response> {
    let mut attempts = 0_u8;
    loop {
        attempts = attempts.saturating_add(1);
        let request = client.get(url).headers(rest_headers(mode, if_none_match)?);
        let response = request.send();

        match response {
            Ok(resp)
                if resp.status().is_server_error()
                    || resp.status() == StatusCode::TOO_MANY_REQUESTS =>
            {
                if attempts >= 3 {
                    bail!(
                        "request to {} failed after retries with status {}",
                        url,
                        resp.status()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(200 * u64::from(attempts)));
            }
            Ok(resp) => return Ok(resp),
            Err(err) => {
                if attempts >= 3 {
                    return Err(err)
                        .with_context(|| format!("request to {} failed after retries", url));
                }
                std::thread::sleep(std::time::Duration::from_millis(200 * u64::from(attempts)));
            }
        }
    }
}

fn parse_next_link(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let link = headers.get("link")?.to_str().ok()?;
    for part in link.split(',') {
        let trimmed = part.trim();
        if !trimmed.contains("rel=\"next\"") {
            continue;
        }
        let start = trimmed.find('<')?;
        let end = trimmed.find('>')?;
        if end > start + 1 {
            return Some(trimmed[start + 1..end].to_string());
        }
    }
    None
}

pub fn fetch_github_user_keys(username: &str) -> Result<GithubUserKeys> {
    fetch_github_user_keys_with_options(username, &fetch_options_from_env()?, None)
}

pub fn fetch_github_user_keys_with_options(
    username: &str,
    options: &GithubFetchOptions,
    if_none_match: Option<&str>,
) -> Result<GithubUserKeys> {
    let use_gh = match options.auth_mode {
        GithubAuthMode::Auto => gh_installed(),
        GithubAuthMode::Gh => {
            if !gh_installed() {
                bail!("github auth mode 'gh' requested but gh is not installed");
            }
            true
        }
        GithubAuthMode::Token | GithubAuthMode::Anonymous => false,
    };

    if use_gh {
        let keys = gh_api_lines(&format!("users/{username}/keys"), ".[].key", true)?;
        return Ok(GithubUserKeys {
            username: username.to_string(),
            url: github_web_keys_url(&options.web_base_url, username),
            keys,
            backend: GithubBackend::Gh,
            authenticated: true,
            auth_mode: options.auth_mode,
            metadata: GithubFetchMetadata::default(),
        });
    }

    let client = reqwest::blocking::Client::builder()
        .build()
        .context("failed to build reqwest client")?;
    let mut keys = Vec::new();
    let mut next = Some(format!(
        "{}/users/{username}/keys?per_page=100",
        options.api_base_url.trim_end_matches('/'),
    ));
    let mut metadata = GithubFetchMetadata::default();
    let mut applied_etag = false;

    while let Some(url) = next {
        let current_if_none_match = if !applied_etag { if_none_match } else { None };
        let resp = rest_get_with_retry(&client, &url, options.auth_mode, current_if_none_match)
            .with_context(|| format!("failed to fetch GitHub user keys for {username}"))?;
        if resp.status() == StatusCode::NOT_MODIFIED {
            metadata.not_modified = true;
            return Ok(GithubUserKeys {
                username: username.to_string(),
                url: github_web_keys_url(&options.web_base_url, username),
                keys: Vec::new(),
                backend: GithubBackend::Rest,
                authenticated: rest_authenticated(options.auth_mode),
                auth_mode: options.auth_mode,
                metadata,
            });
        }
        if options.private_source_hard_fail
            && (resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN)
        {
            bail!(
                "GitHub user keys request failed for {username} (status {}); provide GITHUB_TOKEN or gh auth",
                resp.status()
            );
        }

        let headers = resp.headers().clone();
        if !applied_etag {
            metadata.etag = headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
            applied_etag = true;
        }
        let (remaining, reset) = parse_rate_limit(&headers);
        metadata.rate_limit_remaining = remaining;
        metadata.rate_limit_reset_unix = reset;

        let resp = resp
            .error_for_status()
            .with_context(|| format!("GitHub user keys request failed for {username}"))?;
        let text = resp
            .text()
            .context("failed to read GitHub user keys response")?;
        let parsed: Vec<serde_json::Value> =
            serde_json::from_str(&text).context("invalid GitHub user keys JSON")?;
        keys.extend(
            parsed
                .iter()
                .filter_map(|item| item.get("key").and_then(serde_json::Value::as_str))
                .map(ToString::to_string),
        );
        next = parse_next_link(&headers);
    }

    Ok(GithubUserKeys {
        username: username.to_string(),
        url: github_web_keys_url(&options.web_base_url, username),
        keys,
        backend: GithubBackend::Rest,
        authenticated: rest_authenticated(options.auth_mode),
        auth_mode: options.auth_mode,
        metadata,
    })
}

pub fn fetch_github_team_members(
    org: &str,
    team: &str,
) -> Result<(Vec<String>, GithubBackend, bool)> {
    let fetched =
        fetch_github_team_members_with_options(org, team, &fetch_options_from_env()?, None)?;
    Ok((fetched.members, fetched.backend, fetched.authenticated))
}

pub fn fetch_github_team_members_with_options(
    org: &str,
    team: &str,
    options: &GithubFetchOptions,
    if_none_match: Option<&str>,
) -> Result<GithubTeamMembers> {
    let use_gh = match options.auth_mode {
        GithubAuthMode::Auto => gh_installed(),
        GithubAuthMode::Gh => {
            if !gh_installed() {
                bail!("github auth mode 'gh' requested but gh is not installed");
            }
            true
        }
        GithubAuthMode::Token | GithubAuthMode::Anonymous => false,
    };

    if use_gh {
        let members = gh_api_lines(
            &format!("orgs/{org}/teams/{team}/members"),
            ".[].login",
            true,
        )?;
        return Ok(GithubTeamMembers {
            org: org.to_string(),
            team: team.to_string(),
            members,
            backend: GithubBackend::Gh,
            authenticated: true,
            auth_mode: options.auth_mode,
            metadata: GithubFetchMetadata::default(),
        });
    }

    let client = reqwest::blocking::Client::builder()
        .build()
        .context("failed to build reqwest client")?;
    let mut members = Vec::new();
    let mut next = Some(format!(
        "{}/orgs/{org}/teams/{team}/members?per_page=100",
        options.api_base_url.trim_end_matches('/'),
    ));
    let authenticated = rest_authenticated(options.auth_mode);
    let mut metadata = GithubFetchMetadata::default();
    let mut applied_etag = false;

    while let Some(url) = next {
        let current_if_none_match = if !applied_etag { if_none_match } else { None };
        let resp = rest_get_with_retry(&client, &url, options.auth_mode, current_if_none_match)
            .with_context(|| format!("failed to fetch GitHub team members for {org}/{team}"))?;

        if resp.status() == StatusCode::NOT_MODIFIED {
            metadata.not_modified = true;
            return Ok(GithubTeamMembers {
                org: org.to_string(),
                team: team.to_string(),
                members: Vec::new(),
                backend: GithubBackend::Rest,
                authenticated,
                auth_mode: options.auth_mode,
                metadata,
            });
        }

        if options.private_source_hard_fail
            && (resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN)
        {
            bail!(
                "GitHub team members request failed for {org}/{team} (status {}); this requires authenticated access via GITHUB_TOKEN or gh auth",
                resp.status()
            );
        }

        let headers = resp.headers().clone();
        if !applied_etag {
            metadata.etag = headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
            applied_etag = true;
        }
        let (remaining, reset) = parse_rate_limit(&headers);
        metadata.rate_limit_remaining = remaining;
        metadata.rate_limit_reset_unix = reset;
        let text = resp
            .text()
            .context("failed to read GitHub team members response")?;
        let parsed: Vec<serde_json::Value> =
            serde_json::from_str(&text).context("invalid GitHub team members JSON")?;
        members.extend(
            parsed
                .iter()
                .filter_map(|item| item.get("login").and_then(serde_json::Value::as_str))
                .map(ToString::to_string),
        );
        next = parse_next_link(&headers);
    }

    Ok(GithubTeamMembers {
        org: org.to_string(),
        team: team.to_string(),
        members,
        backend: GithubBackend::Rest,
        authenticated,
        auth_mode: options.auth_mode,
        metadata,
    })
}

#[must_use]
pub fn recipient_store_dir(repo_root: &Path) -> PathBuf {
    repo_root.join(".git-sshripped").join("recipients")
}

#[must_use]
pub fn wrapped_store_dir(repo_root: &Path) -> PathBuf {
    repo_root.join(".git-sshripped").join("wrapped")
}

pub fn list_recipients(repo_root: &Path) -> Result<Vec<RecipientKey>> {
    let dir = recipient_store_dir(repo_root);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut recipients = Vec::new();
    for entry in fs::read_dir(&dir)
        .with_context(|| format!("failed to read recipient dir {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        if !entry
            .file_type()
            .with_context(|| format!("failed to read entry type for {}", entry.path().display()))?
            .is_file()
        {
            continue;
        }
        let text = fs::read_to_string(entry.path())
            .with_context(|| format!("failed to read recipient file {}", entry.path().display()))?;
        let recipient: RecipientKey = toml::from_str(&text).with_context(|| {
            format!("failed to parse recipient file {}", entry.path().display())
        })?;
        recipients.push(recipient);
    }

    recipients.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    Ok(recipients)
}

pub fn add_recipient_from_public_key(
    repo_root: &Path,
    public_key_line: &str,
    source: RecipientSource,
) -> Result<RecipientKey> {
    let trimmed = public_key_line.trim();
    if trimmed.is_empty() {
        bail!("empty SSH public key line");
    }

    let mut parts = trimmed.split_whitespace();
    let key_type = parts
        .next()
        .context("SSH public key is missing key type")?
        .to_string();
    let key_body = parts
        .next()
        .context("SSH public key is missing key material")?;

    if !SUPPORTED_KEY_TYPES
        .iter()
        .any(|supported| *supported == key_type)
    {
        bail!(
            "unsupported SSH key type '{key_type}'; supported types: {}",
            SUPPORTED_KEY_TYPES.join(", ")
        );
    }

    let fingerprint = fingerprint_for_public_key(&key_type, key_body);

    let recipient = RecipientKey {
        fingerprint: fingerprint.clone(),
        key_type,
        public_key_line: trimmed.to_string(),
        source,
    };

    let dir = recipient_store_dir(repo_root);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create recipient dir {}", dir.display()))?;
    let file = dir.join(format!("{fingerprint}.toml"));
    let content = toml::to_string_pretty(&recipient)
        .with_context(|| format!("failed to serialize recipient {}", recipient.fingerprint))?;
    fs::write(&file, content)
        .with_context(|| format!("failed to write recipient file {}", file.display()))?;

    Ok(recipient)
}

pub fn add_recipients_from_github_keys(repo_root: &Path, url: &str) -> Result<Vec<RecipientKey>> {
    add_recipients_from_github_source(repo_root, url, None)
}

pub fn add_recipients_from_github_username(
    repo_root: &Path,
    username: &str,
) -> Result<Vec<RecipientKey>> {
    add_recipients_from_github_username_with_options(
        repo_root,
        username,
        &fetch_options_from_env()?,
    )
}

pub fn add_recipients_from_github_username_with_options(
    repo_root: &Path,
    username: &str,
    options: &GithubFetchOptions,
) -> Result<Vec<RecipientKey>> {
    let fetched = fetch_github_user_keys_with_options(username, options, None)?;
    let mut added = Vec::new();
    for line in fetched.keys.iter().filter(|line| !line.trim().is_empty()) {
        let recipient = add_recipient_from_public_key(
            repo_root,
            line,
            RecipientSource::GithubKeys {
                url: fetched.url.clone(),
                username: Some(username.to_string()),
            },
        )
        .with_context(|| format!("failed to add recipient from key line '{line}'"))?;
        added.push(recipient);
    }
    Ok(added)
}

pub fn add_recipients_from_github_source(
    repo_root: &Path,
    url: &str,
    username: Option<String>,
) -> Result<Vec<RecipientKey>> {
    add_recipients_from_github_source_with_options(
        repo_root,
        url,
        username,
        &fetch_options_from_env()?,
    )
}

pub fn add_recipients_from_github_source_with_options(
    repo_root: &Path,
    url: &str,
    username: Option<String>,
    options: &GithubFetchOptions,
) -> Result<Vec<RecipientKey>> {
    if let Some(user) = username.as_deref() {
        return add_recipients_from_github_username_with_options(repo_root, user, options);
    }

    let text = reqwest::blocking::Client::builder()
        .build()
        .context("failed to build reqwest client")?
        .get(url)
        .headers(rest_headers(options.auth_mode, None)?)
        .send()
        .with_context(|| format!("failed to GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GitHub keys request returned error for {url}"))?
        .text()
        .context("failed to read GitHub keys body")?;

    let mut added = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let recipient = add_recipient_from_public_key(
            repo_root,
            line,
            RecipientSource::GithubKeys {
                url: url.to_string(),
                username: username.clone(),
            },
        )
        .with_context(|| format!("failed to add recipient from key line '{line}'"))?;
        added.push(recipient);
    }

    Ok(added)
}

pub fn remove_recipients_by_fingerprints(
    repo_root: &Path,
    fingerprints: &[String],
) -> Result<usize> {
    let mut removed = 0;
    for fingerprint in fingerprints {
        if remove_recipient_by_fingerprint(repo_root, fingerprint)? {
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn wrap_repo_key_for_recipient(
    repo_root: &Path,
    recipient: &RecipientKey,
    repo_key: &[u8],
) -> Result<PathBuf> {
    let ssh_recipient = SshRecipient::from_str(&recipient.public_key_line).map_err(|err| {
        anyhow::anyhow!(
            "invalid ssh public key for {}: {:?}",
            recipient.fingerprint,
            err
        )
    })?;

    let encryptor = Encryptor::with_recipients(iter::once(&ssh_recipient as _))
        .context("failed to initialize age encryptor")?;

    let mut wrapped = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut wrapped)
            .context("failed to start age wrapping")?;
        writer
            .write_all(repo_key)
            .context("failed to write repo key to wrapper")?;
        writer.finish().context("failed to finish age wrapping")?;
    }

    let dir = wrapped_store_dir(repo_root);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create wrapped dir {}", dir.display()))?;
    let wrapped_file = dir.join(format!("{}.age", recipient.fingerprint));
    fs::write(&wrapped_file, wrapped)
        .with_context(|| format!("failed to write wrapped key {}", wrapped_file.display()))?;
    Ok(wrapped_file)
}

pub fn wrap_repo_key_for_all_recipients(repo_root: &Path, repo_key: &[u8]) -> Result<Vec<PathBuf>> {
    let recipients = list_recipients(repo_root)?;
    if recipients.is_empty() {
        bail!("no recipients configured; add at least one recipient first");
    }

    let mut wrapped_files = Vec::new();
    for recipient in recipients {
        let wrapped_file = wrap_repo_key_for_recipient(repo_root, &recipient, repo_key)?;
        wrapped_files.push(wrapped_file);
    }
    Ok(wrapped_files)
}

pub fn remove_recipient_by_fingerprint(repo_root: &Path, fingerprint: &str) -> Result<bool> {
    let recipient_file = recipient_store_dir(repo_root).join(format!("{fingerprint}.toml"));
    let wrapped_file = wrapped_store_dir(repo_root).join(format!("{fingerprint}.age"));

    let mut removed_any = false;
    if recipient_file.exists() {
        fs::remove_file(&recipient_file).with_context(|| {
            format!(
                "failed to remove recipient file {}",
                recipient_file.display()
            )
        })?;
        removed_any = true;
    }
    if wrapped_file.exists() {
        fs::remove_file(&wrapped_file)
            .with_context(|| format!("failed to remove wrapped file {}", wrapped_file.display()))?;
        removed_any = true;
    }

    Ok(removed_any)
}
