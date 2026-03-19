#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
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
    Doctor,
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
        Command::Doctor => cmd_doctor(),
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

fn cmd_doctor() -> Result<()> {
    let mut failures = Vec::new();

    let repo_root = current_repo_root()?;
    let common_dir = current_common_dir()?;
    println!("doctor: repo root {}", repo_root.display());
    println!("doctor: common dir {}", common_dir.display());

    let manifest = match read_manifest(&repo_root) {
        Ok(manifest) => {
            println!("check manifest: PASS");
            manifest
        }
        Err(err) => {
            println!("check manifest: FAIL");
            failures.push(format!("manifest unreadable: {err:#}"));
            RepositoryManifest::default()
        }
    };

    let process_cfg = git_local_config(&repo_root, "filter.git-ssh-crypt.process")?;
    if process_cfg
        .as_ref()
        .is_some_and(|value| value.contains("filter-process"))
    {
        println!("check filter.process: PASS");
    } else {
        println!("check filter.process: FAIL");
        failures.push("filter.git-ssh-crypt.process is missing or invalid".to_string());
    }

    let required_cfg = git_local_config(&repo_root, "filter.git-ssh-crypt.required")?;
    if required_cfg.as_deref() == Some("true") {
        println!("check filter.required: PASS");
    } else {
        println!("check filter.required: FAIL");
        failures.push("filter.git-ssh-crypt.required should be true".to_string());
    }

    let gitattributes = repo_root.join(".gitattributes");
    match fs::read_to_string(&gitattributes) {
        Ok(text) if text.contains("filter=git-ssh-crypt") => {
            println!("check gitattributes wiring: PASS");
        }
        Ok(_) => {
            println!("check gitattributes wiring: FAIL");
            failures.push(".gitattributes has no filter=git-ssh-crypt entries".to_string());
        }
        Err(err) => {
            println!("check gitattributes wiring: FAIL");
            failures.push(format!("cannot read {}: {err}", gitattributes.display()));
        }
    }

    let recipients = list_recipients(&repo_root)?;
    if recipients.is_empty() {
        println!("check recipients: FAIL");
        failures.push("no recipients configured".to_string());
    } else {
        println!("check recipients: PASS ({})", recipients.len());
    }

    let wrapped_files = wrapped_key_files(&repo_root)?;
    if wrapped_files.is_empty() {
        println!("check wrapped keys: FAIL");
        failures.push("no wrapped keys found".to_string());
    } else {
        println!("check wrapped keys: PASS ({})", wrapped_files.len());
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
            println!("check unlock session: PASS (UNLOCKED)");
        } else {
            println!("check unlock session: FAIL");
            failures.push(format!(
                "unlock session key length is {}, expected 32",
                decoded.len()
            ));
        }
    } else {
        println!("check unlock session: PASS (LOCKED)");
    }

    println!("doctor: algorithm {:?}", manifest.encryption_algorithm);
    println!(
        "doctor: protected patterns {}",
        manifest.protected_patterns.join(", ")
    );

    if failures.is_empty() {
        println!("doctor: OK");
        return Ok(());
    }

    println!("doctor: {} issue(s) found", failures.len());
    for failure in failures {
        eprintln!("- {failure}");
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
