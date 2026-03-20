#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use age::Decryptor;
use age::Identity;
use age::secrecy::SecretString;
use age::ssh::Identity as SshIdentity;
use anyhow::{Context, Result};
use git_sshripped_ssh_identity_models::{IdentityDescriptor, IdentitySource};
use wait_timeout::ChildExt;

#[derive(Clone, Copy)]
struct TerminalCallbacks;

impl age::Callbacks for TerminalCallbacks {
    fn display_message(&self, message: &str) {
        eprintln!("{message}");
    }

    fn confirm(&self, _message: &str, _yes_string: &str, _no_string: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        if let Ok(passphrase) = std::env::var("GSC_SSH_KEY_PASSPHRASE")
            && !passphrase.is_empty()
        {
            return Some(SecretString::from(passphrase));
        }

        rpassword::prompt_password(format!("{description}: "))
            .ok()
            .map(SecretString::from)
    }
}

/// Maximum number of passphrase attempts for encrypted SSH keys.
const MAX_PASSPHRASE_ATTEMPTS: u32 = 3;

/// Decrypt a passphrase-protected SSH key interactively with retries.
///
/// Prompts for the passphrase up to [`MAX_PASSPHRASE_ATTEMPTS`] times.
/// Checks the `GSC_SSH_KEY_PASSPHRASE` environment variable first.
///
/// # Errors
///
/// Returns an error if the passphrase is wrong after all attempts or if
/// the terminal prompt fails.
fn decrypt_encrypted_key(
    enc: &age::ssh::EncryptedKey,
    path: &std::path::Path,
) -> Result<SshIdentity> {
    for attempt in 1..=MAX_PASSPHRASE_ATTEMPTS {
        let passphrase = if let Ok(p) = std::env::var("GSC_SSH_KEY_PASSPHRASE")
            && !p.is_empty()
        {
            SecretString::from(p)
        } else {
            let prompt = format!("Enter passphrase for {}", path.display());
            let p = rpassword::prompt_password(format!("{prompt}: "))
                .context("failed to read passphrase from terminal")?;
            SecretString::from(p)
        };

        match enc.decrypt(passphrase) {
            Ok(decrypted) => return Ok(SshIdentity::from(decrypted)),
            Err(_) if attempt < MAX_PASSPHRASE_ATTEMPTS => {
                eprintln!("wrong passphrase, try again ({attempt}/{MAX_PASSPHRASE_ATTEMPTS})");
            }
            Err(_) => {
                anyhow::bail!(
                    "failed to decrypt {} after {MAX_PASSPHRASE_ATTEMPTS} attempts",
                    path.display()
                );
            }
        }
    }
    unreachable!()
}

#[must_use]
fn ssh_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh"))
}

/// Scan `~/.ssh/` for all files ending in `.pub` that have a corresponding
/// private key file (same path without `.pub`).  Returns `(private, public)` pairs.
#[must_use]
pub fn discover_ssh_key_files() -> Vec<(PathBuf, PathBuf)> {
    let Some(ssh_dir) = ssh_dir() else {
        return Vec::new();
    };

    let Ok(entries) = std::fs::read_dir(&ssh_dir) else {
        return Vec::new();
    };

    let mut pairs = Vec::new();
    for entry in entries.flatten() {
        let pub_path = entry.path();
        if !pub_path.is_file() {
            continue;
        }
        let Some(name) = pub_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pub"))
        {
            continue;
        }
        let private_path = pub_path.with_extension("");
        if private_path.is_file() {
            pairs.push((private_path, pub_path));
        }
    }
    pairs
}

/// Parse `~/.ssh/config` and extract all `IdentityFile` directive values.
/// Expands leading `~` and `~/` to the user's home directory.
#[must_use]
pub fn identity_files_from_ssh_config() -> Vec<PathBuf> {
    let Some(ssh_dir) = ssh_dir() else {
        return Vec::new();
    };

    let config_path = ssh_dir.join("config");
    let Ok(text) = std::fs::read_to_string(&config_path) else {
        return Vec::new();
    };

    parse_identity_files_from_config(&text, dirs::home_dir().as_deref())
}

fn parse_identity_files_from_config(text: &str, home: Option<&std::path::Path>) -> Vec<PathBuf> {
    text.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && line.len() > 12
                && line[..12].eq_ignore_ascii_case("identityfile")
        })
        .filter_map(|line| {
            let value =
                line[12..].trim_start_matches(|c: char| c == '=' || c.is_ascii_whitespace());
            if value.is_empty() {
                return None;
            }
            let expanded = if value == "~" {
                home?.to_path_buf()
            } else if let Some(rest) = value.strip_prefix("~/") {
                home?.join(rest)
            } else {
                PathBuf::from(value)
            };
            Some(expanded)
        })
        .collect()
}

#[must_use]
pub fn default_public_key_candidates() -> Vec<PathBuf> {
    let mut candidates = well_known_public_key_paths();

    // Public keys for IdentityFile entries from ~/.ssh/config
    for private in identity_files_from_ssh_config() {
        let public = private.with_extension("pub");
        if !candidates.contains(&public) {
            candidates.push(public);
        }
    }

    // All discovered .pub files from ~/.ssh/
    for (_, pub_path) in discover_ssh_key_files() {
        if !candidates.contains(&pub_path) {
            candidates.push(pub_path);
        }
    }

    candidates
}

/// Returns only the well-known standard public key paths.
///
/// Returns `id_ed25519.pub` and `id_rsa.pub` from `~/.ssh/`.  Use this when
/// auto-adding recipients during `init` -- we don't want to silently add
/// every key in `~/.ssh/` as a recipient.
#[must_use]
pub fn well_known_public_key_paths() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(ssh_dir) = ssh_dir() {
        candidates.push(ssh_dir.join("id_ed25519.pub"));
        candidates.push(ssh_dir.join("id_rsa.pub"));
    }
    candidates
}

#[must_use]
pub fn default_private_key_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    // Hardcoded standard locations first
    if let Some(ssh_dir) = ssh_dir() {
        candidates.push(ssh_dir.join("id_ed25519"));
        candidates.push(ssh_dir.join("id_rsa"));
    }

    // IdentityFile entries from ~/.ssh/config
    for path in identity_files_from_ssh_config() {
        if !candidates.contains(&path) {
            candidates.push(path);
        }
    }

    // All discovered private key files from ~/.ssh/
    for (private, _) in discover_ssh_key_files() {
        if !candidates.contains(&private) {
            candidates.push(private);
        }
    }

    candidates
}

/// Query the SSH agent for loaded public keys.
///
/// # Errors
///
/// Returns an error if `ssh-add -L` fails to execute or produces non-UTF-8
/// output.
/// List public key strings for all identities currently loaded in the SSH
/// agent, in the same `key-type base64-data [comment]` format as
/// `ssh-add -L`.
///
/// Returns an empty vec when `SSH_AUTH_SOCK` is not set, the agent is
/// unreachable, or the agent has no keys.
///
/// # Errors
///
/// Returns an error only on unexpected failures *after* a successful
/// connection.
pub fn agent_public_keys() -> Result<Vec<String>> {
    let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") else {
        return Ok(Vec::new());
    };
    let sock_path = std::path::Path::new(&sock);
    let Ok(mut client) = ssh_agent_client_rs::Client::connect(sock_path) else {
        return Ok(Vec::new());
    };

    let identities = client
        .list_all_identities()
        .context("failed to list SSH agent identities")?;

    let mut keys = Vec::new();
    for identity in identities {
        let pubkey: &ssh_key::PublicKey = match &identity {
            ssh_agent_client_rs::Identity::PublicKey(boxed_cow) => boxed_cow.as_ref(),
            ssh_agent_client_rs::Identity::Certificate(_) => continue,
        };
        keys.push(pubkey.to_openssh().unwrap_or_default());
    }
    Ok(keys)
}

/// Find local private key files whose public keys are loaded in the SSH agent.
///
/// # Errors
///
/// Returns an error if the agent cannot be queried or a public key file
/// cannot be read.
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

        let pub_trimmed = public_line.trim();
        // Compare only the key-type + key-data portion (first two tokens),
        // ignoring trailing comment which may differ between agent and file.
        let pub_key_data: String = pub_trimmed
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");

        let agent_match = agent_keys.iter().any(|agent_line| {
            let agent_data: String = agent_line
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ");
            agent_data == pub_key_data
        });

        if !agent_match {
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

fn parse_helper_key_output(output: &[u8]) -> Result<Option<Vec<u8>>> {
    if output.len() == 32 {
        return Ok(Some(output.to_vec()));
    }

    let text = String::from_utf8(output.to_vec()).context("agent helper output was not utf8")?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if trimmed.len() == 64 {
        let decoded = hex::decode(trimmed).context("agent helper output was invalid hex")?;
        if decoded.len() == 32 {
            return Ok(Some(decoded));
        }
    }

    anyhow::bail!("agent helper output must be 32 raw bytes or 64-char hex-encoded key")
}

/// Unwrap a repo key using an external agent helper program.
///
/// # Errors
///
/// Returns an error if the helper cannot be spawned, times out, or produces
/// invalid output.
pub fn unwrap_repo_key_with_agent_helper(
    wrapped_files: &[PathBuf],
    helper_path: &std::path::Path,
    timeout_ms: u64,
) -> Result<Option<(Vec<u8>, IdentityDescriptor)>> {
    for wrapped in wrapped_files {
        let mut child = Command::new(helper_path)
            .arg(wrapped)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "failed running agent helper '{}': {}",
                    helper_path.display(),
                    wrapped.display()
                )
            })?;

        let timeout = Duration::from_millis(timeout_ms);
        let status = child
            .wait_timeout(timeout)
            .context("failed waiting on agent helper process")?;

        let output = if status.is_some() {
            child
                .wait_with_output()
                .context("failed collecting agent helper output")?
        } else {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "agent helper timed out after {}ms for {}",
                timeout_ms,
                wrapped.display()
            );
        };

        if !output.status.success() {
            continue;
        }

        let Some(key) = parse_helper_key_output(&output.stdout)? else {
            continue;
        };

        return Ok(Some((
            key,
            IdentityDescriptor {
                source: IdentitySource::SshAgent,
                label: format!("{} ({})", helper_path.display(), wrapped.display()),
            },
        )));
    }

    Ok(None)
}

/// Auto-detect the best available SSH identity.
///
/// # Errors
///
/// This function is infallible in practice but returns `Result` for
/// consistency with the rest of the API.
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

/// Try each identity to decrypt a wrapped repo key file.
///
/// # Errors
///
/// Returns an error if identity files cannot be read or parsed, or if a
/// wrapped key file is malformed.
pub fn unwrap_repo_key_from_wrapped_files<S: ::std::hash::BuildHasher>(
    wrapped_files: &[PathBuf],
    identity_files: &[PathBuf],
    interactive_identities: &HashSet<PathBuf, S>,
) -> Result<Option<(Vec<u8>, IdentityDescriptor)>> {
    let mut identities: Vec<(SshIdentity, PathBuf)> = Vec::new();

    for identity_file in identity_files {
        if !identity_file.exists() {
            continue;
        }
        let content = std::fs::read(identity_file)
            .with_context(|| format!("failed reading identity file {}", identity_file.display()))?;
        let filename = Some(identity_file.display().to_string());
        let identity = SshIdentity::from_buffer(std::io::Cursor::new(&content), filename)
            .with_context(|| format!("failed parsing identity file {}", identity_file.display()))?;
        if let SshIdentity::Encrypted(ref enc) = identity {
            if !interactive_identities.contains(identity_file) {
                eprintln!(
                    "skipping passphrase-protected key {} (pass --identity to use it)",
                    identity_file.display()
                );
                continue;
            }
            // Decrypt the key upfront so we only prompt for the passphrase
            // once, rather than once per wrapped file.
            let decrypted = decrypt_encrypted_key(enc, identity_file)?;
            identities.push((decrypted, identity_file.clone()));
        } else {
            identities.push((identity, identity_file.clone()));
        }
    }

    for wrapped in wrapped_files {
        let wrapped_bytes = std::fs::read(wrapped)
            .with_context(|| format!("failed reading wrapped key {}", wrapped.display()))?;

        for (identity, path) in &identities {
            let decryptor = Decryptor::new_buffered(std::io::Cursor::new(&wrapped_bytes))
                .with_context(|| format!("invalid wrapped key format {}", wrapped.display()))?;
            let decrypt_identity = identity.clone().with_callbacks(TerminalCallbacks);
            let Ok(mut reader) =
                decryptor.decrypt(std::iter::once(&decrypt_identity as &dyn Identity))
            else {
                continue;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parse_config_extracts_identity_files_with_tilde() {
        let config = "\
Host github.com
    User git
    IdentityFile ~/.ssh/github

Host *
    ControlMaster auto
";
        let home = Path::new("/home/testuser");
        let result = parse_identity_files_from_config(config, Some(home));
        assert_eq!(result, vec![PathBuf::from("/home/testuser/.ssh/github")]);
    }

    #[test]
    fn parse_config_extracts_multiple_identity_files() {
        let config = "\
Host work
    IdentityFile ~/.ssh/work_key

Host personal
    IdentityFile ~/.ssh/personal_key

Host github.com
    IdentityFile ~/.ssh/github
";
        let home = Path::new("/Users/user");
        let result = parse_identity_files_from_config(config, Some(home));
        assert_eq!(
            result,
            vec![
                PathBuf::from("/Users/user/.ssh/work_key"),
                PathBuf::from("/Users/user/.ssh/personal_key"),
                PathBuf::from("/Users/user/.ssh/github"),
            ]
        );
    }

    #[test]
    fn parse_config_handles_absolute_paths() {
        let config = "IdentityFile /opt/keys/deploy_key\n";
        let home = Path::new("/home/user");
        let result = parse_identity_files_from_config(config, Some(home));
        assert_eq!(result, vec![PathBuf::from("/opt/keys/deploy_key")]);
    }

    #[test]
    fn parse_config_skips_comments_and_blank_lines() {
        let config = "\
# This is a comment
  # indented comment

Host foo
    # IdentityFile ~/.ssh/commented_out
    IdentityFile ~/.ssh/real_key
";
        let home = Path::new("/home/user");
        let result = parse_identity_files_from_config(config, Some(home));
        assert_eq!(result, vec![PathBuf::from("/home/user/.ssh/real_key")]);
    }

    #[test]
    fn parse_config_case_insensitive_directive() {
        let config =
            "identityfile ~/.ssh/lower\nIDENTITYFILE ~/.ssh/upper\nIdentityFile ~/.ssh/mixed\n";
        let home = Path::new("/home/user");
        let result = parse_identity_files_from_config(config, Some(home));
        assert_eq!(
            result,
            vec![
                PathBuf::from("/home/user/.ssh/lower"),
                PathBuf::from("/home/user/.ssh/upper"),
                PathBuf::from("/home/user/.ssh/mixed"),
            ]
        );
    }

    #[test]
    fn parse_config_handles_equals_separator() {
        let config = "IdentityFile=~/.ssh/equals_key\n";
        let home = Path::new("/home/user");
        let result = parse_identity_files_from_config(config, Some(home));
        assert_eq!(result, vec![PathBuf::from("/home/user/.ssh/equals_key")]);
    }

    #[test]
    fn parse_config_empty_input() {
        let result = parse_identity_files_from_config("", Some(Path::new("/home/user")));
        assert!(result.is_empty());
    }

    #[test]
    fn parse_config_no_home_skips_tilde_paths() {
        let config = "IdentityFile ~/.ssh/key\nIdentityFile /abs/key\n";
        let result = parse_identity_files_from_config(config, None);
        assert_eq!(result, vec![PathBuf::from("/abs/key")]);
    }

    #[test]
    fn discover_keys_in_temp_dir() {
        let temp = tempfile::TempDir::new().expect("temp dir should create");
        let ssh_dir = temp.path();

        // Create a standard key pair
        std::fs::write(ssh_dir.join("id_ed25519"), "private").unwrap();
        std::fs::write(ssh_dir.join("id_ed25519.pub"), "ssh-ed25519 AAAA...").unwrap();

        // Create a custom-named key pair
        std::fs::write(ssh_dir.join("github"), "private").unwrap();
        std::fs::write(ssh_dir.join("github.pub"), "ssh-ed25519 BBBB...").unwrap();

        // Create a .pub file with no matching private key (should be skipped)
        std::fs::write(ssh_dir.join("orphan.pub"), "ssh-rsa CCCC...").unwrap();

        // Create a non-.pub file (should be ignored)
        std::fs::write(ssh_dir.join("known_hosts"), "stuff").unwrap();

        // Create a subdirectory with .pub extension (should be ignored)
        std::fs::create_dir(ssh_dir.join("agent.pub")).unwrap();

        // Use the same logic as discover_ssh_key_files but against our temp dir
        let entries = std::fs::read_dir(ssh_dir).unwrap();
        let mut pairs = Vec::new();
        for entry in entries.flatten() {
            let pub_path = entry.path();
            if !pub_path.is_file() {
                continue;
            }
            let Some(name) = pub_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("pub"))
            {
                continue;
            }
            let private_path = pub_path.with_extension("");
            if private_path.is_file() {
                pairs.push((private_path, pub_path));
            }
        }

        pairs.sort();
        assert_eq!(pairs.len(), 2);

        let names: Vec<&str> = pairs
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert!(names.contains(&"github"));
        assert!(names.contains(&"id_ed25519"));
    }
}
