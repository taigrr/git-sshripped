#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use git_ssh_crypt_encryption_models::EncryptionAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RepositoryManifest {
    pub manifest_version: u32,
    pub encryption_algorithm: EncryptionAlgorithm,
    pub protected_patterns: Vec<String>,
    pub strict_mode: bool,
    pub repo_key_id: Option<String>,
    pub min_recipients: usize,
    pub allowed_key_types: Vec<String>,
    pub require_doctor_clean_for_rotate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct GithubSourceRegistry {
    pub users: Vec<GithubUserSource>,
    pub teams: Vec<GithubTeamSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GithubUserSource {
    pub username: String,
    pub url: String,
    pub fingerprints: Vec<String>,
    pub last_refreshed_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GithubTeamSource {
    pub org: String,
    pub team: String,
    pub member_usernames: Vec<String>,
    pub fingerprints: Vec<String>,
    pub last_refreshed_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct RepositoryLocalConfig {
    pub agent_helper: Option<String>,
}

impl Default for RepositoryManifest {
    fn default() -> Self {
        Self {
            manifest_version: 1,
            encryption_algorithm: EncryptionAlgorithm::AesSivV1,
            protected_patterns: vec!["secrets/**".to_string()],
            strict_mode: false,
            repo_key_id: None,
            min_recipients: 1,
            allowed_key_types: vec!["ssh-ed25519".to_string(), "ssh-rsa".to_string()],
            require_doctor_clean_for_rotate: false,
        }
    }
}
