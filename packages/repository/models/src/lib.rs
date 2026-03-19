#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use git_ssh_crypt_encryption_models::EncryptionAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepositoryManifest {
    pub manifest_version: u32,
    pub encryption_algorithm: EncryptionAlgorithm,
    pub protected_patterns: Vec<String>,
}

impl Default for RepositoryManifest {
    fn default() -> Self {
        Self {
            manifest_version: 1,
            encryption_algorithm: EncryptionAlgorithm::AesSivV1,
            protected_patterns: vec!["secrets/**".to_string()],
        }
    }
}
