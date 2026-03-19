#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use git_ssh_crypt_encryption_models::EncryptionAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InitOptions {
    pub protected_patterns: Vec<String>,
    pub algorithm: EncryptionAlgorithm,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            protected_patterns: vec!["secrets/**".to_string()],
            algorithm: EncryptionAlgorithm::AesSivV1,
        }
    }
}
