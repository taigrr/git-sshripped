#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use git_sshripped_encryption_models::EncryptionAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InitOptions {
    pub algorithm: EncryptionAlgorithm,
    pub strict_mode: bool,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::AesSivV1,
            strict_mode: false,
        }
    }
}
