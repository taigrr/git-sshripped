#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

#[cfg(feature = "cli-models")]
pub use git_sshripped_cli_models as cli_models;
#[cfg(feature = "encryption")]
pub use git_sshripped_encryption as encryption;
#[cfg(feature = "encryption-models")]
pub use git_sshripped_encryption_models as encryption_models;
#[cfg(feature = "filter")]
pub use git_sshripped_filter as filter;
#[cfg(feature = "filter-models")]
pub use git_sshripped_filter_models as filter_models;
#[cfg(feature = "recipient")]
pub use git_sshripped_recipient as recipient;
#[cfg(feature = "recipient-models")]
pub use git_sshripped_recipient_models as recipient_models;
#[cfg(feature = "repository")]
pub use git_sshripped_repository as repository;
#[cfg(feature = "repository-models")]
pub use git_sshripped_repository_models as repository_models;
#[cfg(feature = "ssh-agent")]
pub use git_sshripped_ssh_agent as ssh_agent;
#[cfg(feature = "ssh-agent-models")]
pub use git_sshripped_ssh_agent_models as ssh_agent_models;
#[cfg(feature = "ssh-identity")]
pub use git_sshripped_ssh_identity as ssh_identity;
#[cfg(feature = "ssh-identity-models")]
pub use git_sshripped_ssh_identity_models as ssh_identity_models;
#[cfg(feature = "worktree")]
pub use git_sshripped_worktree as worktree;
#[cfg(feature = "worktree-models")]
pub use git_sshripped_worktree_models as worktree_models;
