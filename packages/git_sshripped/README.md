# git_sshripped

Umbrella crate that re-exports all git-sshripped domain crates under a single
dependency.

## Overview

This crate provides a convenience facade over the git-sshripped workspace.
Each sub-crate is gated behind a feature flag, so downstream consumers can
depend on `git_sshripped` with fine-grained control over which domains are
compiled.

With the default `all` feature enabled, every domain crate is re-exported.

## Feature Flags

| Feature | Re-exported Crate |
|---------|-------------------|
| `cli-models` | `git_sshripped_cli_models` |
| `encryption` | `git_sshripped_encryption` |
| `encryption-models` | `git_sshripped_encryption_models` |
| `filter` | `git_sshripped_filter` |
| `filter-models` | `git_sshripped_filter_models` |
| `recipient` | `git_sshripped_recipient` |
| `recipient-models` | `git_sshripped_recipient_models` |
| `repository` | `git_sshripped_repository` |
| `repository-models` | `git_sshripped_repository_models` |
| `ssh-agent` | `git_sshripped_ssh_agent` |
| `ssh-agent-models` | `git_sshripped_ssh_agent_models` |
| `ssh-identity` | `git_sshripped_ssh_identity` |
| `ssh-identity-models` | `git_sshripped_ssh_identity_models` |
| `worktree` | `git_sshripped_worktree` |
| `worktree-models` | `git_sshripped_worktree_models` |

## Usage

```toml
[dependencies]
git_sshripped = { version = "0.1", features = ["encryption", "filter"] }
```

See the [git-sshripped repository](https://github.com/BSteffaniak/git-sshripped)
for full documentation.
