# git-ssh-crypt

Worktree-safe transparent Git encryption using SSH-oriented recipient workflows.

## Workspace architecture

This project follows a strict domain + `*_models` package convention:

- `git_ssh_crypt_<domain>` for behavior
- `git_ssh_crypt_<domain>_models` for domain-owned shared types

Current domains:

- `repository`
- `recipient`
- `worktree`
- `encryption`
- `filter`
- `ssh_identity`
- `cli`

## Current behavior

- Repository metadata in `.git-ssh-crypt/manifest.toml`
- Git filter wiring + attributes installation from `init`
- Worktree-shared unlock state in `GIT_COMMON_DIR/git-ssh-crypt/session/unlock.json`
- Filter policy:
  - smudge fail-open (returns ciphertext if locked)
  - clean fail-closed for protected plaintext when locked
- Deterministic encrypted file format with AES-SIV backend
- Repository key wrapping to SSH recipients using age SSH support
- Unlock by unwrapping wrapped key files with local SSH private keys

## Commands

- `git-ssh-crypt init [--strict]`
- `git-ssh-crypt unlock [--identity <path>]`
- `git-ssh-crypt lock`
- `git-ssh-crypt status`
- `git-ssh-crypt doctor`
- `git-ssh-crypt verify [--strict]`
- `git-ssh-crypt add-user --key <pub|path>`
- `git-ssh-crypt list-users`
- `git-ssh-crypt remove-user --fingerprint <fp> [--force]`
- `git-ssh-crypt rewrap`
- `git-ssh-crypt rotate-key [--auto-reencrypt]`
- `git-ssh-crypt reencrypt`

## Important implementation note

The long-running `filter-process` protocol is enabled by default via git
config. The single-blob `clean`/`smudge` commands remain available as explicit
fallback commands.

## CI baseline

- `git-ssh-crypt doctor`
- `git-ssh-crypt verify --strict`
- `cargo deny check`

## Operational self-check

Run this sequence in a repository using git-ssh-crypt:

```bash
git-ssh-crypt doctor
git-ssh-crypt verify --strict
cargo test -p git_ssh_crypt_cli --test smoke_ci
```
