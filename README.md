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

## Important implementation note

`filter-process` protocol is not implemented yet; git filter wiring currently uses
`clean`/`smudge` subprocess commands.
