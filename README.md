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

## Important implementation note

Recipient key wrapping is scaffolded (recipient import/storage exists), but full
per-recipient wrapping/unwrapping of repository keys is not complete yet. During
bootstrap, `init` writes a local repo key to `.git-ssh-crypt/repo-key.hex` and
`unlock` can consume that key or `--key-hex`.
