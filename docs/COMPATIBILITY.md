# git-crypt Compatibility Map

This maps common `git-crypt` workflows to `git-sshripped` equivalents.

## Core workflow

- `git-crypt init` -> `git-sshripped init --pattern "secrets/**" --recipient-key <pubkey>`
- `git-crypt unlock` -> `git-sshripped unlock --identity <private-key>`
- `git-crypt lock` -> `git-sshripped lock`

## Access management

- `git-crypt add-gpg-user <key>` -> `git-sshripped add-user --key <ssh-pubkey|path>`
- `git-crypt` key removal -> `git-sshripped remove-user --fingerprint <fp>`
- `git-crypt` offboarding workflow -> `git-sshripped revoke-user ... [--auto-reencrypt]`

## Rotation and migration

- Rotate and re-encrypt history tip -> `git-sshripped rotate-key --auto-reencrypt`
- Migrate attributes -> `git-sshripped migrate-from-git-crypt --dry-run --verify --write-report <file>`

## SSH/GitHub-native additions

- GitHub user keys: `add-github-user`, `refresh-github-keys`
- GitHub team membership: `add-github-team`, `refresh-github-teams`
- Policy controls: `policy show|set|verify`
- Runtime GitHub controls: `config set-github-auth-mode`, `config set-github-api-base`, `config set-github-web-base`
