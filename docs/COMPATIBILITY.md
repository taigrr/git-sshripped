# git-crypt Compatibility Map

This maps common `git-crypt` workflows to `git-ssh-crypt` equivalents.

## Core workflow

- `git-crypt init` -> `git-ssh-crypt init --pattern "secrets/**" --recipient-key <pubkey>`
- `git-crypt unlock` -> `git-ssh-crypt unlock --identity <private-key>`
- `git-crypt lock` -> `git-ssh-crypt lock`

## Access management

- `git-crypt add-gpg-user <key>` -> `git-ssh-crypt add-user --key <ssh-pubkey|path>`
- `git-crypt` key removal -> `git-ssh-crypt remove-user --fingerprint <fp>`
- `git-crypt` offboarding workflow -> `git-ssh-crypt revoke-user ... [--auto-reencrypt]`

## Rotation and migration

- Rotate and re-encrypt history tip -> `git-ssh-crypt rotate-key --auto-reencrypt`
- Migrate attributes -> `git-ssh-crypt migrate-from-git-crypt --dry-run --verify --write-report <file>`

## SSH/GitHub-native additions

- GitHub user keys: `add-github-user`, `refresh-github-keys`
- GitHub team membership: `add-github-team`, `refresh-github-teams`
- Policy controls: `policy show|set|verify`
- Runtime GitHub controls: `config set-github-auth-mode`, `config set-github-api-base`, `config set-github-web-base`
