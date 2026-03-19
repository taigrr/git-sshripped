# git-ssh-crypt

`git-ssh-crypt` keeps selected files encrypted in Git while still letting you work with plaintext when the repository is unlocked.

It is for teams that already use SSH keys and want encryption to fit normal Git usage instead of adding a separate manual workflow.

## Why this tool

- SSH-native recipient access using existing SSH public/private keys.
- Git-transparent encryption through Git filters, so normal `git add`, `git commit`, and `git checkout` behavior still applies.
- Worktree-aware lock/unlock state that behaves consistently across Git worktrees.
- Built-in checks (`doctor`, `verify --strict`) to catch config issues and plaintext mistakes early.

Many alternatives fall short because they require manual encrypt/decrypt steps, do not use SSH as the recipient model, or do not behave cleanly with worktrees.

## How it works

1. `init` sets up manifest, patterns, and Git filter wiring.
2. Protected paths (for example `secrets/**`) are encrypted when staged.
3. The repository data key is wrapped to configured SSH recipients.
4. `unlock` makes protected files readable in your working tree.
5. `lock` removes unlocked key material and protected paths read back as ciphertext.

## Quick start

```bash
# in an existing Git repository
git-ssh-crypt init --strict --pattern "secrets/**" --recipient-key ~/.ssh/id_ed25519.pub

# unlock using your SSH private key
git-ssh-crypt unlock --identity ~/.ssh/id_ed25519

# work normally
mkdir -p secrets
printf 'API_TOKEN=example\n' > secrets/app.env
git add secrets/app.env

# validate setup
git-ssh-crypt doctor
git-ssh-crypt verify --strict

# lock when done
git-ssh-crypt lock
```

## Common commands

### Daily use

- `git-ssh-crypt unlock [--identity <path>] [--github-user <user>]`
- `git-ssh-crypt lock`
- `git-ssh-crypt status`
- `git-ssh-crypt doctor`
- `git-ssh-crypt verify [--strict]`

### User and access management

- `git-ssh-crypt add-user --key <pub|path>`
- `git-ssh-crypt add-user --github-user <user>`
- `git-ssh-crypt add-user --github-keys-url <url>`
- `git-ssh-crypt list-users [--verbose]`
- `git-ssh-crypt remove-user --fingerprint <fp> [--force]`
- `git-ssh-crypt refresh-github-keys`
- `git-ssh-crypt access-audit [--identity <path>]`

### Maintenance

- `git-ssh-crypt install`
- `git-ssh-crypt rewrap`
- `git-ssh-crypt rotate-key [--auto-reencrypt]`
- `git-ssh-crypt reencrypt`
- `git-ssh-crypt migrate-from-git-crypt`
- `git-ssh-crypt export-repo-key --out <path>`
- `git-ssh-crypt import-repo-key --input <path>`

## Security notes

- This project is pre-1.0 and should be treated as security-sensitive software.
- Deterministic encryption is used for Git filter stability and has known leakage tradeoffs.
- Keep at least two valid recipients configured to reduce lockout risk.

See `SECURITY.md` for the full threat model and operational guidance.
