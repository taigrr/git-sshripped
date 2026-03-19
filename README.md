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

- `git-ssh-crypt unlock [--identity <path>] [--github-user <user>] [--prefer-agent] [--no-agent]`

`unlock` auto-resolves an agent helper in this order:
1) `GSC_SSH_AGENT_HELPER` env var
2) `git config --local git-ssh-crypt.agentHelper`
3) `.git-ssh-crypt/config.toml` (`agent_helper`)
4) PATH search (`git-ssh-crypt-agent-helper`, `age-plugin-ssh-agent`, `age-plugin-ssh`)

Helper contract: `<helper> <wrapped-key-file>` -> stdout with decrypted 32-byte
repo key (raw bytes or 64-char hex).
- `git-ssh-crypt lock`
- `git-ssh-crypt status`
- `git-ssh-crypt doctor [--json]`
- `git-ssh-crypt verify [--strict] [--json]`

### User and access management

- `git-ssh-crypt add-user --key <pub|path>`
- `git-ssh-crypt add-user --github-user <user>`
- `git-ssh-crypt add-user --github-keys-url <url>`
- `git-ssh-crypt list-users [--verbose]`
- `git-ssh-crypt remove-user --fingerprint <fp> [--force]`
- `git-ssh-crypt revoke-user --fingerprint <fp> [--auto-reencrypt] [--json]`
- `git-ssh-crypt revoke-user --github-user <user> [--all-keys-for-user] [--auto-reencrypt] [--json]`
- `git-ssh-crypt revoke-user --org <org> --team <team> [--auto-reencrypt] [--json]`
- `git-ssh-crypt add-github-user --username <user> [--no-auto-wrap]`
- `git-ssh-crypt list-github-users [--verbose]`
- `git-ssh-crypt remove-github-user --username <user> [--force]`
- `git-ssh-crypt refresh-github-keys [--username <user>] [--dry-run] [--fail-on-drift] [--json]`
- `git-ssh-crypt add-github-team --org <org> --team <team> [--no-auto-wrap]`
- `git-ssh-crypt list-github-teams`
- `git-ssh-crypt remove-github-team --org <org> --team <team>`
- `git-ssh-crypt refresh-github-teams [--org <org>] [--team <team>] [--dry-run] [--fail-on-drift] [--json]`
- `git-ssh-crypt access-audit [--identity <path>] [--json]`

`add-github-user` and `add-github-team` auto-wrap by default when an unlock session is available. Use `--no-auto-wrap` to skip wrapping.

### Maintenance

- `git-ssh-crypt install`
- `git-ssh-crypt rewrap`
- `git-ssh-crypt rotate-key [--auto-reencrypt]`
- `git-ssh-crypt reencrypt`
- `git-ssh-crypt migrate-from-git-crypt [--dry-run] [--reencrypt] [--verify] [--json]`
- `git-ssh-crypt migrate-from-git-crypt ... [--write-report <path>]`
- `git-ssh-crypt export-repo-key --out <path>`
- `git-ssh-crypt import-repo-key --input <path>`
- `git-ssh-crypt policy show|set|verify [--json]`
- `git-ssh-crypt config set-agent-helper <path>`
- `git-ssh-crypt config set-github-api-base <url>`
- `git-ssh-crypt config set-github-web-base <url>`
- `git-ssh-crypt config set-github-auth-mode <auto|gh|token|anonymous>`
- `git-ssh-crypt config set-github-private-source-hard-fail <true|false>`
- `git-ssh-crypt config show`

## Security notes

- This project is pre-1.0 and should be treated as security-sensitive software.
- Deterministic encryption is used for Git filter stability and has known leakage tradeoffs.
- Keep at least two valid recipients configured to reduce lockout risk.

See `SECURITY.md` for the full threat model and operational guidance.
