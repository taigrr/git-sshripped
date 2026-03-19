# git-sshripped

`git-sshripped` keeps selected files encrypted in Git while still letting you work with plaintext when the repository is unlocked.

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
git-sshripped init --strict --pattern "secrets/**" --recipient-key ~/.ssh/id_ed25519.pub

# unlock using your SSH private key
git-sshripped unlock --identity ~/.ssh/id_ed25519

# work normally
mkdir -p secrets
printf 'API_TOKEN=example\n' > secrets/app.env
git add secrets/app.env

# validate setup
git-sshripped doctor
git-sshripped verify --strict

# lock when done
git-sshripped lock
```

## Common commands

### Daily use

- `git-sshripped unlock [--identity <path>] [--github-user <user>] [--prefer-agent] [--no-agent]`

`unlock` auto-resolves an agent helper in this order:
1) `GSC_SSH_AGENT_HELPER` env var
2) `git config --local git-sshripped.agentHelper`
3) `.git-sshripped/config.toml` (`agent_helper`)
4) PATH search (`git-sshripped-agent-helper`, `age-plugin-ssh-agent`, `age-plugin-ssh`)

Helper contract: `<helper> <wrapped-key-file>` -> stdout with decrypted 32-byte
repo key (raw bytes or 64-char hex).
- `git-sshripped lock`
- `git-sshripped status`
- `git-sshripped doctor [--json]`
- `git-sshripped verify [--strict] [--json]`

### User and access management

- `git-sshripped add-user --key <pub|path>`
- `git-sshripped add-user --github-user <user>`
- `git-sshripped add-user --github-keys-url <url>`
- `git-sshripped list-users [--verbose]`
- `git-sshripped remove-user --fingerprint <fp> [--force]`
- `git-sshripped revoke-user --fingerprint <fp> [--auto-reencrypt] [--json]`
- `git-sshripped revoke-user --github-user <user> [--all-keys-for-user] [--auto-reencrypt] [--json]`
- `git-sshripped revoke-user --org <org> --team <team> [--auto-reencrypt] [--json]`
- `git-sshripped add-github-user --username <user> [--no-auto-wrap]`
- `git-sshripped list-github-users [--verbose]`
- `git-sshripped remove-github-user --username <user> [--force]`
- `git-sshripped refresh-github-keys [--username <user>] [--dry-run] [--fail-on-drift] [--json]`
- `git-sshripped add-github-team --org <org> --team <team> [--no-auto-wrap]`
- `git-sshripped list-github-teams`
- `git-sshripped remove-github-team --org <org> --team <team>`
- `git-sshripped refresh-github-teams [--org <org>] [--team <team>] [--dry-run] [--fail-on-drift] [--json]`
- `git-sshripped access-audit [--identity <path>] [--json]`

`add-github-user` and `add-github-team` auto-wrap by default when an unlock session is available. Use `--no-auto-wrap` to skip wrapping.

### Maintenance

- `git-sshripped install`
- `git-sshripped rewrap`
- `git-sshripped rotate-key [--auto-reencrypt]`
- `git-sshripped reencrypt`
- `git-sshripped migrate-from-git-crypt [--dry-run] [--reencrypt] [--verify] [--json]`
- `git-sshripped migrate-from-git-crypt ... [--write-report <path>]`
- `git-sshripped export-repo-key --out <path>`
- `git-sshripped import-repo-key --input <path>`
- `git-sshripped policy show|set|verify [--json]`
- `git-sshripped policy set --require-verify-strict-clean-for-rotate-revoke <true|false>`
- `git-sshripped policy set --max-source-staleness-hours <hours>`
- `git-sshripped config set-agent-helper <path>`
- `git-sshripped config set-github-api-base <url>`
- `git-sshripped config set-github-web-base <url>`
- `git-sshripped config set-github-auth-mode <auto|gh|token|anonymous>`
- `git-sshripped config set-github-private-source-hard-fail <true|false>`
- `git-sshripped config show`

## Security notes

- This project is pre-1.0 and should be treated as security-sensitive software.
- Deterministic encryption is used for Git filter stability and has known leakage tradeoffs.
- Keep at least two valid recipients configured to reduce lockout risk.

See `SECURITY.md` for the full threat model and operational guidance.
See `docs/COMPATIBILITY.md` for git-crypt command mapping and migration notes.
