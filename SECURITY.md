# Security Model

This project is currently pre-1.0 and should be treated as security-sensitive software under active hardening.

## Threat model

- Protect protected-path file contents at rest in Git objects and on remotes.
- Assume attacker can read repository history and encrypted blobs.
- Assume attacker does not control maintainer/developer endpoints with unlocked keys.

## Non-goals

- Defense against local host compromise after unlock.
- Forward secrecy for already-encrypted history.
- Metadata hiding for protected paths and file sizes.

## Current cryptographic properties

- Repository files are encrypted with a repository data key.
- Repository data key is wrapped per recipient SSH public key.
- Associated data binds ciphertext to repository-relative path.

## Deterministic leakage

Deterministic encryption is used for Git filter stability. This leaks:

- Equality of same plaintext at same path/AD context.
- Approximate plaintext length.

## Operational requirements

- Keep at least two valid recipients to avoid lockout.
- Run `git-ssh-crypt doctor` and `git-ssh-crypt verify --strict` in CI.
- Rotate recipients/keys when access policy changes.
- Prefer `ssh-ed25519` recipients; use `ssh-rsa` only when compatibility requires it.

## Reporting security issues

Report vulnerabilities privately to maintainers before opening public issues.
