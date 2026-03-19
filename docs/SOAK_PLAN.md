# Release Candidate Soak Plan

## Scope

- Run at least one full business day on real repositories with protected paths.
- Exercise lock/unlock, recipient changes, rotate-key, and worktree workflows.

## Required checks per run

1. `git-ssh-crypt doctor`
2. `git-ssh-crypt verify --strict`
3. `cargo test`

## Scenarios

- Single worktree edit/commit for protected files.
- Multi-worktree unlock from one worktree, commit from another.
- Lock in one worktree and verify clean failure in another.
- `rotate-key --auto-reencrypt` then commit and unlock from a fresh shell.

## Exit criteria

- No hangs in `git add`, `checkout`, `switch`, `worktree add`.
- No plaintext protected blobs in index/history during soak.
- No unrecoverable lockout event for configured recipients.
