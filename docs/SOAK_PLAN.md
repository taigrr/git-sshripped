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
- Stale-session workflow: rotate in one worktree, verify stale warning in another, then unlock to recover.
- Large repo run: >= 2k protected files, `reencrypt`, `verify --strict`, branch switch, and checkout timings recorded.
- High-recipient run: >= 50 recipients, rotate-key wrap latency and unlock latency recorded.
- GitHub refresh resilience:
  - token auth mode with missing token (expect auth failure classification),
  - dry-run refresh with ETag unchanged path,
  - simulated rate-limit response path (classification and telemetry).
- Failure injection:
  - index lock present during rotate auto-reencrypt rollback,
  - temporary network failure during refresh should classify as backend unavailable.

## Metrics to collect

- `git add` latency on protected files (p50/p95)
- `git checkout` latency for branches with protected files
- `reencrypt` total duration and files/sec
- `refresh-github-*` event telemetry (`auth_mode`, `rate_limit_remaining`, `error_code`)
- Incidents requiring manual intervention and recovery time
- Refresh GitHub user/team sources with and without drift.
- Failure-injection: set `config set-github-auth-mode token` without `GITHUB_TOKEN` and confirm categorized refresh failure.
- Failure-injection: stale source policy (`policy set --max-source-staleness-hours`) trips `policy verify` with actionable failures.
- Scale pass: run recipient/refresh/verify on repo snapshots with 1k+ protected files and 100+ recipients.

## Failure diagnostics checklist

- Refresh events include `error_code` (`auth_missing`, `permission_denied`, `not_found`, `rate_limited`, `backend_unavailable`).
- Source registry persists last refresh status/message for each user/team source.
- `status` and `doctor` surface policy and key/session mismatch context (`repo_key_id`, `session_matches_manifest`).

## Exit criteria

- No hangs in `git add`, `checkout`, `switch`, `worktree add`.
- No plaintext protected blobs in index/history during soak.
- No unrecoverable lockout event for configured recipients.
