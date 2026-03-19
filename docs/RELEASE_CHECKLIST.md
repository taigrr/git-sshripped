# Release Checklist

- [ ] `cargo fmt --check`
- [ ] `cargo check`
- [ ] `cargo test`
- [ ] `git-ssh-crypt doctor` passes on clean repo
- [ ] `git-ssh-crypt verify --strict` passes on protected files
- [ ] Recipient lifecycle validated (`add-user`, `list-users`, `remove-user`, `rewrap`)
- [ ] Worktree lock/unlock integration tests pass
- [ ] Security docs reviewed (`SECURITY.md`, `docs/FORMAT.md`)
- [ ] Soak plan executed (`docs/SOAK_PLAN.md`)
