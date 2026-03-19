use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

const TEST_PRIVATE_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBPLYMx485X5KACIiNYV5UD5QQwCFryTNF8UmGGuGziowAAAJjwIMUg8CDF
IAAAAAtzc2gtZWQyNTUxOQAAACBPLYMx485X5KACIiNYV5UD5QQwCFryTNF8UmGGuGziow
AAAEBh012cG+6OBMUHrxxxVQQ73Y32TrNRJcpZdI11XEJ8EE8tgzHjzlfkoAIiI1hXlQPl
BDAIWvJM0XxSYYa4bOKjAAAAEnRlc3RAZ2l0LXNzaC1jcnlwdAECAw==
-----END OPENSSH PRIVATE KEY-----
";

const TEST_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE8tgzHjzlfkoAIiI1hXlQPlBDAIWvJM0XxSYYa4bOKj test@git-ssh-crypt\n";

fn run_ok(cmd: &mut Command) -> Vec<u8> {
    let output = cmd.output().expect("command execution should succeed");
    if !output.status.success() {
        panic!(
            "command failed: status={}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output.stdout
}

fn run_fail(cmd: &mut Command) -> (String, String) {
    let output = cmd.output().expect("command execution should succeed");
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn configure_filter_paths(repo: &Path, bin: &str) {
    run_ok(Command::new("git").current_dir(repo).args([
        "config",
        "--local",
        "filter.git-ssh-crypt.process",
        &format!("{bin} filter-process"),
    ]));
    run_ok(Command::new("git").current_dir(repo).args([
        "config",
        "--local",
        "filter.git-ssh-crypt.clean",
        &format!("{bin} clean --path %f"),
    ]));
    run_ok(Command::new("git").current_dir(repo).args([
        "config",
        "--local",
        "filter.git-ssh-crypt.smudge",
        &format!("{bin} smudge --path %f"),
    ]));
}

#[test]
fn filter_process_roundtrip_with_lock_unlock() {
    let bin = env!("CARGO_BIN_EXE_git-ssh-crypt");
    let temp = TempDir::new().expect("temp dir should create");
    let repo = temp.path();

    run_ok(Command::new("git").current_dir(repo).args(["init"]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["config", "user.name", "test"]),
    );
    run_ok(Command::new("git").current_dir(repo).args([
        "config",
        "user.email",
        "test@example.com",
    ]));

    let keys_dir = repo.join("keys");
    fs::create_dir_all(&keys_dir).expect("keys dir should create");
    let private_key = keys_dir.join("id_ed25519");
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&private_key, TEST_PRIVATE_KEY).expect("private key should write");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));

    configure_filter_paths(repo, bin);

    run_ok(
        Command::new(bin).current_dir(repo).args([
            "unlock",
            "--identity",
            private_key
                .to_str()
                .expect("private key path should be utf8"),
        ]),
    );

    let secret_dir = repo.join("secrets");
    fs::create_dir_all(&secret_dir).expect("secrets dir should create");
    let secret_file = secret_dir.join("app.env");
    fs::write(&secret_file, b"API_KEY=top_secret\n").expect("secret file should write");

    run_ok(Command::new("git").current_dir(repo).args(["add", "."]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["commit", "-m", "test commit"]),
    );

    let staged_blob = run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["show", "HEAD:secrets/app.env"]),
    );
    assert!(staged_blob.starts_with(b"GSC1"));
    assert!(
        !staged_blob
            .windows(b"top_secret".len())
            .any(|w| w == b"top_secret")
    );

    run_ok(Command::new(bin).current_dir(repo).args(["lock"]));
    fs::remove_file(&secret_file).expect("secret file should be removable while locked");
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["checkout", "--", "secrets/app.env"]),
    );
    let locked_view = fs::read(&secret_file).expect("locked view should read");
    assert!(locked_view.starts_with(b"GSC1"));

    run_ok(
        Command::new(bin).current_dir(repo).args([
            "unlock",
            "--identity",
            private_key
                .to_str()
                .expect("private key path should be utf8"),
        ]),
    );
    fs::remove_file(&secret_file).expect("secret file should be removable while unlocked");
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["checkout", "--", "secrets/app.env"]),
    );
    let unlocked_view = fs::read_to_string(&secret_file).expect("unlocked view should read utf8");
    assert_eq!(unlocked_view, "API_KEY=top_secret\n");
}

#[test]
fn filter_process_unlock_lock_is_shared_across_worktrees() {
    let bin = env!("CARGO_BIN_EXE_git-ssh-crypt");
    let temp = TempDir::new().expect("temp dir should create");
    let repo = temp.path();

    run_ok(Command::new("git").current_dir(repo).args(["init"]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["config", "user.name", "test"]),
    );
    run_ok(Command::new("git").current_dir(repo).args([
        "config",
        "user.email",
        "test@example.com",
    ]));

    let keys_dir = repo.join("keys");
    fs::create_dir_all(&keys_dir).expect("keys dir should create");
    let private_key = keys_dir.join("id_ed25519");
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&private_key, TEST_PRIVATE_KEY).expect("private key should write");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));

    configure_filter_paths(repo, bin);

    fs::write(repo.join("README.md"), "bootstrap\n").expect("readme should write");
    run_ok(Command::new("git").current_dir(repo).args([
        "add",
        ".gitattributes",
        ".git-ssh-crypt",
        "README.md",
    ]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["commit", "-m", "bootstrap"]),
    );

    run_ok(
        Command::new(bin).current_dir(repo).args([
            "unlock",
            "--identity",
            private_key
                .to_str()
                .expect("private key path should be utf8"),
        ]),
    );

    let worktree_dir = temp.path().join("wt2");
    run_ok(Command::new("git").current_dir(repo).args([
        "worktree",
        "add",
        "-b",
        "wt2",
        worktree_dir.to_str().expect("worktree path should be utf8"),
    ]));

    let status = run_ok(
        Command::new(bin)
            .current_dir(&worktree_dir)
            .args(["status"]),
    );
    let status_text = String::from_utf8(status).expect("status output should be utf8");
    assert!(status_text.contains("state: UNLOCKED"));

    let wt_secret_dir = worktree_dir.join("secrets");
    fs::create_dir_all(&wt_secret_dir).expect("worktree secrets dir should create");
    let wt_secret_file = wt_secret_dir.join("wt.env");
    fs::write(&wt_secret_file, b"TOKEN=wt_unlocked\n").expect("worktree secret file should write");
    run_ok(
        Command::new("git")
            .current_dir(&worktree_dir)
            .args(["add", "."]),
    );
    run_ok(Command::new("git").current_dir(&worktree_dir).args([
        "commit",
        "-m",
        "worktree secret",
    ]));

    let wt_blob = run_ok(
        Command::new("git")
            .current_dir(&worktree_dir)
            .args(["show", "HEAD:secrets/wt.env"]),
    );
    assert!(wt_blob.starts_with(b"GSC1"));

    run_ok(Command::new(bin).current_dir(&worktree_dir).args(["lock"]));

    let main_secret_dir = repo.join("secrets");
    fs::create_dir_all(&main_secret_dir).expect("main secrets dir should create");
    let main_secret_file = main_secret_dir.join("main.env");
    fs::write(&main_secret_file, b"TOKEN=main_locked\n").expect("main secret file should write");
    let (_, stderr) = run_fail(
        Command::new("git")
            .current_dir(repo)
            .args(["add", "secrets/main.env"]),
    );
    assert!(stderr.contains("repository is locked") || stderr.contains("clean filter"));
}

#[test]
fn recipient_remove_guard_and_verify_strict() {
    let bin = env!("CARGO_BIN_EXE_git-ssh-crypt");
    let temp = TempDir::new().expect("temp dir should create");
    let repo = temp.path();

    run_ok(Command::new("git").current_dir(repo).args(["init"]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["config", "user.name", "test"]),
    );
    run_ok(Command::new("git").current_dir(repo).args([
        "config",
        "user.email",
        "test@example.com",
    ]));

    let keys_dir = repo.join("keys");
    fs::create_dir_all(&keys_dir).expect("keys dir should create");
    let private_key = keys_dir.join("id_ed25519");
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&private_key, TEST_PRIVATE_KEY).expect("private key should write");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--strict",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));
    configure_filter_paths(repo, bin);

    run_ok(
        Command::new(bin).current_dir(repo).args([
            "unlock",
            "--identity",
            private_key
                .to_str()
                .expect("private key path should be utf8"),
        ]),
    );

    let secret_dir = repo.join("secrets");
    fs::create_dir_all(&secret_dir).expect("secrets dir should create");
    fs::write(secret_dir.join("app.env"), b"TOKEN=value\n").expect("secret should write");
    run_ok(Command::new("git").current_dir(repo).args(["add", "."]));

    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .args(["verify", "--strict"]),
    );

    let (_, stderr) = run_fail(Command::new(bin).current_dir(repo).args([
        "remove-user",
        "--fingerprint",
        "does-not-exist",
    ]));
    assert!(stderr.contains("recipient not found"));

    let users = String::from_utf8(run_ok(
        Command::new(bin).current_dir(repo).args(["list-users"]),
    ))
    .expect("list-users output should be utf8");
    let fingerprint = users
        .split_whitespace()
        .next()
        .expect("fingerprint should be present")
        .to_string();

    let (_, stderr) = run_fail(Command::new(bin).current_dir(repo).args([
        "remove-user",
        "--fingerprint",
        &fingerprint,
    ]));
    assert!(stderr.contains("refusing to remove the last recipient"));
}

#[test]
fn rotate_key_and_reencrypt_changes_encrypted_blob() {
    let bin = env!("CARGO_BIN_EXE_git-ssh-crypt");
    let temp = TempDir::new().expect("temp dir should create");
    let repo = temp.path();

    run_ok(Command::new("git").current_dir(repo).args(["init"]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["config", "user.name", "test"]),
    );
    run_ok(Command::new("git").current_dir(repo).args([
        "config",
        "user.email",
        "test@example.com",
    ]));

    let keys_dir = repo.join("keys");
    fs::create_dir_all(&keys_dir).expect("keys dir should create");
    let private_key = keys_dir.join("id_ed25519");
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&private_key, TEST_PRIVATE_KEY).expect("private key should write");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));
    configure_filter_paths(repo, bin);

    run_ok(
        Command::new(bin).current_dir(repo).args([
            "unlock",
            "--identity",
            private_key
                .to_str()
                .expect("private key path should be utf8"),
        ]),
    );

    let secret_dir = repo.join("secrets");
    fs::create_dir_all(&secret_dir).expect("secrets dir should create");
    fs::write(secret_dir.join("rotate.env"), b"TOKEN=rotate_me\n").expect("secret should write");
    run_ok(Command::new("git").current_dir(repo).args(["add", "."]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["commit", "-m", "before rotate"]),
    );

    let before = run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["show", "HEAD:secrets/rotate.env"]),
    );
    assert!(before.starts_with(b"GSC1"));

    run_ok(Command::new(bin).current_dir(repo).args(["rotate-key"]));
    run_ok(Command::new(bin).current_dir(repo).args(["reencrypt"]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["commit", "-am", "after rotate"]),
    );

    let after = run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["show", "HEAD:secrets/rotate.env"]),
    );
    assert!(after.starts_with(b"GSC1"));
    assert_ne!(before, after);
}
