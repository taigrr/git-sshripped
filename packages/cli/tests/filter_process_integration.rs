use std::fs;
use std::path::Path;
use std::path::PathBuf;
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
const TEST_RSA_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKxv3k0w1R4W4zH5ZlB0PkqfYq2Qf7o7Y3w5Q6lN3J2o6b2iF7p3r7wqM8mC6nVqP4yN1iC8eR7uW1dK9h5f3j2a1mN8pQ6rT4vY7zE2sL1dM9pQ8wN2kH3jR6bV1wQ4cN7fK2zL5mP8jQ1aC4nB7dE9gH2jK5mN8pR2tW5xY8zC1vB4nM7 test-rsa@git-ssh-crypt";

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

fn rewrite_manifest_line(repo: &Path, key: &str, value_literal: &str) {
    let manifest_path = repo.join(".git-ssh-crypt").join("manifest.toml");
    let manifest_text = fs::read_to_string(&manifest_path).expect("manifest should read");
    let mut found = false;
    let rewritten = manifest_text
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(&format!("{key} = ")) {
                found = true;
                format!("{key} = {value_literal}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(found, "manifest key should exist: {key}");
    fs::write(&manifest_path, format!("{rewritten}\n")).expect("manifest should rewrite");
}

fn generate_encrypted_ed25519_keypair(
    keys_dir: &Path,
    name: &str,
    passphrase: &str,
) -> (PathBuf, PathBuf) {
    let private_key = keys_dir.join(name);
    let private_key_str = private_key
        .to_str()
        .expect("private key path should be utf8")
        .to_string();
    let output = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            passphrase,
            "-C",
            "enc-test@git-ssh-crypt",
            "-f",
            &private_key_str,
        ])
        .output()
        .expect("ssh-keygen should execute");
    if !output.status.success() {
        panic!(
            "ssh-keygen failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    (private_key.clone(), private_key.with_extension("pub"))
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

    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .args(["rotate-key", "--auto-reencrypt"]),
    );
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

#[test]
fn rotate_key_auto_reencrypt_rolls_back_on_failure() {
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
    let secret_file = secret_dir.join("rollback.env");
    fs::write(&secret_file, b"TOKEN=before_failure\n").expect("secret should write");
    run_ok(Command::new("git").current_dir(repo).args(["add", "."]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["commit", "-m", "before failure"]),
    );

    let wrapped_dir = repo.join(".git-ssh-crypt").join("wrapped");
    let wrapped_entry = fs::read_dir(&wrapped_dir)
        .expect("wrapped dir should exist")
        .next()
        .expect("wrapped dir should contain files")
        .expect("wrapped entry should be readable");
    let wrapped_path = wrapped_entry.path();
    let _wrapped_before = fs::read(&wrapped_path).expect("wrapped file should be readable");

    fs::write(repo.join(".git").join("index.lock"), b"lock").expect("index lock should be created");
    let (_, stderr) = run_fail(
        Command::new(bin)
            .current_dir(repo)
            .args(["rotate-key", "--auto-reencrypt"]),
    );
    assert!(stderr.contains("auto-reencrypt failed"));
    fs::remove_file(repo.join(".git").join("index.lock")).expect("index lock should remove");

    let _wrapped_after = fs::read(&wrapped_path).expect("wrapped file should remain readable");

    fs::remove_file(&secret_file).expect("secret should be removable");
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["checkout", "--", "secrets/rollback.env"]),
    );
    let restored = fs::read_to_string(&secret_file).expect("restored secret should be readable");
    assert_eq!(restored, "TOKEN=before_failure\n");

    fs::write(&secret_file, b"TOKEN=after_failure\n").expect("secret should rewrite");
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["add", "secrets/rollback.env"]),
    );
}

#[test]
fn rotate_key_wrap_failure_restores_previous_wrapped_files() {
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

    let wrapped_dir = repo.join(".git-ssh-crypt").join("wrapped");
    let wrapped_entry = fs::read_dir(&wrapped_dir)
        .expect("wrapped dir should exist")
        .next()
        .expect("wrapped dir should contain files")
        .expect("wrapped entry should be readable");
    let wrapped_path = wrapped_entry.path();
    let wrapped_before = fs::read(&wrapped_path).expect("wrapped file should read");

    let recipients_dir = repo.join(".git-ssh-crypt").join("recipients");
    let recipient_entry = fs::read_dir(&recipients_dir)
        .expect("recipients dir should exist")
        .next()
        .expect("recipient entry should exist")
        .expect("recipient entry should be readable");
    let recipient_path = recipient_entry.path();
    let recipient_original =
        fs::read_to_string(&recipient_path).expect("recipient file should read");
    let recipient_broken = recipient_original.replace("ssh-ed25519", "ssh-invalid");
    fs::write(&recipient_path, recipient_broken).expect("recipient file should be rewritten");

    let (_, stderr) = run_fail(Command::new(bin).current_dir(repo).args(["rotate-key"]));
    assert!(stderr.contains("previous wrapped files restored"));

    let wrapped_after = fs::read(&wrapped_path).expect("wrapped file should read after failure");
    assert_eq!(wrapped_before, wrapped_after);

    fs::write(&recipient_path, recipient_original).expect("recipient file should be restored");

    let secret_dir = repo.join("secrets");
    fs::create_dir_all(&secret_dir).expect("secrets dir should create");
    fs::write(
        secret_dir.join("post_wrap_fail.env"),
        b"TOKEN=still_operable\n",
    )
    .expect("secret should write");
    run_ok(Command::new("git").current_dir(repo).args(["add", "."]));
}

#[test]
fn manifest_min_recipients_blocks_remove_and_revoke() {
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
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));

    rewrite_manifest_line(repo, "min_recipients", "2");

    let users = String::from_utf8(run_ok(
        Command::new(bin).current_dir(repo).args(["list-users"]),
    ))
    .expect("list-users output should be utf8");
    let fingerprint = users
        .split_whitespace()
        .next()
        .expect("fingerprint should be present")
        .to_string();

    let (_, stderr_remove) = run_fail(Command::new(bin).current_dir(repo).args([
        "remove-user",
        "--fingerprint",
        &fingerprint,
        "--force",
    ]));
    assert!(stderr_remove.contains("min_recipients=2"));

    let (_, stderr_revoke) = run_fail(Command::new(bin).current_dir(repo).args([
        "revoke-user",
        "--fingerprint",
        &fingerprint,
        "--force",
    ]));
    assert!(stderr_revoke.contains("min_recipients=2"));
}

#[test]
fn disallowed_key_type_add_rollback_removes_new_recipient() {
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
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));

    rewrite_manifest_line(repo, "allowed_key_types", "[\"ssh-ed25519\"]");

    let _ = run_fail(Command::new(bin).current_dir(repo).args([
        "add-user",
        "--key",
        TEST_RSA_PUBLIC_KEY,
    ]));

    let users = String::from_utf8(run_ok(
        Command::new(bin).current_dir(repo).args(["list-users"]),
    ))
    .expect("list-users output should be utf8");
    assert_eq!(users.lines().count(), 1);

    let recipient_count = fs::read_dir(repo.join(".git-ssh-crypt").join("recipients"))
        .expect("recipients dir should exist")
        .count();
    assert_eq!(recipient_count, 1);
}

#[test]
fn migrate_write_report_outputs_json_file() {
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
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));

    fs::write(
        repo.join(".gitattributes"),
        "secrets/** filter=git-crypt diff=git-crypt\n",
    )
    .expect("gitattributes should write");

    let report_path = repo.join("migration-report.json");
    run_ok(
        Command::new(bin).current_dir(repo).args([
            "migrate-from-git-crypt",
            "--dry-run",
            "--write-report",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ]),
    );

    let report_text = fs::read_to_string(&report_path).expect("report file should exist");
    let report_json: serde_json::Value =
        serde_json::from_str(&report_text).expect("report should parse as json");
    assert_eq!(report_json["dry_run"], true);
    assert_eq!(report_json["gitattributes"]["legacy_lines_replaced"], 1);
}

#[test]
fn policy_set_show_verify_json_roundtrip() {
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
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));

    run_ok(Command::new(bin).current_dir(repo).args([
        "policy",
        "set",
        "--min-recipients",
        "1",
        "--allow-key-type",
        "ssh-ed25519",
        "--require-doctor-clean-for-rotate",
        "true",
        "--require-verify-strict-clean-for-rotate-revoke",
        "true",
        "--max-source-staleness-hours",
        "24",
    ]));

    let policy_show = String::from_utf8(run_ok(
        Command::new(bin)
            .current_dir(repo)
            .args(["policy", "show", "--json"]),
    ))
    .expect("policy show output should be utf8");
    let policy_json: serde_json::Value =
        serde_json::from_str(&policy_show).expect("policy show should parse");
    assert_eq!(policy_json["min_recipients"], 1);
    assert_eq!(policy_json["require_doctor_clean_for_rotate"], true);
    assert_eq!(
        policy_json["require_verify_strict_clean_for_rotate_revoke"],
        true
    );
    assert_eq!(policy_json["max_source_staleness_hours"], 24);

    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .args(["policy", "verify", "--json"]),
    );
}

#[test]
fn config_show_includes_github_runtime_settings() {
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

    run_ok(Command::new(bin).current_dir(repo).args([
        "config",
        "set-github-api-base",
        "https://ghe.example.com/api/v3",
    ]));
    run_ok(Command::new(bin).current_dir(repo).args([
        "config",
        "set-github-web-base",
        "https://ghe.example.com",
    ]));
    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .args(["config", "set-github-auth-mode", "token"]),
    );
    run_ok(Command::new(bin).current_dir(repo).args([
        "config",
        "set-github-private-source-hard-fail",
        "false",
    ]));

    let out = String::from_utf8(run_ok(
        Command::new(bin).current_dir(repo).args(["config", "show"]),
    ))
    .expect("config show output should be utf8");
    let cfg: serde_json::Value = serde_json::from_str(&out).expect("config should parse");
    assert_eq!(cfg["github_api_base"], "https://ghe.example.com/api/v3");
    assert_eq!(cfg["github_web_base"], "https://ghe.example.com");
    assert_eq!(cfg["github_auth_mode"], "token");
    assert_eq!(cfg["github_private_source_hard_fail"], false);
}

#[test]
fn refresh_github_keys_reports_auth_missing_error_code() {
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
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));
    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .args(["config", "set-github-auth-mode", "token"]),
    );

    let sources = r#"[[users]]
username = "example-user"
url = "https://github.com/example-user.keys"
fingerprints = []
last_refreshed_unix = 1
"#;
    fs::write(
        repo.join(".git-ssh-crypt").join("github-sources.toml"),
        sources,
    )
    .expect("github sources should write");

    let _ = run_fail(
        Command::new(bin)
            .current_dir(repo)
            .args(["refresh-github-keys", "--json"]),
    );
}

#[test]
fn policy_verify_fails_when_source_staleness_exceeds_policy() {
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
    let public_key = keys_dir.join("id_ed25519.pub");
    fs::write(&public_key, TEST_PUBLIC_KEY).expect("public key should write");

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));
    run_ok(Command::new(bin).current_dir(repo).args([
        "policy",
        "set",
        "--max-source-staleness-hours",
        "1",
    ]));

    let sources = r#"[[users]]
username = "example-user"
url = "https://github.com/example-user.keys"
fingerprints = []
last_refreshed_unix = 1
"#;
    fs::write(
        repo.join(".git-ssh-crypt").join("github-sources.toml"),
        sources,
    )
    .expect("github sources should write");

    let _ = run_fail(
        Command::new(bin)
            .current_dir(repo)
            .args(["policy", "verify", "--json"]),
    );
}

#[test]
fn lock_refuses_dirty_protected_files_without_force() {
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
    let secret_file = secret_dir.join("dirty.env");
    fs::write(&secret_file, b"TOKEN=clean\n").expect("secret should write");
    run_ok(Command::new("git").current_dir(repo).args(["add", "."]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["commit", "-m", "seed protected file"]),
    );

    fs::write(&secret_file, b"TOKEN=dirty\n").expect("dirty secret should write");
    let (_, stderr) = run_fail(Command::new(bin).current_dir(repo).args(["lock"]));
    assert!(
        stderr.contains("lock refused") || stderr.contains("protected files have local changes")
    );

    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .args(["lock", "--force"]),
    );
    let locked = fs::read(&secret_file).expect("locked file should read");
    assert!(locked.starts_with(b"GSC1"));
}

#[test]
fn worktree_key_rotation_causes_old_branch_session_mismatch_until_unlock() {
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
    fs::write(secret_dir.join("base.env"), b"TOKEN=base\n").expect("base secret should write");
    run_ok(Command::new("git").current_dir(repo).args(["add", "."]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["commit", "-m", "base"]),
    );

    let worktree_dir = temp.path().join("wt-rotate");
    run_ok(Command::new("git").current_dir(repo).args([
        "worktree",
        "add",
        "-b",
        "wt-rotate",
        worktree_dir.to_str().expect("worktree path should be utf8"),
    ]));

    run_ok(
        Command::new(bin)
            .current_dir(&worktree_dir)
            .args(["rotate-key", "--auto-reencrypt"]),
    );
    run_ok(Command::new("git").current_dir(&worktree_dir).args([
        "commit",
        "-am",
        "rotate in worktree",
    ]));

    fs::write(secret_dir.join("oldbranch.env"), b"TOKEN=oldbranch\n")
        .expect("oldbranch secret should write");
    let (_, stderr) = run_fail(
        Command::new("git")
            .current_dir(repo)
            .args(["add", "secrets/oldbranch.env"]),
    );
    assert!(
        stderr.contains("unlock session key does not match this worktree manifest")
            || stderr.contains("clean filter")
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
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["add", "secrets/oldbranch.env"]),
    );
}

#[test]
fn unlock_with_encrypted_ssh_private_key_via_env_passphrase() {
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
    let passphrase = "integration-passphrase";
    let (private_key, public_key) =
        generate_encrypted_ed25519_keypair(&keys_dir, "id_ed25519_enc", passphrase);

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));
    configure_filter_paths(repo, bin);

    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .env("GSC_SSH_KEY_PASSPHRASE", passphrase)
            .args([
                "unlock",
                "--identity",
                private_key
                    .to_str()
                    .expect("private key path should be utf8"),
            ]),
    );

    let secret_dir = repo.join("secrets");
    fs::create_dir_all(&secret_dir).expect("secrets dir should create");
    let secret_file = secret_dir.join("enc.env");
    fs::write(&secret_file, b"TOKEN=encrypted_identity\n").expect("secret should write");
    run_ok(Command::new("git").current_dir(repo).args(["add", "."]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["commit", "-m", "encrypted key unlock"]),
    );

    let staged_blob = run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["show", "HEAD:secrets/enc.env"]),
    );
    assert!(staged_blob.starts_with(b"GSC1"));

    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .args(["lock", "--force"]),
    );
    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .env("GSC_SSH_KEY_PASSPHRASE", passphrase)
            .args([
                "unlock",
                "--identity",
                private_key
                    .to_str()
                    .expect("private key path should be utf8"),
            ]),
    );

    fs::remove_file(&secret_file).expect("secret file should be removable");
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["checkout", "--", "secrets/enc.env"]),
    );
    let unlocked_view = fs::read_to_string(&secret_file).expect("unlocked view should read utf8");
    assert_eq!(unlocked_view, "TOKEN=encrypted_identity\n");
}

#[test]
fn unlock_with_encrypted_ssh_private_key_fails_with_wrong_env_passphrase() {
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
    let passphrase = "integration-passphrase";
    let (private_key, public_key) =
        generate_encrypted_ed25519_keypair(&keys_dir, "id_ed25519_enc_bad", passphrase);

    run_ok(Command::new(bin).current_dir(repo).args([
        "init",
        "--pattern",
        "secrets/**",
        "--recipient-key",
        public_key.to_str().expect("public key path should be utf8"),
    ]));
    configure_filter_paths(repo, bin);

    let (_, stderr) = run_fail(
        Command::new(bin)
            .current_dir(repo)
            .env("GSC_SSH_KEY_PASSPHRASE", "wrong-passphrase")
            .args([
                "unlock",
                "--identity",
                private_key
                    .to_str()
                    .expect("private key path should be utf8"),
            ]),
    );
    assert!(
        stderr.contains("could not decrypt any wrapped key")
            || stderr.contains("key decryption")
            || stderr.contains("invalid passphrase")
    );
}

#[test]
fn negation_pattern_excludes_file_from_encryption() {
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
        "hosts/**",
        "--pattern",
        "!hosts/meta.nix",
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

    let hosts_dir = repo.join("hosts");
    fs::create_dir_all(&hosts_dir).expect("hosts dir should create");
    fs::write(hosts_dir.join("secret.nix"), b"{ key = \"private\"; }\n")
        .expect("secret file should write");
    fs::write(hosts_dir.join("meta.nix"), b"{ hostname = \"myhost\"; }\n")
        .expect("meta file should write");

    run_ok(Command::new("git").current_dir(repo).args(["add", "."]));
    run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["commit", "-m", "add hosts"]),
    );

    // secret.nix should be encrypted in the committed blob
    let secret_blob = run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["show", "HEAD:hosts/secret.nix"]),
    );
    assert!(
        secret_blob.starts_with(b"GSC1"),
        "secret.nix should be encrypted"
    );

    // meta.nix should remain plaintext in the committed blob
    let meta_blob = run_ok(
        Command::new("git")
            .current_dir(repo)
            .args(["show", "HEAD:hosts/meta.nix"]),
    );
    assert!(
        !meta_blob.starts_with(b"GSC1"),
        "meta.nix should NOT be encrypted"
    );
    assert_eq!(
        String::from_utf8(meta_blob).expect("meta blob should be utf8"),
        "{ hostname = \"myhost\"; }\n"
    );

    // verify --strict should pass (meta.nix is not counted as protected)
    run_ok(
        Command::new(bin)
            .current_dir(repo)
            .args(["verify", "--strict"]),
    );
}
