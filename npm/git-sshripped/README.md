# git-sshripped

Git-transparent encryption using SSH keys. No GPG, no Rust toolchain required.

This is the npm distribution of [git-sshripped](https://github.com/BSteffaniak/git-sshripped), a tool that keeps selected files encrypted at rest in Git repositories while letting developers work with plaintext when the repo is unlocked.

## Install

```bash
npm install git-sshripped
```

This installs a prebuilt native binary for your platform. No Rust or Cargo needed.

## Usage

### CLI

Once installed, `git-sshripped` is available as a command:

```bash
# Initialize in a repo
git-sshripped init --pattern "secrets/**"

# Unlock (decrypt files for local development)
git-sshripped unlock

# Lock (scrub plaintext from working tree)
git-sshripped lock

# Check status
git-sshripped status
```

### Auto-unlock in postinstall

Add this to your project's `package.json` so that encrypted files are automatically decrypted after `npm install`:

```json
{
  "scripts": {
    "postinstall": "git-sshripped unlock --soft"
  }
}
```

The `--soft` flag ensures that `npm install` won't fail if the user doesn't have access to the encrypted files (e.g., they don't have the right SSH key, or they're a CI bot without credentials). A warning is printed instead.

For strict mode (fail if unlock fails):

```json
{
  "scripts": {
    "postinstall": "git-sshripped unlock"
  }
}
```

### Programmatic API

```js
const { binaryPath, run } = require("git-sshripped");

// Get the path to the binary
console.log(binaryPath);

// Spawn git-sshripped with arguments
const child = run(["status", "--json"]);
child.on("exit", (code) => {
  console.log("exit code:", code);
});
```

## Binary resolution

The binary is resolved in this order:

1. `GIT_SSHRIPPED_BINARY_PATH` environment variable
2. Platform-specific npm package (installed automatically via `optionalDependencies`)
3. System-installed `git-sshripped` found in `PATH`

## Supported platforms

| Platform | Architecture | npm package |
|----------|-------------|-------------|
| macOS | ARM64 (Apple Silicon) | `@git-sshripped/darwin-arm64` |
| macOS | x64 (Intel) | `@git-sshripped/darwin-x64` |
| Linux | x64 (glibc) | `@git-sshripped/linux-x64` |
| Linux | ARM64 (glibc) | `@git-sshripped/linux-arm64` |
| Linux | x64 (musl/Alpine) | `@git-sshripped/linux-x64-musl` |
| Windows | x64 | `@git-sshripped/win32-x64` |

## License

MPL-2.0
