"use strict";

const { platform, arch } = process;
const { execSync, spawn } = require("child_process");
const { env } = process;

function isMusl() {
  if (platform !== "linux") return false;
  try {
    const stderr = execSync("ldd --version 2>&1", {
      stdio: ["pipe", "pipe", "pipe"],
    }).toString();
    if (stderr.indexOf("musl") > -1) return true;
  } catch (err) {
    if (err.stderr && err.stderr.toString().indexOf("musl") > -1) return true;
  }
  return false;
}

const PLATFORMS = {
  win32: {
    x64: "@git-sshripped/win32-x64/git-sshripped.exe",
  },
  darwin: {
    x64: "@git-sshripped/darwin-x64/git-sshripped",
    arm64: "@git-sshripped/darwin-arm64/git-sshripped",
  },
  linux: {
    x64: "@git-sshripped/linux-x64/git-sshripped",
    arm64: "@git-sshripped/linux-arm64/git-sshripped",
  },
  "linux-musl": {
    x64: "@git-sshripped/linux-x64-musl/git-sshripped",
  },
};

/**
 * Resolves the path to the git-sshripped binary.
 *
 * Resolution order:
 * 1. GIT_SSHRIPPED_BINARY_PATH environment variable
 * 2. Platform-specific npm package
 * 3. System-installed binary in PATH
 *
 * @returns {string} Absolute path to the binary
 * @throws {Error} If no binary can be found
 */
function getBinaryPath() {
  if (env.GIT_SSHRIPPED_BINARY_PATH) {
    return env.GIT_SSHRIPPED_BINARY_PATH;
  }

  const platformKey =
    platform === "linux" && isMusl() ? "linux-musl" : platform;
  const subpath = PLATFORMS?.[platformKey]?.[arch];

  if (subpath) {
    try {
      return require.resolve(subpath);
    } catch {
      // Platform package not installed
    }
  }

  try {
    const which = platform === "win32" ? "where" : "which";
    const resolved = execSync(`${which} git-sshripped`, {
      stdio: ["pipe", "pipe", "pipe"],
    })
      .toString()
      .trim()
      .split("\n")[0];
    if (resolved) return resolved;
  } catch {
    // Not found in PATH
  }

  throw new Error(
    `No prebuilt git-sshripped binary available for ${platform}/${arch}. ` +
      `Install via cargo (cargo install git_sshripped_cli) or set GIT_SSHRIPPED_BINARY_PATH.`
  );
}

/**
 * The resolved path to the git-sshripped binary.
 * @type {string}
 */
const binaryPath = getBinaryPath();

/**
 * Spawn git-sshripped with the given arguments.
 *
 * @param {string[]} args - Command-line arguments to pass
 * @param {import("child_process").SpawnOptions} [options] - Options passed to child_process.spawn
 * @returns {import("child_process").ChildProcess}
 */
function run(args, options) {
  return spawn(binaryPath, args, { stdio: "inherit", ...options });
}

module.exports = { binaryPath, run };
