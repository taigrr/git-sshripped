#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<EOF
Usage: $(basename "$0") <patch|minor|major|VERSION>

Bump the version across all Cargo.toml and npm package.json files.

Examples:
  $(basename "$0") patch       # 0.1.3 → 0.1.4
  $(basename "$0") minor       # 0.1.3 → 0.2.0
  $(basename "$0") major       # 0.1.3 → 1.0.0
  $(basename "$0") 0.2.0-rc.1  # explicit version
EOF
  exit 1
}

if [ $# -ne 1 ]; then
  usage
fi

ARG="$1"

# Read current version from workspace Cargo.toml
CURRENT=$(grep '^version = ' "$REPO_ROOT/Cargo.toml" | head -1 | sed 's/version = "\(.*\)"/\1/')

if [ -z "$CURRENT" ]; then
  echo "error: could not read current version from Cargo.toml"
  exit 1
fi

# Parse current version into major.minor.patch
IFS='.' read -r CUR_MAJOR CUR_MINOR CUR_PATCH <<< "$CURRENT"

# Compute new version
case "$ARG" in
  patch)
    NEW_VERSION="${CUR_MAJOR}.${CUR_MINOR}.$((CUR_PATCH + 1))"
    ;;
  minor)
    NEW_VERSION="${CUR_MAJOR}.$((CUR_MINOR + 1)).0"
    ;;
  major)
    NEW_VERSION="$((CUR_MAJOR + 1)).0.0"
    ;;
  *)
    # Validate it looks like a version
    if ! echo "$ARG" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+'; then
      echo "error: '$ARG' does not look like a valid version (expected X.Y.Z)"
      exit 1
    fi
    NEW_VERSION="$ARG"
    ;;
esac

if [ "$CURRENT" = "$NEW_VERSION" ]; then
  echo "error: new version is the same as current version ($CURRENT)"
  exit 1
fi

echo "Bumping version: $CURRENT → $NEW_VERSION"
echo ""

# --- Cargo.toml ---
# Update workspace.package.version and workspace.dependencies entries for
# internal crates only.  Internal crate entries always contain "path =" while
# external deps from crates.io never do, so we use that to distinguish them
# and avoid accidentally bumping an unrelated dependency whose version string
# happens to match the current project version.
sed -i.bak \
  -e "s/^version = \"$CURRENT\"/version = \"$NEW_VERSION\"/" \
  -e "/path = /s/\"$CURRENT\"/\"$NEW_VERSION\"/g" \
  "$REPO_ROOT/Cargo.toml"
rm -f "$REPO_ROOT/Cargo.toml.bak"
echo "  updated Cargo.toml"

# --- npm package.json files (using jq for precision) ---

# Main package: update .version and all .optionalDependencies values
MAIN_PKG="$REPO_ROOT/npm/git-sshripped/package.json"
if [ -f "$MAIN_PKG" ]; then
  jq --arg v "$NEW_VERSION" '.version = $v | .optionalDependencies |= map_values($v)' "$MAIN_PKG" > "$MAIN_PKG.tmp"
  mv "$MAIN_PKG.tmp" "$MAIN_PKG"
  echo "  updated npm/git-sshripped/package.json"
fi

# Platform packages: update .version only
PLATFORM_PACKAGES=(
  "npm/darwin-arm64/package.json"
  "npm/darwin-x64/package.json"
  "npm/linux-arm64/package.json"
  "npm/linux-x64/package.json"
  "npm/linux-x64-musl/package.json"
  "npm/win32-x64/package.json"
)

for pkg in "${PLATFORM_PACKAGES[@]}"; do
  PKG_PATH="$REPO_ROOT/$pkg"
  if [ -f "$PKG_PATH" ]; then
    jq --arg v "$NEW_VERSION" '.version = $v' "$PKG_PATH" > "$PKG_PATH.tmp"
    mv "$PKG_PATH.tmp" "$PKG_PATH"
    echo "  updated $pkg"
  fi
done

# --- Verify Cargo.toml parses correctly ---
echo ""
echo "Running cargo check to verify..."
if (cd "$REPO_ROOT" && cargo check --quiet 2>&1); then
  echo "  cargo check passed"
else
  echo ""
  echo "error: cargo check failed after version bump"
  echo "You may need to manually fix Cargo.toml or run 'cargo update'"
  exit 1
fi

echo ""
echo "Done. Version bumped from $CURRENT to $NEW_VERSION across all packages."
echo ""
echo "Next steps:"
echo "  git add -A && git commit -m \"bump version to $NEW_VERSION\""
echo "  git tag v$NEW_VERSION"
echo "  git push origin main --tags"
