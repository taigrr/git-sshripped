#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use anyhow::{Result, bail};
use git_ssh_crypt_encryption::{decrypt, encrypt, is_encrypted};
use git_ssh_crypt_repository_models::RepositoryManifest;
use globset::{Glob, GlobSet, GlobSetBuilder};

struct ProtectedSet {
    include: GlobSet,
    exclude: GlobSet,
}

fn compile_protected_set(manifest: &RepositoryManifest) -> Result<ProtectedSet> {
    let mut include = GlobSetBuilder::new();
    let mut exclude = GlobSetBuilder::new();
    for pattern in &manifest.protected_patterns {
        if let Some(negated) = pattern.strip_prefix('!') {
            exclude.add(Glob::new(negated)?);
        } else {
            include.add(Glob::new(pattern)?);
        }
    }
    Ok(ProtectedSet {
        include: include.build()?,
        exclude: exclude.build()?,
    })
}

pub fn is_protected_path(manifest: &RepositoryManifest, path: &str) -> Result<bool> {
    let set = compile_protected_set(manifest)?;
    Ok(set.include.is_match(path) && !set.exclude.is_match(path))
}

pub fn clean(
    manifest: &RepositoryManifest,
    repo_key: Option<&[u8]>,
    path: &str,
    content: &[u8],
) -> Result<Vec<u8>> {
    if !is_protected_path(manifest, path)? {
        return Ok(content.to_vec());
    }

    if is_encrypted(content) {
        return Ok(content.to_vec());
    }

    let key = repo_key.ok_or_else(|| {
        anyhow::anyhow!(
            "repository is locked and cannot encrypt protected file '{}'; run git-ssh-crypt unlock",
            path
        )
    })?;
    encrypt(manifest.encryption_algorithm, key, path, content)
}

pub fn smudge(
    manifest: &RepositoryManifest,
    repo_key: Option<&[u8]>,
    path: &str,
    content: &[u8],
) -> Result<Vec<u8>> {
    if !is_protected_path(manifest, path)? {
        return Ok(content.to_vec());
    }

    if !is_encrypted(content) {
        return Ok(content.to_vec());
    }

    if let Some(key) = repo_key {
        return decrypt(key, path, content);
    }

    Ok(content.to_vec())
}

pub fn diff(
    manifest: &RepositoryManifest,
    repo_key: Option<&[u8]>,
    path: &str,
    content: &[u8],
) -> Result<Vec<u8>> {
    if !is_protected_path(manifest, path)? || !is_encrypted(content) {
        return Ok(content.to_vec());
    }

    if let Some(key) = repo_key {
        return decrypt(key, path, content);
    }

    bail!("file '{}' is encrypted and repository is locked", path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with_patterns(patterns: &[&str]) -> RepositoryManifest {
        RepositoryManifest {
            protected_patterns: patterns.iter().map(|s| (*s).to_string()).collect(),
            ..RepositoryManifest::default()
        }
    }

    #[test]
    fn simple_include_pattern_matches() {
        let m = manifest_with_patterns(&["secrets/**"]);
        assert!(is_protected_path(&m, "secrets/key.env").unwrap());
        assert!(is_protected_path(&m, "secrets/nested/deep.pem").unwrap());
        assert!(!is_protected_path(&m, "public/readme.md").unwrap());
    }

    #[test]
    fn negation_pattern_excludes_matching_path() {
        let m = manifest_with_patterns(&["secrets/**", "!secrets/README.md"]);
        assert!(is_protected_path(&m, "secrets/key.env").unwrap());
        assert!(!is_protected_path(&m, "secrets/README.md").unwrap());
    }

    #[test]
    fn negation_glob_excludes_subtree() {
        let m = manifest_with_patterns(&["hosts/bs-mbpro/**", "!hosts/bs-mbpro/meta.nix"]);
        assert!(is_protected_path(&m, "hosts/bs-mbpro/default.nix").unwrap());
        assert!(is_protected_path(&m, "hosts/bs-mbpro/home.nix").unwrap());
        assert!(!is_protected_path(&m, "hosts/bs-mbpro/meta.nix").unwrap());
    }

    #[test]
    fn negation_without_matching_include_protects_nothing() {
        let m = manifest_with_patterns(&["!foo.txt"]);
        assert!(!is_protected_path(&m, "foo.txt").unwrap());
        assert!(!is_protected_path(&m, "bar.txt").unwrap());
    }

    #[test]
    fn multiple_negation_patterns() {
        let m = manifest_with_patterns(&["data/**", "!data/public.txt", "!data/readme.md"]);
        assert!(is_protected_path(&m, "data/secret.key").unwrap());
        assert!(!is_protected_path(&m, "data/public.txt").unwrap());
        assert!(!is_protected_path(&m, "data/readme.md").unwrap());
    }

    #[test]
    fn negation_order_is_irrelevant() {
        let m1 = manifest_with_patterns(&["secrets/**", "!secrets/public.txt"]);
        let m2 = manifest_with_patterns(&["!secrets/public.txt", "secrets/**"]);
        assert_eq!(
            is_protected_path(&m1, "secrets/public.txt").unwrap(),
            is_protected_path(&m2, "secrets/public.txt").unwrap()
        );
        assert_eq!(
            is_protected_path(&m1, "secrets/private.key").unwrap(),
            is_protected_path(&m2, "secrets/private.key").unwrap()
        );
    }

    #[test]
    fn no_patterns_protects_nothing() {
        let m = manifest_with_patterns(&[]);
        assert!(!is_protected_path(&m, "anything.txt").unwrap());
    }

    #[test]
    fn negation_with_glob_wildcard_excludes_subtree() {
        let m = manifest_with_patterns(&["hosts/**", "!hosts/public/**"]);
        assert!(is_protected_path(&m, "hosts/private/secret.nix").unwrap());
        assert!(!is_protected_path(&m, "hosts/public/readme.md").unwrap());
        assert!(!is_protected_path(&m, "hosts/public/nested/file.txt").unwrap());
    }
}
