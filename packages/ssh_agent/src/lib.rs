#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use ssh_agent_client_rs::Client;
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, LineEnding, SshSig};

pub use git_sshripped_ssh_agent_models::AgentWrappedKey;

/// Domain separator prepended to the challenge before signing, preventing
/// cross-protocol signature reuse.
const DOMAIN_SEPARATOR: &[u8] = b"git-sshripped-agent-v1";

/// HKDF info string for deriving the wrapping key from a signature.
const HKDF_INFO: &[u8] = b"git-sshripped-agent-wrap-v1";

/// Default SSH signature namespace for interactive access challenges.
pub const DEFAULT_SSHSIG_NAMESPACE: &str = "git-sshripped-access-v1";

/// An SSH key available in the running SSH agent.
#[derive(Debug, Clone)]
pub struct AgentKey {
    /// Fingerprint in git-sshripped's format: `base64url_no_pad(SHA256(key_type + ":" + key_data))`.
    pub fingerprint: String,
    /// The parsed public key (used to request signatures from the agent).
    pub public_key: ssh_key::PublicKey,
}

/// A challenge proof signed by an SSH key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeProof {
    /// Fingerprint of the signing public key.
    pub fingerprint: String,
    /// Public key in OpenSSH line format.
    pub public_key_openssh: String,
    /// Signature encoded in OpenSSH SSHSIG PEM format.
    pub signature_pem: String,
}

/// Compute a fingerprint in the same format that git-sshripped uses for
/// recipient files and wrapped key filenames.
///
/// The format is `base64url_no_pad(SHA256("key_type:base64_key_data"))`,
/// e.g. `nUy4xy4qXy07aLaplZjYi1K3ybk5-0XS8PWNkGb8vxk`.
#[must_use]
pub fn fingerprint_for_public_key_line(openssh_line: &str) -> Option<String> {
    let mut parts = openssh_line.split_whitespace();
    let key_type = parts.next()?;
    let key_body = parts.next()?;

    let mut hasher = Sha256::new();
    hasher.update(key_type.as_bytes());
    hasher.update([b':']);
    hasher.update(key_body.as_bytes());
    Some(BASE64URL.encode(hasher.finalize()))
}

/// Connect to the SSH agent and list all available Ed25519 keys.
///
/// Returns an empty vec if `SSH_AUTH_SOCK` is not set or the agent is
/// unreachable.
///
/// # Errors
///
/// Returns an error only on unexpected I/O failures *after* a successful
/// connection.  A missing `SSH_AUTH_SOCK` or connection refusal is treated
/// as "no agent" and returns `Ok(vec![])`.
pub fn list_agent_ed25519_keys() -> Result<Vec<AgentKey>> {
    let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") else {
        return Ok(Vec::new());
    };
    let sock_path = Path::new(&sock);
    let Ok(mut client) = Client::connect(sock_path) else {
        return Ok(Vec::new());
    };
    let identities = client
        .list_all_identities()
        .context("failed to list SSH agent identities")?;

    let mut keys = Vec::new();
    for identity in identities {
        let pubkey: &ssh_key::PublicKey = match &identity {
            ssh_agent_client_rs::Identity::PublicKey(boxed_cow) => boxed_cow.as_ref(),
            ssh_agent_client_rs::Identity::Certificate(_) => continue,
        };
        if !matches!(pubkey.key_data(), KeyData::Ed25519(_)) {
            continue;
        }
        let openssh_line = pubkey
            .to_openssh()
            .context("failed encoding SSH public key")?;
        let Some(fingerprint) = fingerprint_for_public_key_line(&openssh_line) else {
            continue;
        };
        keys.push(AgentKey {
            fingerprint,
            public_key: pubkey.clone(),
        });
    }
    Ok(keys)
}

/// Build the data blob that gets signed by the agent.
fn sign_payload(challenge: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(DOMAIN_SEPARATOR.len() + challenge.len());
    payload.extend_from_slice(DOMAIN_SEPARATOR);
    payload.extend_from_slice(challenge);
    payload
}

/// Sign an SSHSIG challenge with a specific SSH agent key.
///
/// # Errors
///
/// Returns an error if the SSH agent is unavailable, refuses to sign, or if
/// signature encoding fails.
pub fn sign_challenge_with_agent_key(
    challenge: &[u8],
    namespace: &str,
    agent_key: &AgentKey,
) -> Result<ChallengeProof> {
    let signed_data =
        SshSig::signed_data(namespace, HashAlg::Sha256, challenge).context("invalid challenge")?;
    let signature = sign_message_with_agent(agent_key, &signed_data)?;
    let sshsig = SshSig::new(
        agent_key.public_key.key_data().clone(),
        namespace,
        HashAlg::Sha256,
        signature,
    )
    .context("failed building SSH signature")?;
    let public_key_openssh = agent_key
        .public_key
        .to_openssh()
        .context("failed encoding SSH public key")?;
    let signature_pem = sshsig
        .to_pem(LineEnding::LF)
        .context("failed encoding SSH signature")?;

    Ok(ChallengeProof {
        fingerprint: agent_key.fingerprint.clone(),
        public_key_openssh,
        signature_pem,
    })
}

/// Sign a challenge with the best available SSH agent key.
///
/// Prefers keys whose fingerprints are listed in `preferred_fingerprints`.
/// If no preference matches, falls back to the first available Ed25519 agent
/// key.
///
/// # Errors
///
/// Returns an error if querying the SSH agent fails or signature generation
/// fails for the selected key.
pub fn sign_challenge_with_any_agent_key(
    challenge: &[u8],
    namespace: &str,
    preferred_fingerprints: &[String],
) -> Result<Option<ChallengeProof>> {
    let agent_keys = list_agent_ed25519_keys()?;
    if agent_keys.is_empty() {
        return Ok(None);
    }

    let selected = preferred_fingerprints
        .iter()
        .find_map(|fingerprint| {
            agent_keys
                .iter()
                .find(|candidate| candidate.fingerprint == *fingerprint)
        })
        .unwrap_or(&agent_keys[0]);

    let proof = sign_challenge_with_agent_key(challenge, namespace, selected)?;
    Ok(Some(proof))
}

/// Verify a challenge proof signed with an SSH key.
///
/// # Errors
///
/// Returns an error if the public key or signature cannot be parsed, if the
/// fingerprint does not match the public key, or if signature verification
/// fails.
pub fn verify_challenge_proof(
    challenge: &[u8],
    namespace: &str,
    proof: &ChallengeProof,
) -> Result<()> {
    let computed = fingerprint_for_public_key_line(&proof.public_key_openssh)
        .ok_or_else(|| anyhow::anyhow!("challenge proof contains an invalid public key"))?;
    if computed != proof.fingerprint {
        anyhow::bail!("challenge proof fingerprint does not match public key");
    }

    verify_challenge_signature(
        challenge,
        namespace,
        &proof.public_key_openssh,
        &proof.signature_pem,
    )
}

/// Verify an SSHSIG challenge signature for a specific public key.
///
/// # Errors
///
/// Returns an error if the public key or signature cannot be parsed, or if
/// signature verification fails.
pub fn verify_challenge_signature(
    challenge: &[u8],
    namespace: &str,
    public_key_openssh: &str,
    signature_pem: &str,
) -> Result<()> {
    let public_key = ssh_key::PublicKey::from_openssh(public_key_openssh)
        .context("invalid OpenSSH public key")?;
    let signature = SshSig::from_pem(signature_pem).context("invalid SSH signature PEM")?;
    public_key
        .verify(namespace, challenge, &signature)
        .context("SSH challenge signature verification failed")
}

/// Derive a 32-byte `ChaCha20Poly1305` key from an Ed25519 signature.
fn derive_wrap_key(signature_bytes: &[u8], challenge: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(challenge), signature_bytes);
    let mut key: [u8; 32] = rand::random();
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(key)
}

/// Wrap (encrypt) a repo key using the SSH agent.
///
/// Asks the agent to sign a fresh random challenge with `agent_key`, then
/// derives a symmetric key and encrypts `repo_key`.
///
/// # Errors
///
/// Returns an error if the agent refuses to sign or a cryptographic
/// operation fails.
pub fn agent_wrap_repo_key(agent_key: &AgentKey, repo_key: &[u8]) -> Result<AgentWrappedKey> {
    let challenge: [u8; 32] = rand::random();

    let signature = sign_with_agent(agent_key, &challenge)?;
    let wrap_key = derive_wrap_key(&signature, &challenge)?;

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);
    let cipher = ChaCha20Poly1305::new_from_slice(&wrap_key)
        .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 key init failed: {e}"))?;
    let ciphertext = cipher
        .encrypt(&nonce, repo_key)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    Ok(AgentWrappedKey {
        version: 1,
        fingerprint: agent_key.fingerprint.clone(),
        challenge: BASE64.encode(challenge),
        nonce: BASE64.encode(nonce_bytes),
        encrypted_repo_key: BASE64.encode(ciphertext),
    })
}

/// Unwrap (decrypt) a repo key using the SSH agent.
///
/// Asks the agent to re-sign the stored challenge, derives the same
/// symmetric key, and decrypts. Returns `Ok(None)` if the AEAD tag does
/// not verify (wrong key or non-deterministic agent).
///
/// # Errors
///
/// Returns an error on I/O or base64-decoding failures.
pub fn agent_unwrap_repo_key(
    agent_key: &AgentKey,
    wrapped: &AgentWrappedKey,
) -> Result<Option<Vec<u8>>> {
    let challenge = BASE64
        .decode(&wrapped.challenge)
        .context("invalid base64 in agent-wrap challenge")?;
    let nonce_bytes = BASE64
        .decode(&wrapped.nonce)
        .context("invalid base64 in agent-wrap nonce")?;
    let ciphertext = BASE64
        .decode(&wrapped.encrypted_repo_key)
        .context("invalid base64 in agent-wrap ciphertext")?;

    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let signature = sign_with_agent(agent_key, &challenge)?;
    let wrap_key = derive_wrap_key(&signature, &challenge)?;

    let cipher = ChaCha20Poly1305::new_from_slice(&wrap_key)
        .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 key init failed: {e}"))?;

    Ok(cipher.decrypt(nonce, ciphertext.as_ref()).ok()) // Tag mismatch returns None: wrong key or non-deterministic agent
}

/// Ask the SSH agent to sign a challenge with the given key, returning the
/// raw signature bytes.
fn sign_with_agent(agent_key: &AgentKey, challenge: &[u8]) -> Result<Vec<u8>> {
    let payload = sign_payload(challenge);
    let signature = sign_message_with_agent(agent_key, &payload)?;
    Ok(extract_ed25519_signature_bytes(&signature))
}

/// Ask the SSH agent to sign raw bytes with the given key.
fn sign_message_with_agent(agent_key: &AgentKey, payload: &[u8]) -> Result<ssh_key::Signature> {
    let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") else {
        anyhow::bail!("SSH_AUTH_SOCK is not set");
    };
    let sock_path = Path::new(&sock);
    let mut client =
        Client::connect(sock_path).context("failed to connect to SSH agent for signing")?;
    let signature = client
        .sign(&agent_key.public_key, payload)
        .context("SSH agent refused to sign")?;

    Ok(signature)
}

/// Extract the raw 64-byte Ed25519 signature from the SSH wire format.
///
/// The `ssh-key` crate's `Signature` contains algorithm-prefixed data;
/// for Ed25519 the raw bytes are the 64-byte signature itself.
fn extract_ed25519_signature_bytes(sig: &ssh_key::Signature) -> Vec<u8> {
    sig.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::{
        ChallengeProof, DEFAULT_SSHSIG_NAMESPACE, fingerprint_for_public_key_line,
        verify_challenge_proof,
    };
    use ssh_key::{HashAlg, LineEnding, PrivateKey};

    const TEST_PRIVATE_KEY: &str = r"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn challenge_proof_verification_accepts_valid_signature() {
        let private_key: PrivateKey = TEST_PRIVATE_KEY.parse().expect("parse test private key");
        let challenge = b"bmux challenge";
        let signature = private_key
            .sign(DEFAULT_SSHSIG_NAMESPACE, HashAlg::Sha256, challenge)
            .expect("sign challenge");
        let public_key_openssh = private_key
            .public_key()
            .to_openssh()
            .expect("encode public key");
        let fingerprint =
            fingerprint_for_public_key_line(&public_key_openssh).expect("derive fingerprint");
        let proof = ChallengeProof {
            fingerprint,
            public_key_openssh,
            signature_pem: signature
                .to_pem(LineEnding::LF)
                .expect("encode signature PEM"),
        };

        verify_challenge_proof(challenge, DEFAULT_SSHSIG_NAMESPACE, &proof)
            .expect("proof should verify");
    }

    #[test]
    fn challenge_proof_verification_rejects_fingerprint_mismatch() {
        let private_key: PrivateKey = TEST_PRIVATE_KEY.parse().expect("parse test private key");
        let challenge = b"bmux challenge";
        let signature = private_key
            .sign(DEFAULT_SSHSIG_NAMESPACE, HashAlg::Sha256, challenge)
            .expect("sign challenge");
        let public_key_openssh = private_key
            .public_key()
            .to_openssh()
            .expect("encode public key");
        let mut proof = ChallengeProof {
            fingerprint: "invalid-fingerprint".to_string(),
            public_key_openssh,
            signature_pem: signature
                .to_pem(LineEnding::LF)
                .expect("encode signature PEM"),
        };

        let result = verify_challenge_proof(challenge, DEFAULT_SSHSIG_NAMESPACE, &proof);
        assert!(result.is_err());

        proof.fingerprint = fingerprint_for_public_key_line(&proof.public_key_openssh)
            .expect("derive real fingerprint");
        verify_challenge_proof(challenge, DEFAULT_SSHSIG_NAMESPACE, &proof)
            .expect("proof should verify once fingerprint is corrected");
    }
}
