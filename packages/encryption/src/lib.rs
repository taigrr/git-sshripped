#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use anyhow::{Context, Result};
use git_ssh_crypt_encryption_models::{
    ENCRYPTED_MAGIC, EncryptedHeader, EncryptionAlgorithm, EncryptionModelsError,
};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

#[cfg(feature = "crypto-aes-siv")]
use aes_siv::Aes256SivAead;
#[cfg(feature = "crypto-aes-siv")]
use aes_siv::aead::generic_array::GenericArray;
#[cfg(feature = "crypto-aes-siv")]
use aes_siv::aead::{Aead, KeyInit, Payload};

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("plaintext does not appear to be encrypted")]
    NotEncrypted,
    #[error("invalid encrypted header")]
    InvalidHeader,
    #[error("unsupported encryption algorithm")]
    UnsupportedAlgorithm(EncryptionAlgorithm),
}

fn derive_key_material(repo_key: &[u8]) -> Result<[u8; 64]> {
    let hk = Hkdf::<Sha256>::new(Some(b"git-ssh-crypt:aes-siv:v1"), repo_key);
    let mut out = [0_u8; 64];
    hk.expand(b"file-key", &mut out)
        .map_err(|_| anyhow::anyhow!("failed to derive aes-siv key"))?;
    Ok(out)
}

#[must_use]
pub fn is_encrypted(content: &[u8]) -> bool {
    content.starts_with(&ENCRYPTED_MAGIC)
}

pub fn encrypt(
    algorithm: EncryptionAlgorithm,
    repo_key: &[u8],
    path: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if is_encrypted(plaintext) {
        return Ok(plaintext.to_vec());
    }

    match algorithm {
        EncryptionAlgorithm::AesSivV1 => encrypt_aes_siv(repo_key, path.as_bytes(), plaintext),
    }
}

pub fn decrypt(repo_key: &[u8], path: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
    let (header, ciphertext) = parse_header(encrypted)?;

    match header.algorithm {
        EncryptionAlgorithm::AesSivV1 => decrypt_aes_siv(repo_key, path.as_bytes(), ciphertext),
    }
}

fn parse_header(input: &[u8]) -> Result<(EncryptedHeader, &[u8])> {
    if input.len() < 6 || !input.starts_with(&ENCRYPTED_MAGIC) {
        return Err(EncryptionError::NotEncrypted.into());
    }

    let version = input[4];
    let algorithm = EncryptionAlgorithm::from_id(input[5]).map_err(|err| match err {
        EncryptionModelsError::UnknownAlgorithm(_) | EncryptionModelsError::InvalidHeader => {
            EncryptionError::InvalidHeader
        }
    })?;

    Ok((EncryptedHeader { version, algorithm }, &input[6..]))
}

#[cfg(feature = "crypto-aes-siv")]
fn encrypt_aes_siv(repo_key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key_material = derive_key_material(repo_key)?;
    let key = GenericArray::from_slice(&key_material);
    let cipher = Aes256SivAead::new(key);
    let nonce = GenericArray::from_slice(&[0_u8; 16]);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .context("failed to encrypt content with aes-siv")?;

    let mut out = Vec::with_capacity(6 + ciphertext.len());
    out.extend_from_slice(&ENCRYPTED_MAGIC);
    out.push(1);
    out.push(EncryptionAlgorithm::AesSivV1.id());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

#[cfg(not(feature = "crypto-aes-siv"))]
fn encrypt_aes_siv(_repo_key: &[u8], _aad: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>> {
    Err(EncryptionError::UnsupportedAlgorithm(EncryptionAlgorithm::AesSivV1).into())
}

#[cfg(feature = "crypto-aes-siv")]
fn decrypt_aes_siv(repo_key: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key_material = derive_key_material(repo_key)?;
    let key = GenericArray::from_slice(&key_material);
    let cipher = Aes256SivAead::new(key);
    let nonce = GenericArray::from_slice(&[0_u8; 16]);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .context("failed to decrypt content with aes-siv")
}

#[cfg(not(feature = "crypto-aes-siv"))]
fn decrypt_aes_siv(_repo_key: &[u8], _aad: &[u8], _ciphertext: &[u8]) -> Result<Vec<u8>> {
    Err(EncryptionError::UnsupportedAlgorithm(EncryptionAlgorithm::AesSivV1).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ALGO: EncryptionAlgorithm = EncryptionAlgorithm::AesSivV1;
    const KEY: [u8; 32] = [7_u8; 32];

    proptest! {
        #[test]
        fn encrypt_decrypt_roundtrip(path in "[a-zA-Z0-9_/.-]{1,64}", data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let encrypted = encrypt(ALGO, &KEY, &path, &data).expect("encryption should succeed");
            prop_assert!(encrypted.starts_with(&ENCRYPTED_MAGIC));
            let decrypted = decrypt(&KEY, &path, &encrypted).expect("decryption should succeed");
            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn deterministic_encryption(path in "[a-zA-Z0-9_/.-]{1,64}", data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let a = encrypt(ALGO, &KEY, &path, &data).expect("encryption should succeed");
            let b = encrypt(ALGO, &KEY, &path, &data).expect("encryption should succeed");
            prop_assert_eq!(a, b);
        }

        #[test]
        fn path_binding_rejects_wrong_path(path_a in "[a-zA-Z0-9_/.-]{1,64}", path_b in "[a-zA-Z0-9_/.-]{1,64}", data in proptest::collection::vec(any::<u8>(), 0..256)) {
            prop_assume!(path_a != path_b);
            let encrypted = encrypt(ALGO, &KEY, &path_a, &data).expect("encryption should succeed");
            let wrong = decrypt(&KEY, &path_b, &encrypted);
            prop_assert!(wrong.is_err());
        }
    }

    #[test]
    fn tamper_detection_rejects_modified_ciphertext() {
        let path = "secrets/app.env";
        let plaintext = b"TOKEN=abc\n";
        let mut encrypted =
            encrypt(ALGO, &KEY, path, plaintext).expect("encryption should succeed");
        let last = encrypted
            .len()
            .checked_sub(1)
            .expect("encrypted content should not be empty");
        encrypted[last] ^= 0x01;

        let decrypted = decrypt(&KEY, path, &encrypted);
        assert!(decrypted.is_err());
    }
}
