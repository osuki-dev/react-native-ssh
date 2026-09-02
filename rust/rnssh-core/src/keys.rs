//! Key generation and inspection. Private key material never leaves Rust in
//! any form other than the PEM string the app explicitly asked for.

use russh::keys::ssh_key::{self, Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey};
use russh::keys::{PublicKey, decode_secret_key};
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result, SshError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyType {
    Ed25519 = 0,
    EcdsaP256 = 1,
    EcdsaP384 = 2,
    Rsa3072 = 3,
    Rsa4096 = 4,
}

impl KeyType {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => KeyType::Ed25519,
            1 => KeyType::EcdsaP256,
            2 => KeyType::EcdsaP384,
            3 => KeyType::Rsa3072,
            4 => KeyType::Rsa4096,
            _ => return None,
        })
    }
}

/// A freshly generated key pair. `private_key` is OpenSSH PEM
/// (`-----BEGIN OPENSSH PRIVATE KEY-----`), encrypted if a passphrase was given.
/// `public_key` is a single `authorized_keys` line.
#[derive(Clone)]
pub struct KeyPair {
    pub private_key: Zeroizing<String>,
    pub public_key: String,
    pub fingerprint: String,
}

/// Metadata about a private key the app already holds, for validation and
/// display without ever handing the secret to JS again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub comment: String,
    pub encrypted: bool,
}

pub fn generate_key_pair(
    key_type: KeyType,
    comment: Option<&str>,
    passphrase: Option<&str>,
) -> Result<KeyPair> {
    let mut rng = rand::rng();
    let algorithm = match key_type {
        KeyType::Ed25519 => Algorithm::Ed25519,
        KeyType::EcdsaP256 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        KeyType::EcdsaP384 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        KeyType::Rsa3072 | KeyType::Rsa4096 => Algorithm::Rsa { hash: None },
    };

    let mut key = match key_type {
        KeyType::Rsa3072 => rsa_key(&mut rng, 3072)?,
        KeyType::Rsa4096 => rsa_key(&mut rng, 4096)?,
        _ => PrivateKey::random(&mut rng, algorithm)?,
    };
    if let Some(c) = comment {
        key.set_comment(c);
    }

    let public_key = key.public_key().to_openssh()?;
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();

    let pem = match passphrase {
        Some(p) if !p.is_empty() => key.encrypt(&mut rng, p)?.to_openssh(LineEnding::LF)?,
        _ => key.to_openssh(LineEnding::LF)?,
    };

    Ok(KeyPair {
        private_key: Zeroizing::new(pem.to_string()),
        public_key,
        fingerprint,
    })
}

fn rsa_key<R: ssh_key::rand_core::CryptoRng + ?Sized>(
    rng: &mut R,
    bits: usize,
) -> Result<PrivateKey> {
    let keypair = ssh_key::private::RsaKeypair::random(rng, bits)?;
    Ok(PrivateKey::new(keypair.into(), "")?)
}

/// Parse (and, if needed, decrypt) a private key in any format russh accepts:
/// OpenSSH, PKCS#8, PKCS#1 PEM, or PuTTY PPK.
pub fn parse_private_key(pem: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    let key = parse_private_key_unchecked(pem, passphrase)?;
    if let Some(bits) = crate::hostkey::weak_rsa_bits(key.public_key()) {
        return Err(SshError::new(
            ErrorCode::Key,
            format!(
                "RSA key is {bits}-bit; at least {} bits are required (generate an Ed25519 key instead)",
                crate::hostkey::MIN_RSA_BITS
            ),
        ));
    }
    Ok(key)
}

fn parse_private_key_unchecked(pem: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    let pass = passphrase.filter(|p| !p.is_empty());
    decode_secret_key(pem, pass).map_err(|e| {
        let msg = e.to_string();
        let code = ErrorCode::Key;
        if pass.is_none() && looks_encrypted(pem) {
            SshError::new(
                code,
                format!("private key is encrypted and no passphrase was given ({msg})"),
            )
        } else {
            SshError::new(code, msg)
        }
    })
}

pub fn inspect_private_key(pem: &str, passphrase: Option<&str>) -> Result<KeyInfo> {
    let encrypted = looks_encrypted(pem);
    let key = parse_private_key(pem, passphrase)?;
    let public: &PublicKey = key.public_key();
    Ok(KeyInfo {
        algorithm: key.algorithm().as_str().to_string(),
        public_key: public.to_openssh()?,
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        comment: key.comment().to_string(),
        encrypted,
    })
}

fn looks_encrypted(pem: &str) -> bool {
    if let Ok(k) = PrivateKey::from_openssh(pem) {
        return k.is_encrypted();
    }
    pem.contains("ENCRYPTED") || pem.contains("Encryption: aes")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    #[test]
    fn ed25519_roundtrip() {
        let kp = generate_key_pair(KeyType::Ed25519, Some("test@rnssh"), None).unwrap();
        assert!(
            kp.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert!(kp.public_key.starts_with("ssh-ed25519 "));
        assert!(kp.public_key.ends_with("test@rnssh"));
        assert!(kp.fingerprint.starts_with("SHA256:"));
        let info = inspect_private_key(&kp.private_key, None).unwrap();
        assert_eq!(info.fingerprint, kp.fingerprint);
        assert_eq!(info.comment, "test@rnssh");
        assert!(!info.encrypted);
    }

    #[test]
    fn encrypted_key_requires_passphrase() {
        let kp = generate_key_pair(KeyType::EcdsaP256, None, Some("hunter2")).unwrap();
        let err = inspect_private_key(&kp.private_key, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::Key);
        let info = inspect_private_key(&kp.private_key, Some("hunter2")).unwrap();
        assert!(info.encrypted);
        assert_eq!(info.algorithm, "ecdsa-sha2-nistp256");
    }

    #[test]
    fn rsa_generation_works() {
        let kp = generate_key_pair(KeyType::Rsa3072, None, None).unwrap();
        assert!(kp.public_key.starts_with("ssh-rsa "));
    }
}
