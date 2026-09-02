use base64::Engine;
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};

/// What the app sees when it has to decide whether to trust a server.
///
/// `fingerprint` is the OpenSSH-style `SHA256:<base64>` string, which is what
/// users compare against `ssh-keygen -lf`. `public_key` is the raw key blob in
/// base64 (the second column of a `known_hosts` line) so the app can pin the
/// full key rather than only the fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub algorithm: String,
    pub fingerprint: String,
    pub public_key: String,
}

/// Smallest RSA modulus (bits) accepted for host keys and user keys.
/// 1024-bit RSA is factorable with academic budgets; OpenSSH's own floor is
/// 1024 for compatibility, we take the NIST-recommended 2048.
pub const MIN_RSA_BITS: u32 = 2048;

/// `Some(bits)` when `key` is RSA and smaller than [`MIN_RSA_BITS`].
pub fn weak_rsa_bits(key: &PublicKey) -> Option<u32> {
    match key.key_data() {
        russh::keys::ssh_key::public::KeyData::Rsa(rsa) => {
            let bits = rsa.key_size();
            (bits < MIN_RSA_BITS).then_some(bits)
        }
        _ => None,
    }
}

impl HostKey {
    pub fn from_public_key(key: &PublicKey) -> Self {
        let blob = key.to_bytes().unwrap_or_default();
        HostKey {
            algorithm: key.algorithm().as_str().to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            public_key: base64::engine::general_purpose::STANDARD.encode(blob),
        }
    }

    pub fn from_server_key(key: &PublicKeyOrCertificate) -> Self {
        match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => Self::from_public_key(key),
            PublicKeyOrCertificate::Certificate(cert) => {
                let pk = PublicKey::from(cert.public_key().clone());
                let mut hk = Self::from_public_key(&pk);
                hk.algorithm = cert.algorithm().as_str().to_string();
                hk
            }
        }
    }

    /// `<algorithm> <base64>` — the format used by `authorized_keys` and
    /// `known_hosts`.
    pub fn openssh(&self) -> String {
        format!("{} {}", self.algorithm, self.public_key)
    }
}
