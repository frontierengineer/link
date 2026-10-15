//! Keys and ids (section 2). One 32-byte seed yields the node's Ed25519 identity and its X25519
//! session key; the node id is a hash of the Ed25519 public key.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::bytes::{b32, from_b32};
use crate::crypto::{clamp_x25519, hkdf_array, random_array, sha256, x25519_public};

/// A node's keys. Persist [`Identity::seed`]; everything else derives from it.
///
/// Secret material is zeroised when the identity is dropped, and `Debug` never prints it.
#[derive(Clone)]
pub struct Identity {
    seed: Zeroizing<[u8; 32]>,
    id: String,
    signing: SigningKey,
    ed25519_public: [u8; 32],
    x25519_private: Zeroizing<[u8; 32]>,
    x25519_public: [u8; 32],
}

impl Identity {
    /// A new identity from 32 bytes of the operating system's secure randomness.
    pub fn generate() -> Identity {
        let seed = Zeroizing::new(random_array::<32>());
        Identity::from_seed(&seed)
    }

    /// The identity a seed derives (section 2).
    pub fn from_seed(seed: &[u8; 32]) -> Identity {
        let ed_seed = hkdf_array::<32>(seed, &[], b"frontier-link/1/ed25519");
        let mut x_priv = hkdf_array::<32>(seed, &[], b"frontier-link/1/x25519");
        clamp_x25519(&mut x_priv);
        let signing = SigningKey::from_bytes(&ed_seed);
        let ed25519_public = signing.verifying_key().to_bytes();
        let id_bytes = node_id_bytes(&ed25519_public);
        Identity {
            seed: Zeroizing::new(*seed),
            id: b32(&id_bytes),
            signing,
            ed25519_public,
            x25519_public: x25519_public(&x_priv),
            x25519_private: x_priv,
        }
    }

    /// The 32-byte secret seed. It never leaves the node.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The node id: 26 lowercase base32 characters.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn ed25519_public(&self) -> [u8; 32] {
        self.ed25519_public
    }

    pub fn x25519_public(&self) -> [u8; 32] {
        self.x25519_public
    }

    /// The HKDF-derived Ed25519 seed (RFC 8032's private key). Secret.
    pub fn ed25519_seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// The clamped X25519 private key. Secret.
    pub fn x25519_private(&self) -> [u8; 32] {
        *self.x25519_private
    }

    pub(crate) fn x25519_private_ref(&self) -> &[u8; 32] {
        &self.x25519_private
    }

    /// An Ed25519 signature by this node.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity").field("id", &self.id).finish_non_exhaustive()
    }
}

/// `SHA-256(ed25519Public)[0..16]`.
pub fn node_id_bytes(ed25519_public: &[u8; 32]) -> [u8; 16] {
    let h = sha256(ed25519_public);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

/// `b32(SHA-256(ed25519Public)[0..16])`.
pub fn node_id_from_ed25519(ed25519_public: &[u8; 32]) -> String {
    b32(&node_id_bytes(ed25519_public))
}

/// Whether `s` is a node id in its one canonical form: 26 characters of lowercase base32.
pub fn is_node_id(s: &str) -> bool {
    node_id_to_bytes(s).is_some()
}

/// The raw 16 bytes a frame's `peer` field carries.
pub fn node_id_to_bytes(s: &str) -> Option<[u8; 16]> {
    if s.len() != 26 {
        return None;
    }
    from_b32(s)?.try_into().ok()
}

pub fn node_id_from_bytes(b: &[u8; 16]) -> String {
    b32(b)
}
