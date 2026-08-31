use dryoc::constants::{
    CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SEALBYTES, CRYPTO_BOX_SECRETKEYBYTES, CRYPTO_SIGN_BYTES,
};
use dryoc::dryocaead::{DryocAeadEnvelope, Key as AeadKey, VecEnvelope};
use dryoc::dryocbox::{
    DryocBox, KeyPair as BoxKeyPair, Mac as BoxMac, PublicKey as BoxPublicKey,
    SecretKey as BoxSecretKey, VecBox,
};
use dryoc::dryocsecretbox::{
    DryocSecretBox, Key as SecretBoxKey, Nonce as SecretBoxNonce, VecBox as SecretVecBox,
};
use dryoc::pwhash::{PwHash, VecPwHash};
use dryoc::sign::{
    PublicKey as SignPublicKey, SecretKey as SignSecretKey, Signature, SigningKeyPair,
};
use dryoc::types::{NewByteArray, StackByteArray};
use hkdf::SimpleHkdf;
use pgrx::prelude::*;
use sha2::{Sha256, Sha512};

fn crypto_error(context: &str, error: impl std::fmt::Display) -> ! {
    pgrx::error!("{context}: {error}")
}

fn exact_array<const N: usize>(bytes: &[u8], what: &str) -> StackByteArray<N> {
    StackByteArray::try_from(bytes)
        .unwrap_or_else(|_| pgrx::error!("{what} must be exactly {N} bytes"))
}

#[pg_extern(volatile, parallel_safe)]
fn argon2id_hash(password: &str) -> String {
    let hash = VecPwHash::hash_with_defaults(&password.as_bytes())
        .unwrap_or_else(|error| crypto_error("Argon2id hashing failed", error));
    hash.to_encoded_string()
        .unwrap_or_else(|error| crypto_error("Argon2id encoding failed", error))
}

#[pg_extern(immutable, parallel_safe)]
fn argon2id_verify(password: &str, encoded_hash: &str) -> bool {
    PwHash::from_string_with_defaults(encoded_hash)
        .and_then(|hash| hash.verify(&password.as_bytes()))
        .is_ok()
}

/// Returns `nonce || ciphertext || tag`, dryoc's self-contained envelope.
#[pg_extern(volatile, parallel_safe)]
fn xchacha20poly1305_encrypt(
    data: &[u8],
    key: &[u8],
    associated_data: default!(&[u8], "''::bytea"),
) -> Vec<u8> {
    let key: AeadKey = exact_array(key, "XChaCha20-Poly1305 key");
    DryocAeadEnvelope::seal_to_vec(data, Some(associated_data), &key)
        .unwrap_or_else(|error| crypto_error("XChaCha20-Poly1305 encryption failed", error))
        .into_vec()
}

#[pg_extern(immutable, parallel_safe)]
fn xchacha20poly1305_decrypt(
    data: &[u8],
    key: &[u8],
    associated_data: default!(&[u8], "''::bytea"),
) -> Vec<u8> {
    let key: AeadKey = exact_array(key, "XChaCha20-Poly1305 key");
    let envelope = VecEnvelope::from_bytes(data)
        .unwrap_or_else(|error| crypto_error("invalid XChaCha20-Poly1305 envelope", error));
    envelope
        .open_to_vec(Some(associated_data), &key)
        .unwrap_or_else(|error| crypto_error("XChaCha20-Poly1305 authentication failed", error))
}

/// Returns `nonce || mac || ciphertext`; the nonce is generated for each call.
#[pg_extern(volatile, parallel_safe)]
fn secretbox(data: &[u8], key: &[u8]) -> Vec<u8> {
    let key: SecretBoxKey = exact_array(key, "secretbox key");
    let nonce = SecretBoxNonce::generate();
    let encrypted = DryocSecretBox::encrypt_to_vecbox(data, &nonce, &key);
    let mut output = nonce.to_vec();
    output.extend_from_slice(&encrypted.to_vec());
    output
}

#[pg_extern(immutable, parallel_safe)]
fn secretbox_open(data: &[u8], key: &[u8]) -> Vec<u8> {
    const NONCE_BYTES: usize = dryoc::constants::CRYPTO_SECRETBOX_NONCEBYTES;
    if data.len() < NONCE_BYTES + dryoc::constants::CRYPTO_SECRETBOX_MACBYTES {
        pgrx::error!("secretbox envelope is too short");
    }
    let key: SecretBoxKey = exact_array(key, "secretbox key");
    let nonce: SecretBoxNonce = exact_array(&data[..NONCE_BYTES], "secretbox nonce");
    SecretVecBox::from_bytes(&data[NONCE_BYTES..])
        .unwrap_or_else(|error| crypto_error("invalid secretbox envelope", error))
        .decrypt_to_vec(&nonce, &key)
        .unwrap_or_else(|error| crypto_error("secretbox authentication failed", error))
}

#[pg_extern(volatile, parallel_safe)]
fn box_seal(data: &[u8], recipient_public_key: &[u8]) -> Vec<u8> {
    let public_key: BoxPublicKey = exact_array(recipient_public_key, "X25519 public key");
    DryocBox::seal_to_vecbox(data, &public_key)
        .unwrap_or_else(|error| crypto_error("sealed-box encryption failed", error))
        .to_bytes::<Vec<u8>>()
}

#[pg_extern(immutable, parallel_safe)]
fn box_seal_open(data: &[u8], recipient_public_key: &[u8], recipient_secret_key: &[u8]) -> Vec<u8> {
    if data.len() < CRYPTO_BOX_SEALBYTES {
        pgrx::error!("sealed box is too short");
    }
    let public_key: BoxPublicKey = exact_array(recipient_public_key, "X25519 public key");
    let secret_key: BoxSecretKey = exact_array(recipient_secret_key, "X25519 secret key");
    let keypair = BoxKeyPair {
        public_key,
        secret_key,
    };
    let ephemeral_public_key: BoxPublicKey = exact_array(
        &data[..CRYPTO_BOX_PUBLICKEYBYTES],
        "sealed-box ephemeral public key",
    );
    let mac: BoxMac = exact_array(
        &data[CRYPTO_BOX_PUBLICKEYBYTES..CRYPTO_BOX_SEALBYTES],
        "sealed-box MAC",
    );
    VecBox::new_with_epk_data_and_mac(ephemeral_public_key, mac, &data[CRYPTO_BOX_SEALBYTES..])
        .unseal_to_vec(&keypair)
        .unwrap_or_else(|error| crypto_error("sealed-box authentication failed", error))
}

#[pg_extern(immutable, parallel_safe)]
fn ed25519_sign(data: &[u8], secret_key: &[u8]) -> Vec<u8> {
    let secret_key: SignSecretKey = exact_array(secret_key, "Ed25519 secret key");
    let public_key = dryoc::sign::secret_key_to_public_key::<SignPublicKey, _>(&secret_key);
    let keypair = SigningKeyPair {
        public_key,
        secret_key,
    };
    keypair
        .sign_with_defaults(data)
        .unwrap_or_else(|error| crypto_error("Ed25519 signing failed", error))
        .to_vec()[..CRYPTO_SIGN_BYTES]
        .to_vec()
}

#[pg_extern(immutable, parallel_safe)]
fn ed25519_verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    let signature: Signature = exact_array(signature, "Ed25519 signature");
    let public_key: SignPublicKey = exact_array(public_key, "Ed25519 public key");
    let mut signed = signature.to_vec();
    signed.extend_from_slice(data);
    dryoc::sign::VecSignedMessage::from_bytes(&signed)
        .and_then(|message| message.verify(&public_key))
        .is_ok()
}

#[pg_extern(immutable, parallel_safe)]
fn x25519(secret_key: &[u8], public_key: &[u8]) -> Vec<u8> {
    let secret: [u8; CRYPTO_BOX_SECRETKEYBYTES] = secret_key.try_into().unwrap_or_else(|_| {
        pgrx::error!("X25519 secret key must be exactly {CRYPTO_BOX_SECRETKEYBYTES} bytes")
    });
    let public: [u8; CRYPTO_BOX_PUBLICKEYBYTES] = public_key.try_into().unwrap_or_else(|_| {
        pgrx::error!("X25519 public key must be exactly {CRYPTO_BOX_PUBLICKEYBYTES} bytes")
    });
    let mut shared = [0u8; CRYPTO_BOX_SECRETKEYBYTES];
    dryoc::classic::crypto_core::crypto_scalarmult(&mut shared, &secret, &public)
        .unwrap_or_else(|error| crypto_error("X25519 key agreement failed", error));
    shared.to_vec()
}

fn validate_hkdf_length(length: i32) -> Vec<u8> {
    if !(1..=16_320).contains(&length) {
        pgrx::error!("HKDF output length must be between 1 and 16320 bytes");
    }
    vec![0; usize::try_from(length).expect("positive HKDF length")]
}

#[pg_extern(immutable, parallel_safe)]
fn hkdf_sha256(key_material: &[u8], salt: &[u8], info: &[u8], length: i32) -> Vec<u8> {
    let mut output = validate_hkdf_length(length);
    SimpleHkdf::<Sha256>::new(Some(salt), key_material)
        .expand(info, &mut output)
        .unwrap_or_else(|_| pgrx::error!("HKDF-SHA256 output length is too large"));
    output
}

#[pg_extern(immutable, parallel_safe)]
fn hkdf_sha512(key_material: &[u8], salt: &[u8], info: &[u8], length: i32) -> Vec<u8> {
    let mut output = validate_hkdf_length(length);
    SimpleHkdf::<Sha512>::new(Some(salt), key_material)
        .expand(info, &mut output)
        .unwrap_or_else(|_| pgrx::error!("HKDF-SHA512 output length is too large"));
    output
}
