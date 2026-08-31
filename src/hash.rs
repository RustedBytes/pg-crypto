use blake2::{Blake2b512, Digest as _};
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use pgrx::prelude::*;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_512};

fn unknown_algorithm(kind: &str, algorithm: &str) -> ! {
    pgrx::error!("unknown {kind} algorithm: {algorithm}")
}

pub(crate) fn digest_bytes(data: &[u8], algorithm: &str) -> Vec<u8> {
    match algorithm.to_ascii_lowercase().replace('-', "").as_str() {
        "md5" => Md5::digest(data).to_vec(),
        "sha1" => Sha1::digest(data).to_vec(),
        "sha224" => Sha224::digest(data).to_vec(),
        "sha256" => Sha256::digest(data).to_vec(),
        "sha384" => Sha384::digest(data).to_vec(),
        "sha512" => Sha512::digest(data).to_vec(),
        "sha3256" => Sha3_256::digest(data).to_vec(),
        "sha3512" => Sha3_512::digest(data).to_vec(),
        "blake2b" | "blake2b512" => Blake2b512::digest(data).to_vec(),
        _ => unknown_algorithm("digest", algorithm),
    }
}

pub(crate) fn hmac_bytes(data: &[u8], key: &[u8], algorithm: &str) -> Vec<u8> {
    macro_rules! calculate {
        ($digest:ty) => {{
            let mut mac = Hmac::<$digest>::new_from_slice(key)
                .unwrap_or_else(|_| pgrx::error!("invalid HMAC key"));
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match algorithm.to_ascii_lowercase().replace('-', "").as_str() {
        "md5" => calculate!(Md5),
        "sha1" => calculate!(Sha1),
        "sha224" => calculate!(Sha224),
        "sha256" => calculate!(Sha256),
        "sha384" => calculate!(Sha384),
        "sha512" => calculate!(Sha512),
        "sha3256" => calculate!(Sha3_256),
        "sha3512" => calculate!(Sha3_512),
        _ => unknown_algorithm("HMAC", algorithm),
    }
}

#[pg_extern(name = "digest", immutable, parallel_safe)]
fn digest_bytea(data: &[u8], algorithm: &str) -> Vec<u8> {
    digest_bytes(data, algorithm)
}

#[pg_extern(name = "digest", immutable, parallel_safe)]
fn digest_text(data: &str, algorithm: &str) -> Vec<u8> {
    digest_bytes(data.as_bytes(), algorithm)
}

#[pg_extern(name = "hmac", immutable, parallel_safe)]
fn hmac_bytea(data: &[u8], key: &[u8], algorithm: &str) -> Vec<u8> {
    hmac_bytes(data, key, algorithm)
}

#[pg_extern(name = "hmac", immutable, parallel_safe)]
fn hmac_text(data: &str, key: &str, algorithm: &str) -> Vec<u8> {
    hmac_bytes(data.as_bytes(), key.as_bytes(), algorithm)
}

#[pg_extern(immutable, parallel_safe)]
fn blake2b(data: &[u8]) -> Vec<u8> {
    digest_bytes(data, "blake2b")
}

#[pg_extern(immutable, parallel_safe)]
fn sha3_256(data: &[u8]) -> Vec<u8> {
    digest_bytes(data, "sha3-256")
}

#[pg_extern(immutable, parallel_safe)]
fn sha3_512(data: &[u8]) -> Vec<u8> {
    digest_bytes(data, "sha3-512")
}

/// The extension is independent of OpenSSL, so OpenSSL FIPS mode is absent.
#[pg_extern(immutable, parallel_safe)]
fn fips_mode() -> bool {
    false
}
