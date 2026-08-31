use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
};
use pgrx::prelude::*;

#[derive(Clone, Copy)]
enum Algorithm {
    Aes,
    Blowfish,
}

#[derive(Clone, Copy)]
enum Mode {
    Cbc,
    Cfb,
    Ecb,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Padding {
    Pkcs,
    None,
}

fn raw_error(message: &str) -> ! {
    pgrx::error!("raw cipher error: {message}")
}

fn parse_type(cipher_type: &str) -> (Algorithm, Mode, Padding) {
    let normalized = cipher_type.to_ascii_lowercase();
    let (cipher_mode, padding) =
        normalized
            .split_once('/')
            .map_or((normalized.as_str(), Padding::Pkcs), |(left, right)| {
                let padding = match right {
                    "pad:pkcs" => Padding::Pkcs,
                    "pad:none" => Padding::None,
                    _ => raw_error("padding must be pad:pkcs or pad:none"),
                };
                (left, padding)
            });
    let (algorithm, mode) = match cipher_mode {
        "aes" | "aes-cbc" | "rijndael" | "rijndael-cbc" => (Algorithm::Aes, Mode::Cbc),
        "aes-cfb" | "rijndael-cfb" => (Algorithm::Aes, Mode::Cfb),
        "aes-ecb" | "rijndael-ecb" => (Algorithm::Aes, Mode::Ecb),
        "bf" | "bf-cbc" | "blowfish" | "blowfish-cbc" => (Algorithm::Blowfish, Mode::Cbc),
        "bf-cfb" | "blowfish-cfb" => (Algorithm::Blowfish, Mode::Cfb),
        "bf-ecb" | "blowfish-ecb" => (Algorithm::Blowfish, Mode::Ecb),
        _ => raw_error("cipher must be aes or bf with cbc, cfb, or ecb mode"),
    };
    (algorithm, mode, padding)
}

fn fixed<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut output = [0; N];
    let count = input.len().min(N);
    output[..count].copy_from_slice(&input[..count]);
    output
}

enum AesKey {
    Aes128([u8; 16]),
    Aes192([u8; 24]),
    Aes256([u8; 32]),
}

fn aes_key(input: &[u8]) -> AesKey {
    match input.len() {
        0..=16 => AesKey::Aes128(fixed(input)),
        17..=24 => AesKey::Aes192(fixed(input)),
        25..=32 => AesKey::Aes256(fixed(input)),
        _ => raw_error("AES key must not exceed 32 bytes"),
    }
}

macro_rules! encrypt_aes_with {
    ($cipher:ty, $key:expr, $iv:expr, $mode:expr, $padding:expr, $data:expr) => {{
        match $mode {
            Mode::Cbc => match $padding {
                Padding::Pkcs => cbc::Encryptor::<$cipher>::new(&$key.into(), &$iv.into())
                    .encrypt_padded_vec::<Pkcs7>($data),
                Padding::None => cbc::Encryptor::<$cipher>::new(&$key.into(), &$iv.into())
                    .encrypt_padded_vec::<NoPadding>($data),
            },
            Mode::Ecb => match $padding {
                Padding::Pkcs => {
                    ecb::Encryptor::<$cipher>::new(&$key.into()).encrypt_padded_vec::<Pkcs7>($data)
                }
                Padding::None => ecb::Encryptor::<$cipher>::new(&$key.into())
                    .encrypt_padded_vec::<NoPadding>($data),
            },
            Mode::Cfb => {
                let mut output = $data.to_vec();
                cfb_mode::Encryptor::<$cipher>::new(&$key.into(), &$iv.into()).encrypt(&mut output);
                output
            }
        }
    }};
}

macro_rules! decrypt_aes_with {
    ($cipher:ty, $key:expr, $iv:expr, $mode:expr, $padding:expr, $data:expr) => {{
        match $mode {
            Mode::Cbc => match $padding {
                Padding::Pkcs => cbc::Decryptor::<$cipher>::new(&$key.into(), &$iv.into())
                    .decrypt_padded_vec::<Pkcs7>($data)
                    .unwrap_or_else(|_| raw_error("invalid ciphertext or padding")),
                Padding::None => cbc::Decryptor::<$cipher>::new(&$key.into(), &$iv.into())
                    .decrypt_padded_vec::<NoPadding>($data)
                    .unwrap_or_else(|_| raw_error("ciphertext is not block aligned")),
            },
            Mode::Ecb => match $padding {
                Padding::Pkcs => ecb::Decryptor::<$cipher>::new(&$key.into())
                    .decrypt_padded_vec::<Pkcs7>($data)
                    .unwrap_or_else(|_| raw_error("invalid ciphertext or padding")),
                Padding::None => ecb::Decryptor::<$cipher>::new(&$key.into())
                    .decrypt_padded_vec::<NoPadding>($data)
                    .unwrap_or_else(|_| raw_error("ciphertext is not block aligned")),
            },
            Mode::Cfb => {
                let mut output = $data.to_vec();
                cfb_mode::Decryptor::<$cipher>::new(&$key.into(), &$iv.into()).decrypt(&mut output);
                output
            }
        }
    }};
}

fn encrypt_aes(data: &[u8], key: &[u8], iv: &[u8], mode: Mode, padding: Padding) -> Vec<u8> {
    let iv = fixed::<16>(iv);
    match aes_key(key) {
        AesKey::Aes128(key) => encrypt_aes_with!(Aes128, key, iv, mode, padding, data),
        AesKey::Aes192(key) => encrypt_aes_with!(Aes192, key, iv, mode, padding, data),
        AesKey::Aes256(key) => encrypt_aes_with!(Aes256, key, iv, mode, padding, data),
    }
}

fn decrypt_aes(data: &[u8], key: &[u8], iv: &[u8], mode: Mode, padding: Padding) -> Vec<u8> {
    let iv = fixed::<16>(iv);
    match aes_key(key) {
        AesKey::Aes128(key) => decrypt_aes_with!(Aes128, key, iv, mode, padding, data),
        AesKey::Aes192(key) => decrypt_aes_with!(Aes192, key, iv, mode, padding, data),
        AesKey::Aes256(key) => decrypt_aes_with!(Aes256, key, iv, mode, padding, data),
    }
}

fn blowfish_key(key: &[u8]) -> Vec<u8> {
    let mut output = key[..key.len().min(56)].to_vec();
    if !output.is_empty() && output.len() < 4 {
        let original = output.clone();
        while output.len() < 4 {
            output.extend_from_slice(&original);
        }
    }
    output
}

fn encrypt_blowfish(data: &[u8], key: &[u8], iv: &[u8], mode: Mode, padding: Padding) -> Vec<u8> {
    let key = blowfish_key(key);
    let iv = fixed::<8>(iv);
    match mode {
        Mode::Cbc => match padding {
            Padding::Pkcs => cbc::Encryptor::<Blowfish>::new_from_slices(&key, &iv)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .encrypt_padded_vec::<Pkcs7>(data),
            Padding::None => cbc::Encryptor::<Blowfish>::new_from_slices(&key, &iv)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .encrypt_padded_vec::<NoPadding>(data),
        },
        Mode::Ecb => match padding {
            Padding::Pkcs => ecb::Encryptor::<Blowfish>::new_from_slice(&key)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .encrypt_padded_vec::<Pkcs7>(data),
            Padding::None => ecb::Encryptor::<Blowfish>::new_from_slice(&key)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .encrypt_padded_vec::<NoPadding>(data),
        },
        Mode::Cfb => {
            let mut output = data.to_vec();
            cfb_mode::Encryptor::<Blowfish>::new_from_slices(&key, &iv)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .encrypt(&mut output);
            output
        }
    }
}

fn decrypt_blowfish(data: &[u8], key: &[u8], iv: &[u8], mode: Mode, padding: Padding) -> Vec<u8> {
    let key = blowfish_key(key);
    let iv = fixed::<8>(iv);
    match mode {
        Mode::Cbc => match padding {
            Padding::Pkcs => cbc::Decryptor::<Blowfish>::new_from_slices(&key, &iv)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .decrypt_padded_vec::<Pkcs7>(data)
                .unwrap_or_else(|_| raw_error("invalid ciphertext or padding")),
            Padding::None => cbc::Decryptor::<Blowfish>::new_from_slices(&key, &iv)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .decrypt_padded_vec::<NoPadding>(data)
                .unwrap_or_else(|_| raw_error("ciphertext is not block aligned")),
        },
        Mode::Ecb => match padding {
            Padding::Pkcs => ecb::Decryptor::<Blowfish>::new_from_slice(&key)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .decrypt_padded_vec::<Pkcs7>(data)
                .unwrap_or_else(|_| raw_error("invalid ciphertext or padding")),
            Padding::None => ecb::Decryptor::<Blowfish>::new_from_slice(&key)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .decrypt_padded_vec::<NoPadding>(data)
                .unwrap_or_else(|_| raw_error("ciphertext is not block aligned")),
        },
        Mode::Cfb => {
            let mut output = data.to_vec();
            cfb_mode::Decryptor::<Blowfish>::new_from_slices(&key, &iv)
                .unwrap_or_else(|_| raw_error("invalid Blowfish key"))
                .decrypt(&mut output);
            output
        }
    }
}

fn transform(data: &[u8], key: &[u8], iv: &[u8], cipher_type: &str, decrypting: bool) -> Vec<u8> {
    let (algorithm, mode, padding) = parse_type(cipher_type);
    match (algorithm, decrypting) {
        (Algorithm::Aes, false) => encrypt_aes(data, key, iv, mode, padding),
        (Algorithm::Aes, true) => decrypt_aes(data, key, iv, mode, padding),
        (Algorithm::Blowfish, false) => encrypt_blowfish(data, key, iv, mode, padding),
        (Algorithm::Blowfish, true) => decrypt_blowfish(data, key, iv, mode, padding),
    }
}

#[pg_extern(immutable, parallel_safe)]
fn encrypt(data: &[u8], key: &[u8], cipher_type: &str) -> Vec<u8> {
    transform(data, key, &[], cipher_type, false)
}

#[pg_extern(immutable, parallel_safe)]
fn decrypt(data: &[u8], key: &[u8], cipher_type: &str) -> Vec<u8> {
    transform(data, key, &[], cipher_type, true)
}

#[pg_extern(immutable, parallel_safe)]
fn encrypt_iv(data: &[u8], key: &[u8], iv: &[u8], cipher_type: &str) -> Vec<u8> {
    transform(data, key, iv, cipher_type, false)
}

#[pg_extern(immutable, parallel_safe)]
fn decrypt_iv(data: &[u8], key: &[u8], iv: &[u8], cipher_type: &str) -> Vec<u8> {
    transform(data, key, iv, cipher_type, true)
}
