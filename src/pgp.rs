use std::io::{Cursor, Read, Write};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use openpgp::crypto::{KeyPair, Password, S2K, SessionKey};
use openpgp::packet::{PKESK, SKESK, skesk::SKESK4};
use openpgp::parse::{
    PacketParser, Parse,
    stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper},
};
use openpgp::policy::NullPolicy;
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::{Compressor, Encryptor, LiteralWriter, Message};
use openpgp::types::{
    CompressionAlgorithm, CompressionLevel, DataFormat, HashAlgorithm, SymmetricAlgorithm,
};
use openpgp::{Cert, Packet, PacketPile};
use pgrx::prelude::*;
use sequoia_openpgp as openpgp;

fn pgp_error(context: &str, error: impl std::fmt::Display) -> ! {
    pgrx::error!("{context}: {error}")
}

#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // Mirrors independent pgcrypto options.
struct PgpOptions {
    cipher: SymmetricAlgorithm,
    compression: CompressionAlgorithm,
    compression_level: u8,
    text_input: bool,
    unicode_mode: bool,
    convert_crlf: bool,
    s2k_mode: u8,
    s2k_count: Option<u32>,
    s2k_digest: HashAlgorithm,
    s2k_cipher: Option<SymmetricAlgorithm>,
    use_session_key: bool,
}

impl Default for PgpOptions {
    fn default() -> Self {
        Self {
            cipher: SymmetricAlgorithm::AES128,
            compression: CompressionAlgorithm::Uncompressed,
            compression_level: 6,
            text_input: false,
            unicode_mode: false,
            convert_crlf: false,
            s2k_mode: 3,
            s2k_count: None,
            s2k_digest: HashAlgorithm::SHA1,
            s2k_cipher: None,
            use_session_key: false,
        }
    }
}

#[allow(deprecated)]
fn parse_boolean_option(name: &str, value: &str) -> bool {
    match value.trim() {
        "0" => false,
        "1" => true,
        other => pgrx::error!("{name} must be 0 or 1, got {other}"),
    }
}

#[allow(deprecated)]
fn parse_cipher(value: &str) -> SymmetricAlgorithm {
    match value.trim().to_ascii_lowercase().as_str() {
        "bf" | "blowfish" => SymmetricAlgorithm::Blowfish,
        "aes" | "aes128" => SymmetricAlgorithm::AES128,
        "aes192" => SymmetricAlgorithm::AES192,
        "aes256" => SymmetricAlgorithm::AES256,
        "3des" => SymmetricAlgorithm::TripleDES,
        "cast5" => SymmetricAlgorithm::CAST5,
        other => pgrx::error!("unsupported OpenPGP cipher: {other}"),
    }
}

#[allow(deprecated)]
fn parse_options(options: &str, text_input: bool) -> PgpOptions {
    let mut parsed = PgpOptions {
        text_input,
        ..Default::default()
    };
    for option in options
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let (name, value) = option
            .split_once('=')
            .unwrap_or_else(|| pgrx::error!("invalid PGP option: {option}"));
        match name.trim().to_ascii_lowercase().as_str() {
            "cipher-algo" => {
                parsed.cipher = parse_cipher(value);
            }
            "compress-algo" => {
                parsed.compression = match value.trim() {
                    "0" => CompressionAlgorithm::Uncompressed,
                    "1" => CompressionAlgorithm::Zip,
                    "2" => CompressionAlgorithm::Zlib,
                    other => pgrx::error!("compress-algo must be 0, 1, or 2, got {other}"),
                };
            }
            "compress-level" => {
                parsed.compression_level = value.trim().parse::<u8>().unwrap_or_else(|_| {
                    pgrx::error!("compress-level must be an integer from 0 to 9")
                });
                if parsed.compression_level > 9 {
                    pgrx::error!("compress-level must be an integer from 0 to 9");
                }
            }
            "unicode-mode" => {
                parsed.unicode_mode = parse_boolean_option(name, value);
            }
            "convert-crlf" => parsed.convert_crlf = parse_boolean_option(name, value),
            "s2k-mode" => {
                parsed.s2k_mode = value
                    .trim()
                    .parse::<u8>()
                    .unwrap_or_else(|_| pgrx::error!("s2k-mode must be 0, 1, or 3"));
                if !matches!(parsed.s2k_mode, 0 | 1 | 3) {
                    pgrx::error!("s2k-mode must be 0, 1, or 3");
                }
            }
            "s2k-digest-algo" => {
                parsed.s2k_digest = match value.trim().to_ascii_lowercase().as_str() {
                    "md5" => HashAlgorithm::MD5,
                    "sha1" => HashAlgorithm::SHA1,
                    other => pgrx::error!("unsupported S2K digest: {other}"),
                };
            }
            "s2k-cipher-algo" => {
                parsed.s2k_cipher = Some(match value.trim().to_ascii_lowercase().as_str() {
                    "bf" => SymmetricAlgorithm::Blowfish,
                    "aes" | "aes128" => SymmetricAlgorithm::AES128,
                    "aes192" => SymmetricAlgorithm::AES192,
                    "aes256" => SymmetricAlgorithm::AES256,
                    other => pgrx::error!("unsupported S2K cipher: {other}"),
                });
            }
            "s2k-count" => {
                let count = value
                    .trim()
                    .parse::<u32>()
                    .unwrap_or_else(|_| pgrx::error!("s2k-count must be an integer"));
                if !(1_024..=65_011_712).contains(&count) {
                    pgrx::error!("s2k-count must be between 1024 and 65011712");
                }
                parsed.s2k_count = Some(count);
            }
            "sess-key" => parsed.use_session_key = parse_boolean_option(name, value),
            "disable-mdc" => {
                if parse_boolean_option(name, value) {
                    pgrx::error!(
                        "generating OpenPGP messages without integrity protection is not supported"
                    );
                }
            }
            "ignore-cipher-failure" => {
                let _ = parse_boolean_option(name, value);
            }
            other => pgrx::error!("unknown PGP option: {other}"),
        }
    }
    if parsed.s2k_count.is_some() && parsed.s2k_mode != 3 {
        pgrx::error!("s2k-count requires s2k-mode=3");
    }
    parsed
}

fn default_s2k_count() -> openpgp::Result<u32> {
    const MIN: u32 = 65_536;
    const MAX: u32 = 253_952;
    let mut random = [0_u8; 4];
    openpgp::crypto::random(&mut random)?;
    Ok(MIN + u32::from_le_bytes(random) % (MAX - MIN + 1))
}

#[allow(deprecated)]
fn make_s2k(options: PgpOptions) -> openpgp::Result<S2K> {
    match options.s2k_mode {
        0 => Ok(S2K::Simple {
            hash: options.s2k_digest,
        }),
        1 => {
            let mut salt = [0_u8; 8];
            openpgp::crypto::random(&mut salt)?;
            Ok(S2K::Salted {
                hash: options.s2k_digest,
                salt,
            })
        }
        3 => S2K::new_iterated(
            options.s2k_digest,
            options.s2k_count.map_or_else(default_s2k_count, Ok)?,
        ),
        _ => unreachable!("validated S2K mode"),
    }
}

fn crlf_encode(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    for &byte in data {
        if byte == b'\n' {
            output.push(b'\r');
        }
        output.push(byte);
    }
    output
}

fn crlf_decode(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut index = 0;
    while index < data.len() {
        if data[index] == b'\r' && data.get(index + 1) == Some(&b'\n') {
            index += 1;
        }
        output.push(data[index]);
        index += 1;
    }
    output
}

#[derive(Clone, Copy, Default)]
struct DecryptOptions {
    convert_crlf: bool,
}

fn parse_decrypt_options(options: &str) -> DecryptOptions {
    let mut parsed = DecryptOptions::default();
    for option in options
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let (name, value) = option
            .split_once('=')
            .unwrap_or_else(|| pgrx::error!("invalid PGP option: {option}"));
        match name.trim().to_ascii_lowercase().as_str() {
            "convert-crlf" => parsed.convert_crlf = parse_boolean_option(name, value),
            "ignore-cipher-failure" => {
                // Sequoia safely decrypts valid packets regardless of this flag.  It does not
                // emulate pgcrypto's recovery path for historical ciphertext whose cipher
                // operation failed and whose packet body was consequently left as plaintext.
                let _ = parse_boolean_option(name, value);
            }
            // Encryption-only options are accepted and ignored on decrypt,
            // matching pgcrypto's behavior of reading them from the packet.
            "cipher-algo" | "compress-algo" | "compress-level" | "disable-mdc" | "sess-key"
            | "s2k-mode" | "s2k-count" | "s2k-digest-algo" | "s2k-cipher-algo" | "unicode-mode" => {
            }
            other => pgrx::error!("unknown PGP option: {other}"),
        }
    }
    parsed
}

const LITERAL_UNKNOWN: u8 = 0;
const LITERAL_BINARY: u8 = 1;
const LITERAL_TEXT: u8 = 2;
const LITERAL_UNICODE: u8 = 3;

#[allow(deprecated)]
fn inspect_literal_format(pp: &PacketParser, format: &AtomicU8) {
    if let Packet::Literal(literal) = &pp.packet {
        let value = match literal.format() {
            DataFormat::Binary => LITERAL_BINARY,
            DataFormat::Text => LITERAL_TEXT,
            DataFormat::Unicode => LITERAL_UNICODE,
            _ => LITERAL_UNKNOWN,
        };
        format.store(value, Ordering::Relaxed);
    }
}

fn decrypted_text(mut data: Vec<u8>, format: u8, options: DecryptOptions) -> String {
    if !matches!(format, LITERAL_TEXT | LITERAL_UNICODE) {
        pgrx::error!("decrypted OpenPGP data is not text");
    }
    if options.convert_crlf {
        data = crlf_decode(&data);
    }
    if data.contains(&0) {
        pgrx::error!("decrypted text contains a NUL byte");
    }
    String::from_utf8(data)
        .unwrap_or_else(|error| pgp_error("decrypted data is not valid UTF-8", error))
}

fn write_payload(
    mut message: Message<'_>,
    data: &[u8],
    options: PgpOptions,
) -> openpgp::Result<()> {
    if options.compression != CompressionAlgorithm::Uncompressed && options.compression_level > 0 {
        message = Compressor::new(message)
            .algo(options.compression)
            .level(CompressionLevel::new(options.compression_level)?)
            .build()?;
    }
    #[allow(deprecated)]
    let format = match (options.text_input, options.unicode_mode) {
        (false, _) => DataFormat::Binary,
        (true, false) => DataFormat::Text,
        (true, true) => DataFormat::Unicode,
    };
    let converted;
    let data = if options.text_input && options.convert_crlf {
        converted = crlf_encode(data);
        converted.as_slice()
    } else {
        data
    };
    let mut literal = LiteralWriter::new(message).format(format).build()?;
    literal.write_all(data)?;
    literal.finalize()?;
    Ok(())
}

fn sym_encrypt(data: &[u8], password: &str, options: &str, text: bool) -> Vec<u8> {
    let options = parse_options(options, text);
    let s2k = make_s2k(options)
        .unwrap_or_else(|error| pgp_error("could not initialize OpenPGP S2K", error));
    let s2k_cipher = options.s2k_cipher.unwrap_or(options.cipher);
    if !options.use_session_key && s2k_cipher != options.cipher {
        pgrx::error!("s2k-cipher-algo requires sess-key=1 when it differs from cipher-algo");
    }
    let password: Password = password.into();
    let session_key = if options.use_session_key {
        SessionKey::new(
            options
                .cipher
                .key_size()
                .unwrap_or_else(|error| pgp_error("unsupported OpenPGP cipher", error)),
        )
        .unwrap_or_else(|error| pgp_error("could not generate OpenPGP session key", error))
    } else {
        s2k.derive_key(
            &password,
            options
                .cipher
                .key_size()
                .unwrap_or_else(|error| pgp_error("unsupported OpenPGP cipher", error)),
        )
        .unwrap_or_else(|error| pgp_error("OpenPGP S2K derivation failed", error))
    };
    let skesk = if options.use_session_key {
        SKESK4::with_password(options.cipher, s2k_cipher, s2k, &session_key, &password)
            .unwrap_or_else(|error| pgp_error("could not create OpenPGP session key packet", error))
    } else {
        SKESK4::new(s2k_cipher, s2k, None)
            .unwrap_or_else(|error| pgp_error("could not create OpenPGP S2K packet", error))
    };
    let mut output = Vec::new();
    let mut message = Message::new(&mut output);
    Packet::SKESK(skesk.into())
        .serialize(&mut message)
        .unwrap_or_else(|error| pgp_error("could not serialize OpenPGP S2K packet", error));
    let message = Encryptor::with_session_key(message, options.cipher, session_key)
        .and_then(Encryptor::build)
        .unwrap_or_else(|error| pgp_error("could not initialize OpenPGP encryption", error));
    write_payload(message, data, options)
        .unwrap_or_else(|error| pgp_error("OpenPGP encryption failed", error));
    output
}

struct PasswordHelper {
    password: Password,
    literal_format: Arc<AtomicU8>,
}

impl VerificationHelper for PasswordHelper {
    fn inspect(&mut self, pp: &PacketParser) -> openpgp::Result<()> {
        inspect_literal_format(pp, &self.literal_format);
        Ok(())
    }

    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for PasswordHelper {
    fn decrypt(
        &mut self,
        _pkesks: &[PKESK],
        skesks: &[SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        for skesk in skesks {
            if skesk
                .decrypt(&self.password)
                .is_ok_and(|(algorithm, key)| decrypt(algorithm, &key))
            {
                return Ok(None);
            }
        }
        Err(openpgp::Error::InvalidOperation(
            "incorrect password or no symmetric session key".into(),
        )
        .into())
    }
}

fn sym_decrypt(data: &[u8], password: &str) -> (Vec<u8>, u8) {
    let policy = unsafe { NullPolicy::new() };
    let literal_format = Arc::new(AtomicU8::new(LITERAL_UNKNOWN));
    let helper = PasswordHelper {
        password: password.into(),
        literal_format: Arc::clone(&literal_format),
    };
    let mut decryptor = DecryptorBuilder::from_bytes(data)
        .unwrap_or_else(|error| pgp_error("invalid OpenPGP message", error))
        .with_policy(&policy, None, helper)
        .unwrap_or_else(|error| pgp_error("OpenPGP decryption failed", error));
    let mut output = Vec::new();
    decryptor
        .read_to_end(&mut output)
        .unwrap_or_else(|error| pgp_error("OpenPGP decryption failed", error));
    (output, literal_format.load(Ordering::Relaxed))
}

#[pg_extern(volatile, parallel_safe)]
fn pgp_sym_encrypt(data: &str, password: &str, options: default!(&str, "''")) -> Vec<u8> {
    sym_encrypt(data.as_bytes(), password, options, true)
}

#[pg_extern(volatile, parallel_safe)]
fn pgp_sym_encrypt_bytea(data: &[u8], password: &str, options: default!(&str, "''")) -> Vec<u8> {
    sym_encrypt(data, password, options, false)
}

#[pg_extern(immutable, parallel_safe)]
fn pgp_sym_decrypt(data: &[u8], password: &str, options: default!(&str, "''")) -> String {
    let options = parse_decrypt_options(options);
    let (data, format) = sym_decrypt(data, password);
    decrypted_text(data, format, options)
}

#[pg_extern(immutable, parallel_safe)]
fn pgp_sym_decrypt_bytea(data: &[u8], password: &str, options: default!(&str, "''")) -> Vec<u8> {
    let _ = parse_decrypt_options(options);
    sym_decrypt(data, password).0
}

fn pub_encrypt(data: &[u8], public_key: &[u8], options: &str, text: bool) -> Vec<u8> {
    let options = parse_options(options, text);
    let cert = Cert::from_bytes(public_key)
        .unwrap_or_else(|error| pgp_error("invalid OpenPGP public key", error));
    if cert.is_tsk() {
        pgrx::error!("a secret OpenPGP key cannot be used for public-key encryption");
    }
    let policy = unsafe { NullPolicy::new() };
    let recipients = cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();
    let mut output = Vec::new();
    let message = Encryptor::for_recipients(Message::new(&mut output), recipients)
        .symmetric_algo(options.cipher)
        .build()
        .unwrap_or_else(|error| pgp_error("no usable OpenPGP encryption key", error));
    write_payload(message, data, options)
        .unwrap_or_else(|error| pgp_error("OpenPGP public-key encryption failed", error));
    output
}

struct KeyHelper {
    pairs: Vec<KeyPair>,
    cert: Cert,
    literal_format: Arc<AtomicU8>,
}

impl VerificationHelper for KeyHelper {
    fn inspect(&mut self, pp: &PacketParser) -> openpgp::Result<()> {
        inspect_literal_format(pp, &self.literal_format);
        Ok(())
    }

    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for KeyHelper {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        for pkesk in pkesks {
            for pair in &mut self.pairs {
                if pkesk
                    .decrypt(pair, sym_algo)
                    .is_some_and(|(algorithm, key)| decrypt(algorithm, &key))
                {
                    return Ok(Some(self.cert.clone()));
                }
            }
        }
        Err(openpgp::Error::InvalidOperation(
            "message was not encrypted for the supplied key".into(),
        )
        .into())
    }
}

fn pub_decrypt(data: &[u8], secret_key: &[u8], password: &str) -> (Vec<u8>, u8) {
    let cert = Cert::from_bytes(secret_key)
        .unwrap_or_else(|error| pgp_error("invalid OpenPGP secret key", error));
    let password: Password = password.into();
    let mut pairs = Vec::new();
    for ka in cert.keys().secret() {
        let mut key = ka.key().clone();
        if key.secret().is_encrypted() {
            key = key
                .decrypt_secret(&password)
                .unwrap_or_else(|error| pgp_error("could not unlock OpenPGP secret key", error));
        }
        if let Ok(pair) = key.into_keypair() {
            pairs.push(pair);
        }
    }
    if pairs.is_empty() {
        pgrx::error!("OpenPGP secret key contains no usable key material");
    }
    let policy = unsafe { NullPolicy::new() };
    let literal_format = Arc::new(AtomicU8::new(LITERAL_UNKNOWN));
    let mut decryptor = DecryptorBuilder::from_bytes(data)
        .unwrap_or_else(|error| pgp_error("invalid OpenPGP message", error))
        .with_policy(
            &policy,
            None,
            KeyHelper {
                pairs,
                cert,
                literal_format: Arc::clone(&literal_format),
            },
        )
        .unwrap_or_else(|error| pgp_error("OpenPGP public-key decryption failed", error));
    let mut output = Vec::new();
    decryptor
        .read_to_end(&mut output)
        .unwrap_or_else(|error| pgp_error("OpenPGP public-key decryption failed", error));
    (output, literal_format.load(Ordering::Relaxed))
}

#[pg_extern(volatile, parallel_safe)]
fn pgp_pub_encrypt(data: &str, public_key: &[u8], options: default!(&str, "''")) -> Vec<u8> {
    pub_encrypt(data.as_bytes(), public_key, options, true)
}

#[pg_extern(volatile, parallel_safe)]
fn pgp_pub_encrypt_bytea(data: &[u8], public_key: &[u8], options: default!(&str, "''")) -> Vec<u8> {
    pub_encrypt(data, public_key, options, false)
}

#[pg_extern(immutable, parallel_safe)]
fn pgp_pub_decrypt(
    data: &[u8],
    secret_key: &[u8],
    password: default!(&str, "''"),
    options: default!(&str, "''"),
) -> String {
    let options = parse_decrypt_options(options);
    let (data, format) = pub_decrypt(data, secret_key, password);
    decrypted_text(data, format, options)
}

#[pg_extern(immutable, parallel_safe)]
fn pgp_pub_decrypt_bytea(
    data: &[u8],
    secret_key: &[u8],
    password: default!(&str, "''"),
    options: default!(&str, "''"),
) -> Vec<u8> {
    let _ = parse_decrypt_options(options);
    pub_decrypt(data, secret_key, password).0
}

#[pg_extern(immutable, parallel_safe)]
fn pgp_key_id(data: &[u8]) -> String {
    if let Ok(cert) = Cert::from_bytes(data) {
        let policy = unsafe { NullPolicy::new() };
        if let Some(key) = cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .next()
        {
            return key.key().keyid().to_hex();
        }
        pgrx::error!("OpenPGP key contains no usable encryption key");
    }
    let pile = PacketPile::from_reader(Cursor::new(data))
        .unwrap_or_else(|error| pgp_error("invalid OpenPGP data", error));
    for packet in pile.descendants() {
        match packet {
            Packet::PKESK(pkesk) => {
                return pkesk
                    .recipient()
                    .map_or_else(|| "ANYKEY".to_owned(), |id| id.to_hex());
            }
            Packet::SKESK(_) => return "SYMKEY".to_owned(),
            _ => {}
        }
    }
    pgrx::error!("OpenPGP data contains no encrypted session key")
}
