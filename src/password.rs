use pgrx::prelude::*;
use pwhash::{HashSetup, bcrypt, bsdi_crypt, md5_crypt, sha256_crypt, sha512_crypt, unix_crypt};

fn password_error(context: &str, error: impl std::fmt::Display) -> ! {
    pgrx::error!("{context}: {error}")
}

#[pg_extern(immutable, parallel_safe)]
fn crypt(password: &str, salt: &str) -> String {
    pwhash::unix::crypt(password.as_bytes(), salt)
        .unwrap_or_else(|error| password_error("invalid salt", error))
}

fn salt_prefix(hash: &str, algorithm: &str) -> String {
    match algorithm {
        "bf" => hash[..29].replace("$2b$", "$2a$"),
        "des" => hash[..2].to_owned(),
        "xdes" => hash[..9].to_owned(),
        "md5" => {
            let end = hash[3..].find('$').map_or(hash.len(), |index| index + 4);
            hash[..end].to_owned()
        }
        "sha256crypt" | "sha512crypt" => {
            let mut separators = hash.match_indices('$').map(|(index, _)| index);
            let _ = separators.next();
            let _ = separators.next();
            let third = separators.next().unwrap_or(hash.len() - 1);
            let end = if hash.get(3..10) == Some("rounds=") {
                separators.next().unwrap_or(third)
            } else {
                third
            };
            hash[..=end].to_owned()
        }
        _ => unreachable!(),
    }
}

fn rounds_or_default(rounds: i32, default: u32) -> u32 {
    match rounds.cmp(&0) {
        std::cmp::Ordering::Equal => default,
        std::cmp::Ordering::Greater => rounds.cast_unsigned(),
        std::cmp::Ordering::Less => pgrx::error!("iteration count must be positive"),
    }
}

#[allow(deprecated)]
fn generate_salt(algorithm: &str, rounds: i32) -> String {
    let empty = b"";
    match algorithm {
        "bf" => {
            let cost = if rounds == 0 { 6 } else { rounds };
            if !(4..=31).contains(&cost) {
                pgrx::error!("bcrypt iteration count must be between 4 and 31");
            }
            let hash = bcrypt::hash_with(
                bcrypt::BcryptSetup {
                    cost: Some(cost.cast_unsigned()),
                    variant: Some(bcrypt::BcryptVariant::V2a),
                    ..Default::default()
                },
                empty,
            )
            .unwrap_or_else(|error| password_error("could not generate bcrypt salt", error));
            salt_prefix(&hash, algorithm)
        }
        "des" => {
            if !matches!(rounds, 0 | 25) {
                pgrx::error!("DES iteration count must be 25 when specified");
            }
            let hash = unix_crypt::hash(empty)
                .unwrap_or_else(|error| password_error("could not generate DES salt", error));
            salt_prefix(&hash, algorithm)
        }
        "xdes" => {
            let actual = rounds_or_default(rounds, 725);
            if actual > 16_777_215 || actual.is_multiple_of(2) {
                pgrx::error!("extended DES iteration count must be odd and at most 16777215");
            }
            let hash = bsdi_crypt::hash_with(
                HashSetup {
                    salt: None,
                    rounds: Some(actual),
                },
                empty,
            )
            .unwrap_or_else(|error| password_error("could not generate extended DES salt", error));
            salt_prefix(&hash, algorithm)
        }
        "md5" => {
            if !matches!(rounds, 0 | 1_000) {
                pgrx::error!("md5crypt iteration count must be 1000 when specified");
            }
            let hash = md5_crypt::hash(empty)
                .unwrap_or_else(|error| password_error("could not generate md5crypt salt", error));
            salt_prefix(&hash, algorithm)
        }
        "sha256crypt" => {
            let actual = rounds_or_default(rounds, sha256_crypt::DEFAULT_ROUNDS);
            if !(1_000..=999_999_999).contains(&actual) {
                pgrx::error!("sha256crypt iteration count must be between 1000 and 999999999");
            }
            let hash = sha256_crypt::hash_with(
                HashSetup {
                    salt: None,
                    rounds: Some(actual),
                },
                empty,
            )
            .unwrap_or_else(|error| password_error("could not generate sha256crypt salt", error));
            salt_prefix(&hash, algorithm)
        }
        "sha512crypt" => {
            let actual = rounds_or_default(rounds, sha512_crypt::DEFAULT_ROUNDS);
            if !(1_000..=999_999_999).contains(&actual) {
                pgrx::error!("sha512crypt iteration count must be between 1000 and 999999999");
            }
            let hash = sha512_crypt::hash_with(
                HashSetup {
                    salt: None,
                    rounds: Some(actual),
                },
                empty,
            )
            .unwrap_or_else(|error| password_error("could not generate sha512crypt salt", error));
            salt_prefix(&hash, algorithm)
        }
        _ => pgrx::error!("unknown salt algorithm: {algorithm}"),
    }
}

#[pg_extern(volatile, parallel_safe)]
fn gen_salt(algorithm: &str, rounds: default!(i32, 0)) -> String {
    generate_salt(&algorithm.to_ascii_lowercase(), rounds)
}
