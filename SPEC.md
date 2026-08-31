dryoc is fundamentally a pure-Rust libsodium/NaCl-style library. Its current surface includes Curve25519/Ed25519, XSalsa20/ChaCha20-Poly1305, Argon2, BLAKE2b, SHA-256/512, SHA-3, HMAC-SHA256/512, KDFs, CSPRNG, secret streams, etc.

The incompatibilities with `pgcrypto` are substantial.

| `pgcrypto` capability       |          dryoc | Enough for compatible implementation? |
| --------------------------- | -------------: | ------------------------------------: |
| `digest(..., 'sha256')`     |              ✅ |                                     ✅ |
| `digest(..., 'sha512')`     |              ✅ |                                     ✅ |
| SHA-3 extensions            |              ✅ |                      Extra capability |
| `digest(..., 'md5')`        |              ❌ |                                     ❌ |
| `digest(..., 'sha1')`       |              ❌ |                                     ❌ |
| `digest(..., 'sha224')`     |              ❌ |                                     ❌ |
| `digest(..., 'sha384')`     |              ❌ |                                     ❌ |
| HMAC-SHA256                 |              ✅ |                                     ✅ |
| HMAC-SHA512                 |              ✅ |                                     ✅ |
| HMAC-MD5/SHA1/SHA224/SHA384 |              ❌ |                                     ❌ |
| CSPRNG                      |              ✅ |                                     ✅ |
| UUID v4                     | easy using RNG |                                     ✅ |
| Argon2                      |              ✅ |                      Extra capability |
| `crypt(..., bf)` bcrypt     |              ❌ |                                     ❌ |
| `crypt(..., md5)`           |              ❌ |                                     ❌ |
| `crypt(..., des/xdes)`      |              ❌ |                                     ❌ |
| `sha256crypt`               |              ❌ |                                     ❌ |
| `sha512crypt`               |              ❌ |                                     ❌ |
| AES-128/192/256             |              ❌ |                                     ❌ |
| AES-CBC                     |              ❌ |                                     ❌ |
| AES-CFB                     |              ❌ |                                     ❌ |
| AES-ECB                     |              ❌ |                                     ❌ |
| Blowfish                    |              ❌ |                                     ❌ |
| Blowfish CBC/CFB/ECB        |              ❌ |                                     ❌ |
| CAST5                       |              ❌ |                                     ❌ |
| 3DES                        |              ❌ |                                     ❌ |
| OpenPGP packets             |              ❌ |                                     ❌ |
| OpenPGP S2K                 |              ❌ |                                     ❌ |
| RSA encryption              |              ❌ |                                     ❌ |
| ElGamal encryption          |              ❌ |                                     ❌ |
| PGP ASCII armor             |              ❌ |                                     ❌ |
| PGP packet/key parsing      |              ❌ |                                     ❌ |
| zlib/ZIP PGP compression    |              ❌ |                                     ❌ |
| OpenSSL FIPS status         |              ❌ |                                     ❌ |

PostgreSQL 18's exact standard digest set is `md5`, `sha1`, `sha224`, `sha256`, `sha384`, and `sha512`, plus other algorithms exposed by OpenSSL. ([PostgreSQL][1]) `dryoc` explicitly exposes SHA-256 and SHA-512, with SHA-3 as an additional extension, so it covers only part of this interface.

## The biggest problem: OpenPGP

This is where `dryoc` diverges completely from `pgcrypto`.

`pgcrypto` implements OpenPGP/RFC 4880-compatible encryption and supports these symmetric ciphers:

```text
bf
aes128
aes192
aes256
3des
cast5
```

It additionally implements OpenPGP S2K, packet serialization/parsing, MDC, compression, public-key encrypted session keys, ASCII armor, key IDs, and various compatibility options. ([PostgreSQL][2])

`dryoc`, on the other hand, is based on libsodium-compatible constructions such as:

```text
XSalsa20-Poly1305
XChaCha20-Poly1305
ChaCha20-Poly1305
Curve25519
Ed25519
Argon2
BLAKE2b
```

Those are excellent modern primitives, but none give you OpenPGP compatibility.

For example, this:

```sql
SELECT pgp_sym_encrypt(
    'hello',
    'password',
    'cipher-algo=aes256'
);
```

must generate a valid OpenPGP message that GnuPG can decrypt.

You cannot replace that internally with:

```text
Argon2
+
XChaCha20-Poly1305
```

and still call it `pgp_sym_encrypt()`.

It would be cryptographically reasonable, arguably better for a new protocol, but wire-incompatible.

## Raw `encrypt()` / `decrypt()` are also missing

PostgreSQL requires:

```text
AES:
    CBC
    CFB
    ECB

Blowfish:
    CBC
    CFB
    ECB

padding:
    PKCS
    none
```

For example:

```sql
encrypt(data, key, 'aes-cbc/pad:pkcs')
encrypt(data, key, 'aes-cfb/pad:none')
encrypt(data, key, 'bf-ecb')
```

PostgreSQL 18 documents those combinations explicitly. ([PostgreSQL][2])

`dryoc` doesn't expose AES or Blowfish. Its README explicitly notes even libsodium's AES256-GCM API is unimplemented, because the library concentrates on the Sodium-style algorithms.

So you need RustCrypto crates for this part.

## Password hashing is another mismatch

This is interesting because `dryoc` actually has **better modern password hashing**:

```text
Argon2
```

But `pgcrypto` compatibility requires:

```text
bf             bcrypt / Blowfish crypt
md5            md5crypt
des
xdes
sha256crypt
sha512crypt
```

PostgreSQL 18 added the last two. ([PostgreSQL][1])

Therefore `dryoc::pwhash` can't implement:

```sql
crypt()
gen_salt()
```

compatibly.

You can absolutely expose new functions such as:

```sql
argon2_hash()
argon2_verify()
```

but they would be your extension's additions.

---

# What I would use

I would **not try to force everything through dryoc**.

For a pure-Rust `pgrx` implementation, make the crypto backend modular:

```text
pg-crypto
│
├── hash/
│   ├── md5
│   ├── sha1
│   ├── sha2
│   ├── sha3
│   └── blake2
│
├── mac/
│   └── hmac
│
├── password/
│   ├── bcrypt
│   ├── md5crypt
│   ├── descrypt
│   ├── sha256crypt
│   ├── sha512crypt
│   └── argon2
│
├── cipher/
│   ├── aes
│   ├── blowfish
│   ├── cast5
│   └── des3
│
├── pgp/
│   └── OpenPGP implementation
│
├── modern/
│   └── dryoc
│
└── rng/
    └── dryoc
```

### Recommended Rust dependencies

Something approximately like:

```toml
[dependencies]
pgrx = "..."

# Modern crypto / secure randomness
dryoc = "..."

# Hashes
md-5 = "..."
sha1 = "..."
sha2 = "..."
hmac = "..."

# Symmetric crypto
aes = "..."
cbc = "..."
cfb-mode = "..."
ecb = "..."
cipher = "..."

# Legacy pgcrypto compatibility
blowfish = "..."
des = "..."
cast5 = "..."

# Password hashes
bcrypt = "..."

# Encoding
base64 = "..."

# Compression
flate2 = "..."

# OpenPGP
sequoia-openpgp = "..."
```

The exact legacy-crypt crate selection deserves checking because compatibility here means byte-for-byte behavior, not merely implementing a conceptually equivalent algorithm.

---

# Sequoia is probably the missing major component

For this part:

```text
pgp_sym_encrypt
pgp_sym_decrypt

pgp_pub_encrypt
pgp_pub_decrypt

pgp_key_id

armor
dearmor

pgp_armor_headers
```

I would strongly investigate **Sequoia OpenPGP** rather than implementing RFC 4880 packets manually.

Conceptually:

```text
dryoc
   ↓
modern primitives / RNG / additional API

RustCrypto
   ↓
hashes + AES + legacy ciphers

Sequoia
   ↓
OpenPGP compatibility

pgrx
   ↓
PostgreSQL SQL API
```

That is much safer than writing an OpenPGP parser and packet engine yourself.

There is one complication: `pgcrypto` supports very old OpenPGP algorithms including Blowfish, CAST5, and 3DES, and has some peculiar compatibility behaviors. PostgreSQL 18 even gained an `ignore-cipher-failure` option following CVE-2026-14663. ([PostgreSQL][2]) So you would need to test whether Sequoia permits all of the legacy combinations required for strict compatibility.

---

# What dryoc *would* be excellent for

I'd still use it extensively, but for your **new API**, not as the entire compatibility layer.

For example your extension could expose:

```sql
crypto_random_bytes(32)

crypto_blake2b(data)

crypto_sha3_256(data)

crypto_argon2_hash(password)
crypto_argon2_verify(password, hash)

crypto_xchacha20_encrypt(data, key)
crypto_xchacha20_decrypt(data, key)

crypto_secretbox(...)
crypto_box_seal(...)

crypto_ed25519_sign(...)
crypto_ed25519_verify(...)

crypto_x25519(...)
```

That would give `pg-crypto` something `pgcrypto` fundamentally doesn't have: a modern Sodium-style crypto API.

A particularly attractive PostgreSQL API would be:

```sql
SELECT crypto_aead_encrypt(
    plaintext,
    key,
    associated_data
);
```

using:

```text
XChaCha20-Poly1305
```

instead of exposing unauthenticated:

```text
AES-CBC
AES-CFB
AES-ECB
```

Dryoc already implements XChaCha20-Poly1305-IETF and ChaCha20-Poly1305-IETF AEAD.

---

# My proposed scope for `pg-crypto`

I'd split it into **two compatibility levels**.

```text
pgcrypto-compatible
────────────────────────────────

digest()
hmac()

crypt()
gen_salt()

encrypt()
decrypt()
encrypt_iv()
decrypt_iv()

pgp_sym_encrypt()
pgp_sym_decrypt()

pgp_pub_encrypt()
pgp_pub_decrypt()

armor()
dearmor()
pgp_key_id()
pgp_armor_headers()

gen_random_bytes()
gen_random_uuid()
```

Then separately:

```text
pg-crypto modern API
────────────────────────────────

argon2id_hash()
argon2id_verify()

blake2b()
sha3_256()
sha3_512()

xchacha20poly1305_encrypt()
xchacha20poly1305_decrypt()

secretbox()
box_seal()

ed25519_sign()
ed25519_verify()

x25519()

hkdf_sha256()
hkdf_sha512()

random_bytes()
```

And internally:

```text
                 ┌───────────────┐
                 │     pgrx      │
                 └───────┬───────┘
                         │
                 SQL compatibility
                         │
          ┌──────────────┼──────────────┐
          │              │              │
       dryoc         RustCrypto      Sequoia
          │              │              │
      modern       pgcrypto algs      OpenPGP
      crypto       AES/SHA/etc.       packets
```

That architecture is considerably better than attempting a `dryoc-only` port.

**Bottom line:** dryoc probably covers only around **25–35% of the primitives necessary for strict `pgcrypto` compatibility**, but it covers most of what I'd want for a *modern successor* to `pgcrypto`. The missing 65–75% isn't because dryoc is deficient; it is mainly legacy algorithms and the entire OpenPGP protocol stack, which dryoc deliberately doesn't target. PostgreSQL's current `pgcrypto` interface remains heavily tied to OpenSSL and RFC 4880-era algorithms. ([PostgreSQL][1])

For `RustedBytes/pg-crypto`, I'd therefore make **dryoc the modern/security-oriented backend, RustCrypto the compatibility primitive backend, and Sequoia the OpenPGP backend**. That gives you a realistic path to both `pgcrypto` compatibility and a much better new Rust-native API.

[1]: https://www.postgresql.org/docs/18/pgcrypto.html?utm_source=chatgpt.com "PostgreSQL: Documentation: 18: F.26. pgcrypto — cryptographic functions"
[2]: https://www.postgresql.org/docs/18/pgcrypto.html "PostgreSQL: Documentation: 18: F.26. pgcrypto — cryptographic functions"

