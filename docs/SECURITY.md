# Security model

The cryptographic implementation is pure Rust. RustCrypto provides hashes,
HMAC, and raw compatibility ciphers; Sequoia provides RFC 4880 OpenPGP; dryoc
provides the CSPRNG and modern Sodium-style constructions. `fips_mode()`
therefore returns false because no OpenSSL FIPS provider is involved.

Use XChaCha20-Poly1305, secretbox, or sealed box for new encrypted data. Their
outputs authenticate ciphertext, and XChaCha20-Poly1305 also authenticates the
supplied associated data. Authentication failures do not return plaintext.

Raw AES/Blowfish CBC, CFB, and ECB are retained only for compatibility. They do
not provide authentication, and ECB also reveals repeated plaintext blocks.

OpenPGP encryption always emits integrity-protected messages. The unsafe
`disable-mdc=1` option is rejected. `ignore-cipher-failure` does not recreate
the historical recovery behavior for malformed ciphertext produced by a failed
legacy OpenSSL cipher operation.

New password storage should use `argon2id_hash()` and `argon2id_verify()`.
`crypt()` and `gen_salt()` retain DES, extended DES, md5crypt, bcrypt,
SHA-256 crypt, and SHA-512 crypt for compatibility with existing hashes.

The extension performs no HTTP, RPC, filesystem, keyring, or wallet access.
Secret keys, passphrases, and plaintext necessarily enter PostgreSQL backend
memory. Database roles with superuser access, backend debugging access, unsafe
extensions, or access to process memory remain inside the trust boundary.

The extension is relocatable and creates its functions in the schema selected
by `CREATE EXTENSION`. Applications should schema-qualify security-sensitive
calls or use a controlled `search_path`.
