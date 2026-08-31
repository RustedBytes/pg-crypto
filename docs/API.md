# SQL API

## pgcrypto compatibility

```text
digest(text, text) -> bytea
digest(bytea, text) -> bytea
hmac(text, text, text) -> bytea
hmac(bytea, bytea, text) -> bytea
crypt(text, text) -> text
gen_salt(text [, integer]) -> text

encrypt(bytea, bytea, text) -> bytea
decrypt(bytea, bytea, text) -> bytea
encrypt_iv(bytea, bytea, bytea, text) -> bytea
decrypt_iv(bytea, bytea, bytea, text) -> bytea

pgp_sym_encrypt(text, text [, text]) -> bytea
pgp_sym_encrypt_bytea(bytea, text [, text]) -> bytea
pgp_sym_decrypt(bytea, text [, text]) -> text
pgp_sym_decrypt_bytea(bytea, text [, text]) -> bytea

pgp_pub_encrypt(text, bytea [, text]) -> bytea
pgp_pub_encrypt_bytea(bytea, bytea [, text]) -> bytea
pgp_pub_decrypt(bytea, bytea [, text [, text]]) -> text
pgp_pub_decrypt_bytea(bytea, bytea [, text [, text]]) -> bytea

armor(bytea) -> text
armor(bytea, text[], text[]) -> text
dearmor(text) -> bytea
pgp_key_id(bytea) -> text
pgp_armor_headers(text) -> table(key text, value text)

gen_random_bytes(integer) -> bytea
gen_random_uuid() -> uuid
fips_mode() -> boolean
```

Digest and HMAC names include MD5, SHA-1, SHA-224, SHA-256, SHA-384, and
SHA-512. Digest also accepts SHA3-256, SHA3-512, and BLAKE2b.

`gen_salt` supports `bf`, `des`, `xdes`, `md5`, `sha256crypt`, and
`sha512crypt`. `crypt` selects the password format from its salt.

Raw ciphers include AES and Blowfish in CBC, CFB, and ECB modes. The type name
accepts `/pad:pkcs` (the default) or `/pad:none`; CFB remains unpadded in either
case. AES keys up to 16, 24, or 32 bytes select AES-128, AES-192, or AES-256,
respectively, with zero padding inside the selected tier. Blowfish keys are
truncated at 56 bytes. Historical `rijndael*` and `blowfish*` aliases are
accepted.

OpenPGP supports RFC 4880 symmetric and public-key messages, S2K modes 0/1/3,
MD5/SHA-1 S2K digests, optional encrypted session keys, ZIP/zlib compression,
text/binary literal markers, CRLF conversion, AES-128/192/256, Blowfish,
CAST5, and Triple DES. Public encryption requires a public certificate; public
decryption accepts protected or unprotected transferable secret keys.

For safety, `disable-mdc=1` is rejected. `ignore-cipher-failure` is accepted
for valid messages but cannot recover malformed historical ciphertext whose
cipher operation failed and left its packet body unencrypted.

## Modern authenticated API

```text
argon2id_hash(text) -> text
argon2id_verify(text, text) -> boolean

blake2b(bytea) -> bytea
sha3_256(bytea) -> bytea
sha3_512(bytea) -> bytea

xchacha20poly1305_encrypt(bytea, bytea [, bytea]) -> bytea
xchacha20poly1305_decrypt(bytea, bytea [, bytea]) -> bytea
secretbox(bytea, bytea) -> bytea
secretbox_open(bytea, bytea) -> bytea
box_seal(bytea, bytea) -> bytea
box_seal_open(bytea, bytea, bytea) -> bytea

ed25519_sign(bytea, bytea) -> bytea
ed25519_verify(bytea, bytea, bytea) -> boolean
x25519(bytea, bytea) -> bytea

hkdf_sha256(bytea, bytea, bytea, integer) -> bytea
hkdf_sha512(bytea, bytea, bytea, integer) -> bytea
random_bytes(integer) -> bytea
```

XChaCha20-Poly1305 envelopes contain nonce, ciphertext, and authentication tag.
`secretbox` envelopes contain nonce, MAC, and ciphertext. Sealed-box envelopes
contain the ephemeral public key, MAC, and ciphertext. Decryptors validate the
envelope and fail without returning plaintext when authentication fails.

Ed25519 uses 64-byte secret keys, 32-byte public keys, and 64-byte signatures.
X25519 and sealed boxes use 32-byte Curve25519 keys. AEAD and secretbox require
32-byte symmetric keys.
