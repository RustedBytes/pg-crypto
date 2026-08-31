# Support matrix

`pg_crypto` 0.1 supports PostgreSQL 14–18, pgrx 0.19.2, and Rust 1.96 or newer.
The default Cargo feature targets PostgreSQL 18; builds must select exactly one
of `pg14`, `pg15`, `pg16`, `pg17`, or `pg18`.

The extension is pure Rust and does not require OpenSSL at runtime. OpenPGP
interoperability targets RFC 4880 messages and is continuously tested against
GnuPG. GnuPG's newer RFC 9580 AEAD packet format is outside the pgcrypto
compatibility target.

Linux is the primary tested platform. macOS uses dynamic PostgreSQL server
symbol resolution through the repository's Cargo configuration.
