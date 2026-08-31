#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/pg_config" >&2
  exit 2
fi

pg_config="$1"
pg_bindir="$("$pg_config" --bindir)"
test_root="$(mktemp -d /tmp/pg-crypto-gpg.XXXXXX)"
test_port=55419
export GNUPGHOME="$test_root/gnupg"
mkdir -m 700 "$GNUPGHOME"

cleanup() {
  "$pg_bindir/pg_ctl" -D "$test_root/data" -m immediate stop >/dev/null 2>&1 || true
  if [[ "${PG_CRYPTO_KEEP_TEST_ROOT:-0}" == 1 ]]; then
    echo "preserved interoperability fixtures at $test_root" >&2
  else
    rm -rf "$test_root"
  fi
}
trap cleanup EXIT

cargo pgrx install --pg-config "$pg_config"
"$pg_bindir/initdb" -D "$test_root/data" --no-locale --encoding=UTF8 >/dev/null
"$pg_bindir/pg_ctl" -D "$test_root/data" \
  -o "-F -p $test_port -k $test_root" -w start >/dev/null
"$pg_bindir/createdb" -h "$test_root" -p "$test_port" interop
"$pg_bindir/psql" -X -v ON_ERROR_STOP=1 -h "$test_root" -p "$test_port" \
  -d interop -c "CREATE EXTENSION pg_crypto"

"$pg_bindir/psql" -X -A -t -v ON_ERROR_STOP=1 -h "$test_root" -p "$test_port" \
  -d interop -c \
  "SELECT armor(pgp_sym_encrypt('from PostgreSQL', 'interop-password', 'cipher-algo=aes256'))" \
  >"$test_root/from-postgres.asc"

gpg --batch --yes --pinentry-mode loopback --passphrase interop-password \
  --decrypt --output "$test_root/from-postgres.txt" "$test_root/from-postgres.asc"
test "$(<"$test_root/from-postgres.txt")" = "from PostgreSQL"

printf '%s' 'from GnuPG' >"$test_root/from-gpg.txt"
gpg --batch --yes --pinentry-mode loopback --passphrase interop-password \
  --textmode --symmetric --cipher-algo AES256 --output "$test_root/from-gpg.pgp" \
  "$test_root/from-gpg.txt"

decrypted="$("$pg_bindir/psql" -X -A -t -v ON_ERROR_STOP=1 \
  -h "$test_root" -p "$test_port" -d interop -c \
  "SELECT pgp_sym_decrypt(pg_read_binary_file('$test_root/from-gpg.pgp'), 'interop-password')")"
test "$decrypted" = "from GnuPG"

gpg --batch --yes --rfc4880 --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'pg_crypto interop <interop@example.invalid>' \
  rsa2048 encr 0
gpg --batch --yes --pinentry-mode loopback --passphrase '' \
  --default-preference-list 'S9 S8 S7 S2 H10 H9 H8 H11 H2 Z2 Z3 Z1' \
  --quick-update-pref 'interop@example.invalid'
gpg --batch --yes --export 'interop@example.invalid' >"$test_root/public.pgp"
gpg --batch --yes --pinentry-mode loopback --passphrase '' \
  --export-secret-keys 'interop@example.invalid' >"$test_root/secret.pgp"

key_ids_match="$("$pg_bindir/psql" -X -A -t -v ON_ERROR_STOP=1 \
  -h "$test_root" -p "$test_port" -d interop -c \
  "SELECT length(pgp_key_id(pg_read_binary_file('$test_root/public.pgp'))) = 16
      AND pgp_key_id(pg_read_binary_file('$test_root/public.pgp')) =
          pgp_key_id(pg_read_binary_file('$test_root/secret.pgp'))")"
test "$key_ids_match" = "t"

if "$pg_bindir/psql" -X -A -t -v ON_ERROR_STOP=1 \
  -h "$test_root" -p "$test_port" -d interop -c \
  "SELECT pgp_pub_encrypt(
     'must fail', pg_read_binary_file('$test_root/secret.pgp')
   )" >/dev/null 2>&1; then
  echo "pgp_pub_encrypt accepted a secret key" >&2
  exit 1
fi

if "$pg_bindir/psql" -X -A -t -v ON_ERROR_STOP=1 \
  -h "$test_root" -p "$test_port" -d interop -c \
  "SELECT pgp_pub_decrypt(
     pgp_pub_encrypt_bytea(
       'binary marker'::bytea, pg_read_binary_file('$test_root/public.pgp')
     ),
     pg_read_binary_file('$test_root/secret.pgp')
   )" >/dev/null 2>&1; then
  echo "pgp_pub_decrypt accepted binary literal data as text" >&2
  exit 1
fi

"$pg_bindir/psql" -X -A -t -v ON_ERROR_STOP=1 -h "$test_root" -p "$test_port" \
  -d interop -c \
  "SELECT armor(pgp_pub_encrypt(
     'public from PostgreSQL', pg_read_binary_file('$test_root/public.pgp'),
     'cipher-algo=aes256'
   ))" >"$test_root/public-from-postgres.asc"
gpg --batch --yes --decrypt --output "$test_root/public-from-postgres.txt" \
  "$test_root/public-from-postgres.asc"
test "$(<"$test_root/public-from-postgres.txt")" = "public from PostgreSQL"

printf '%s' 'public from GnuPG' >"$test_root/public-from-gpg.txt"
gpg --batch --yes --rfc4880 --trust-model always \
  --textmode --recipient 'interop@example.invalid' \
  --encrypt --output "$test_root/public-from-gpg.pgp" "$test_root/public-from-gpg.txt"
public_decrypted="$("$pg_bindir/psql" -X -A -t -v ON_ERROR_STOP=1 \
  -h "$test_root" -p "$test_port" -d interop -c \
  "SELECT pgp_pub_decrypt(
     pg_read_binary_file('$test_root/public-from-gpg.pgp'),
     pg_read_binary_file('$test_root/secret.pgp')
   )")"
test "$public_decrypted" = "public from GnuPG"

echo "GnuPG symmetric and public-key OpenPGP interoperability passed"
