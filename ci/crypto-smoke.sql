CREATE SCHEMA crypto_ext;
CREATE EXTENSION pg_crypto WITH SCHEMA crypto_ext;
SET search_path = crypto_ext, pg_catalog;

DO $$
DECLARE
  bcrypt_salt text;
  argon_hash text;
  armored text;
  encrypted bytea;
  extension_function_names text[];
  rejected boolean;
  key32 bytea := decode(repeat('11', 32), 'hex');
BEGIN
  SELECT array_agg(DISTINCT p.proname ORDER BY p.proname)
    INTO extension_function_names
  FROM pg_proc p
  JOIN pg_depend d
    ON d.classid = 'pg_proc'::regclass
   AND d.objid = p.oid
   AND d.deptype = 'e'
  JOIN pg_extension e ON e.oid = d.refobjid
  WHERE e.extname = 'pg_crypto';

  ASSERT extension_function_names = ARRAY[
    'argon2id_hash', 'argon2id_verify', 'armor', 'blake2b', 'box_seal',
    'box_seal_open', 'crypt', 'dearmor', 'decrypt', 'decrypt_iv', 'digest',
    'ed25519_sign', 'ed25519_verify', 'encrypt', 'encrypt_iv', 'fips_mode',
    'gen_random_bytes', 'gen_random_uuid', 'gen_salt', 'hkdf_sha256',
    'hkdf_sha512', 'hmac', 'pgp_armor_headers', 'pgp_key_id',
    'pgp_pub_decrypt', 'pgp_pub_decrypt_bytea', 'pgp_pub_encrypt',
    'pgp_pub_encrypt_bytea', 'pgp_sym_decrypt', 'pgp_sym_decrypt_bytea',
    'pgp_sym_encrypt', 'pgp_sym_encrypt_bytea', 'random_bytes', 'secretbox',
    'secretbox_open', 'sha3_256', 'sha3_512', 'x25519',
    'xchacha20poly1305_decrypt', 'xchacha20poly1305_encrypt'
  ];
  ASSERT (
    SELECT count(*) = 43 AND bool_and(p.prokind = 'f')
    FROM pg_proc p
    JOIN pg_depend d
      ON d.classid = 'pg_proc'::regclass
     AND d.objid = p.oid
     AND d.deptype = 'e'
    JOIN pg_extension e ON e.oid = d.refobjid
    WHERE e.extname = 'pg_crypto'
  );
  ASSERT NOT EXISTS (
    SELECT 1
    FROM pg_depend d
    JOIN pg_extension e ON e.oid = d.refobjid
    WHERE e.extname = 'pg_crypto'
      AND d.deptype = 'e'
      AND d.classid <> 'pg_proc'::regclass
  );

  ASSERT encode(digest('abc', 'sha256'), 'hex') =
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  ASSERT encode(hmac(
      'The quick brown fox jumps over the lazy dog', 'key', 'sha256'
    ), 'hex') =
    'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8';
  ASSERT encode(digest('abc', 'sha3-256'), 'hex') =
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532';
  ASSERT encode(sha3_256('abc'::bytea), 'hex') =
    '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532';
  ASSERT octet_length(sha3_512('abc'::bytea)) = 64;
  ASSERT encode(blake2b('abc'::bytea), 'hex') =
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d' ||
    '17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923';

  ASSERT octet_length(gen_random_bytes(32)) = 32;
  ASSERT octet_length(random_bytes(32)) = 32;
  ASSERT gen_random_uuid() IS NOT NULL;
  ASSERT NOT fips_mode();

  bcrypt_salt := gen_salt('bf', 5);
  ASSERT crypt('secret', bcrypt_salt) = crypt(
    'secret', crypt('secret', bcrypt_salt)
  );
  ASSERT crypt('secret', gen_salt('md5')) LIKE '$1$%';
  ASSERT length(gen_salt('des')) = 2;
  ASSERT length(gen_salt('xdes', 725)) = 9;
  ASSERT crypt('secret', gen_salt('sha256crypt', 1000)) LIKE '$5$%';
  ASSERT crypt('secret', gen_salt('sha512crypt', 1000)) LIKE '$6$%';
  rejected := false;
  BEGIN
    PERFORM gen_salt('xdes', 724);
  EXCEPTION WHEN OTHERS THEN
    rejected := true;
  END;
  ASSERT rejected;

  ASSERT (
    SELECT bool_and(
      decrypt_iv(
        encrypt_iv('raw cipher data'::bytea, 'key'::bytea, 'iv'::bytea, kind),
        'key'::bytea, 'iv'::bytea, kind
      ) = 'raw cipher data'::bytea
    )
    FROM (VALUES
      ('aes-cbc'), ('aes-cfb'), ('aes-ecb'),
      ('bf-cbc'), ('bf-cfb'), ('bf-ecb')
    ) modes(kind)
  );
  ASSERT encode(encrypt(
    decode('00112233445566778899aabbccddeeff', 'hex'),
    decode('000102030405060708090a0b0c0d0e0f', 'hex'),
    'aes-ecb/pad:none'
  ), 'hex') = '69c4e0d86a7b0430d8cdb78070b4c55a';
  ASSERT encode(encrypt(
    decode('00112233445566778899aabbccddeeff', 'hex'),
    decode('000102030405060708090a0b0c0d0e0f1011121314151617', 'hex'),
    'aes-ecb/pad:none'
  ), 'hex') = 'dda97ca4864cdfe06eaf70a0ec0d7191';
  ASSERT encode(encrypt(
    decode('00112233445566778899aabbccddeeff', 'hex'),
    decode(
      '000102030405060708090a0b0c0d0e0f' ||
      '101112131415161718191a1b1c1d1e1f', 'hex'
    ),
    'aes-ecb/pad:none'
  ), 'hex') = '8ea2b7ca516745bfeafc49904b496089';
  ASSERT encode(encrypt(
    decode('0000000000000000', 'hex'),
    decode('0000000000000000', 'hex'),
    'bf-ecb/pad:none'
  ), 'hex') = '4ef997456198dd78';
  ASSERT encode(encrypt(
    decode('0011223344', 'hex'),
    decode('000102030405', 'hex'),
    'aes-cfb'
  ), 'hex') = '8145d1a0ef';
  ASSERT octet_length(encrypt(''::bytea, 'foo'::bytea, 'aes-cfb')) = 0;
  ASSERT octet_length(encrypt('foo'::bytea, 'key'::bytea, 'bf-cfb')) = 3;
  ASSERT encode(encrypt(''::bytea, 'foo'::bytea, 'bf'), 'hex') =
    '1871949bb2311c8e';
  ASSERT encrypt('alias test'::bytea, 'key'::bytea, 'rijndael') =
    encrypt('alias test'::bytea, 'key'::bytea, 'aes');
  ASSERT encrypt('alias test'::bytea, 'key'::bytea, 'blowfish') =
    encrypt('alias test'::bytea, 'key'::bytea, 'bf');
  ASSERT (
    SELECT bool_and(
      pgp_sym_decrypt(
        pgp_sym_encrypt('S2K compatibility', 'password', options),
        'password'
      ) = 'S2K compatibility'
    )
    FROM (VALUES
      ('s2k-mode=0,s2k-digest-algo=md5'),
      ('s2k-mode=1,s2k-digest-algo=sha1'),
      ('s2k-mode=3,s2k-count=65536,s2k-digest-algo=sha1'),
      ('sess-key=1,cipher-algo=aes128,s2k-cipher-algo=aes256')
    ) configurations(options)
  );
  ASSERT pgp_sym_decrypt(
    pgp_sym_encrypt(E'line one\nline two', 'password', 'convert-crlf=1'),
    'password', 'convert-crlf=1'
  ) = E'line one\nline two';
  ASSERT pgp_sym_decrypt(
    pgp_sym_encrypt('unicode text', 'password', 'unicode-mode=1'),
    'password'
  ) = 'unicode text';
  ASSERT pgp_sym_decrypt(
    pgp_sym_encrypt('valid cipher', 'password'),
    'password', 'ignore-cipher-failure=1'
  ) = 'valid cipher';
  rejected := false;
  BEGIN
    PERFORM pgp_sym_decrypt(
      pgp_sym_encrypt_bytea('binary marker'::bytea, 'password'),
      'password'
    );
  EXCEPTION WHEN OTHERS THEN
    rejected := true;
  END;
  ASSERT rejected;
  ASSERT (
    SELECT bool_and(
      decrypt_iv(
        encrypt_iv(decode(repeat('22', 16), 'hex'), 'key'::bytea, 'iv'::bytea, kind),
        'key'::bytea, 'iv'::bytea, kind
      ) = decode(repeat('22', 16), 'hex')
    )
    FROM (VALUES
      ('aes-cbc/pad:none'), ('aes-cfb/pad:none'), ('aes-ecb/pad:none'),
      ('bf-cbc/pad:none'), ('bf-cfb/pad:none'), ('bf-ecb/pad:none')
    ) modes(kind)
  );
  rejected := false;
  BEGIN
    PERFORM armor('x'::bytea, ARRAY['Nön-ASCII'], ARRAY['value']);
  EXCEPTION WHEN OTHERS THEN
    rejected := true;
  END;
  ASSERT rejected;

  ASSERT pgp_sym_decrypt(
    pgp_sym_encrypt(
      'hello pgp', 'password', 'cipher-algo=aes256,compress-algo=2'
    ),
    'password'
  ) = 'hello pgp';
  ASSERT (
    SELECT bool_and(
      pgp_sym_decrypt(
        pgp_sym_encrypt('legacy cipher', 'password', 'cipher-algo=' || cipher),
        'password'
      ) = 'legacy cipher'
    )
    FROM (VALUES ('bf'), ('aes128'), ('aes192'), ('aes256'), ('3des'), ('cast5'))
      ciphers(cipher)
  );
  ASSERT pgp_key_id(pgp_sym_encrypt('hello', 'password')) = 'SYMKEY';
  ASSERT dearmor(armor(decode('000102ff', 'hex'))) = decode('000102ff', 'hex');
  armored := armor(
    decode('000102ff', 'hex'),
    ARRAY['Comment', 'Version'], ARRAY['pg_crypto smoke', '1']
  );
  ASSERT dearmor(armored) = decode('000102ff', 'hex');
  ASSERT (
    SELECT count(*) = 2
      AND bool_and(key IN ('Comment', 'Version'))
    FROM pgp_armor_headers(armored)
  );

  ASSERT xchacha20poly1305_decrypt(
    xchacha20poly1305_encrypt('hello'::bytea, key32, 'context'::bytea),
    key32, 'context'::bytea
  ) = 'hello'::bytea;
  rejected := false;
  BEGIN
    PERFORM xchacha20poly1305_decrypt(
      xchacha20poly1305_encrypt('hello'::bytea, key32, 'context'::bytea),
      key32, 'wrong context'::bytea
    );
  EXCEPTION WHEN OTHERS THEN
    rejected := true;
  END;
  ASSERT rejected;

  encrypted := secretbox('hello'::bytea, key32);
  ASSERT secretbox_open(encrypted, key32) = 'hello'::bytea;
  encrypted := set_byte(encrypted, 0, get_byte(encrypted, 0) # 1);
  rejected := false;
  BEGIN
    PERFORM secretbox_open(encrypted, key32);
  EXCEPTION WHEN OTHERS THEN
    rejected := true;
  END;
  ASSERT rejected;
  ASSERT box_seal_open(
    box_seal(
      'sealed hello'::bytea,
      decode('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex')
    ),
    decode('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex'),
    decode('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex')
  ) = 'sealed hello'::bytea;

  argon_hash := argon2id_hash('a long unique password');
  ASSERT argon2id_verify('a long unique password', argon_hash);
  ASSERT NOT argon2id_verify('wrong', argon_hash);

  ASSERT encode(ed25519_sign(
    ''::bytea,
    decode(
      '9d61b19deffd5a60ba844af492ec2cc4' ||
      '4449c5697b326919703bac031cae7f60' ||
      'd75a980182b10ab7d54bfed3c964073a' ||
      '0ee172f3daa62325af021a68f707511a', 'hex'
    )
  ), 'hex') =
    'e5564300c360ac729086e2cc806e828a' ||
    '84877f1eb8e5d974d873e06522490155' ||
    '5fb8821590a33bacc61e39701cf9b46b' ||
    'd25bf5f0595bbe24655141438e7a100b';
  ASSERT ed25519_verify(
    ''::bytea,
    decode(
      'e5564300c360ac729086e2cc806e828a' ||
      '84877f1eb8e5d974d873e06522490155' ||
      '5fb8821590a33bacc61e39701cf9b46b' ||
      'd25bf5f0595bbe24655141438e7a100b', 'hex'
    ),
    decode(
      'd75a980182b10ab7d54bfed3c964073a' ||
      '0ee172f3daa62325af021a68f707511a', 'hex'
    )
  );
  ASSERT NOT ed25519_verify(
    'changed'::bytea,
    decode(
      'e5564300c360ac729086e2cc806e828a' ||
      '84877f1eb8e5d974d873e06522490155' ||
      '5fb8821590a33bacc61e39701cf9b46b' ||
      'd25bf5f0595bbe24655141438e7a100b', 'hex'
    ),
    decode(
      'd75a980182b10ab7d54bfed3c964073a' ||
      '0ee172f3daa62325af021a68f707511a', 'hex'
    )
  );

  ASSERT encode(x25519(
    decode(
      '77076d0a7318a57d3c16c17251b26645' ||
      'df4c2f87ebc0992ab177fba51db92c2a', 'hex'
    ),
    decode(
      'de9edb7d7b7dc1b4d35b61c2ece43537' ||
      '3f8343c85b78674dadfc7e146f882b4f', 'hex'
    )
  ), 'hex') =
    '4a5d9d5ba4ce2de1728e3bf480350f25' ||
    'e07e21c947d19e3376f09b3c1e161742';

  ASSERT encode(hkdf_sha256(
    decode(repeat('0b', 22), 'hex'),
    decode('000102030405060708090a0b0c', 'hex'),
    decode('f0f1f2f3f4f5f6f7f8f9', 'hex'), 42
  ), 'hex') =
    '3cb25f25faacd57a90434f64d0362f2a' ||
    '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' ||
    '34007208d5b887185865';
  ASSERT octet_length(hkdf_sha512('key'::bytea, 'salt'::bytea, 'info'::bytea, 64)) = 64;
END
$$;
