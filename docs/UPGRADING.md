# Upgrading

Version 0.1.0 is the first `pg_crypto` release and has no prior upgrade path.

Future releases must keep the Cargo package and control-file versions in sync
and ship `sql/pg_crypto--0.1.0--<new>.sql` or an equivalent complete migration
chain. `ci/test-upgrade.sh` enforces those release prerequisites.

Protocol envelope formats produced by the modern authenticated APIs are part of
the persistent data contract. Any future format change must be versioned and
retain decryption support for documented older envelopes during the support
window. PostgreSQL function signature changes require an explicit extension
upgrade migration.
