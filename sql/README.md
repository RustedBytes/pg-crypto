# Extension SQL

The `pg_crypto--0.1.0.sql` base schema is generated from the pgrx entity graph
during packaging. Future releases must add an explicit
`pg_crypto--old--new.sql` migration here for every supported upgrade path.
