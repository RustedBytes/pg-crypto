FROM rust:1.96-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release build-essential clang libclang-dev \
        pkg-config libssl-dev libreadline-dev zlib1g-dev flex bison \
        libxml2-dev libxslt1-dev libicu-dev postgresql-common \
    && rm -rf /var/lib/apt/lists/*

RUN install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
       | gpg --batch --yes --dearmor \
           -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-server-dev-18 \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-pgrx --version 0.19.2 --locked \
    && cargo pgrx init --pg18=/usr/lib/postgresql/18/bin/pg_config

WORKDIR /build
COPY . .
RUN ./install.sh \
    --pg-config /usr/lib/postgresql/18/bin/pg_config \
    --out-dir /package

FROM postgres:18-bookworm

LABEL org.opencontainers.image.title="pg_crypto" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.description="Pure-Rust pgcrypto compatibility and modern cryptography"

COPY --from=builder /package/usr/lib/postgresql/18/lib/pg_crypto.so \
    /usr/lib/postgresql/18/lib/pg_crypto.so
COPY --from=builder /package/usr/share/postgresql/18/extension/pg_crypto* \
    /usr/share/postgresql/18/extension/
COPY docker/10-pg-crypto.sql /docker-entrypoint-initdb.d/10-pg-crypto.sql
