#!/bin/sh
# Runs once, as the postgres OS user, when the data directory is first created.
# Generates the server TLS key inside PGDATA (0600, never leaves the volume)
# and installs the versioned pg_hba.conf and settings from the repository.
set -eu
openssl req -new -x509 -nodes -days 825 -newkey rsa:2048 \
  -subj "/CN=db" -addext "subjectAltName=DNS:db" \
  -keyout "$PGDATA/server.key" -out "$PGDATA/server.crt" 2>/dev/null
chmod 600 "$PGDATA/server.key"
cp "$PGDATA/pg_hba.conf" "$PGDATA/pg_hba.conf.image-default"
cp /etc/grants-db/pg_hba.conf "$PGDATA/pg_hba.conf"
cat /etc/grants-db/hardening.conf >> "$PGDATA/postgresql.conf"
