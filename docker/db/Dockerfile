# PostgreSQL 18 with pgaudit (session audit of DDL, role changes and writes, and of everything the superuser does).
FROM postgres:18
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-18-pgaudit \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/log/grants-db && chown postgres:postgres /var/log/grants-db && chmod 0750 /var/log/grants-db
