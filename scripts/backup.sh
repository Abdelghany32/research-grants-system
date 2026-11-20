#!/usr/bin/env bash
# Encrypted logical backup of one database, plus the field-encryption keyring.
#   pg_dump (custom format, as the read-only grants_backup account, local socket)
#     | gpg --encrypt (public key only)  ->  backups/<db>-<UTC time>.dump.gpg
#   secrets/field.key | gpg --encrypt     ->  backups/<db>-<UTC time>.fieldkey.gpg
# The plaintext dump never touches the disk. Encrypting needs only the PUBLIC key:
# the private key (secrets/gnupg) is needed only to restore, and should live with
# the restore team, not on the machine that takes backups (scripts/backup-key.sh).
# The dump holds ciphertext comments; without the keyring they are unreadable, so
# the keyring is backed up too - but as a SEPARATE file, to be stored apart from it.
. "$(dirname "$0")/lib.sh"
DB="${1:-grants}"; valid_db_name "$DB"
load_secrets
umask 077
export GNUPGHOME="$PWD/secrets/gnupg"
KEY="grants-backup@uni.example"

if ! gpg --batch --list-keys "$KEY" >/dev/null 2>&1; then
  mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  # Lab key without a passphrase. In production: generate it offline, keep the
  # private half with the two people allowed to restore, protect it with a passphrase.
  # A passphrase is used when scripts/backup-key.sh has created secrets/gpg-passphrase; otherwise the lab key has none.
  if [ -s secrets/gpg-passphrase ]; then
    gpg --batch --quiet --pinentry-mode loopback --passphrase-file secrets/gpg-passphrase --quick-generate-key "Grants Backup (lab) <$KEY>" default default never
  else
    gpg --batch --quiet --passphrase '' --quick-generate-key "Grants Backup (lab) <$KEY>" default default never
  fi
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FILE="backups/$DB-$STAMP.dump.gpg"
KEYFILE="backups/$DB-$STAMP.fieldkey.gpg"
dc exec -T -e PGPASSWORD="$BACKUP_DB_PASSWORD" db pg_dump -U grants_backup -d "$DB" -Fc --no-password --exclude-table-data='grants.identity_sessions' \
  | gpg --batch --quiet --no-auto-key-locate --trust-model always --encrypt --recipient "$KEY" --output "$FILE"
chmod 600 "$FILE"
sha256sum "$FILE" > "$FILE.sha256"
if [ -s secrets/field.key ]; then
  gpg --batch --quiet --no-auto-key-locate --trust-model always --encrypt --recipient "$KEY" --output "$KEYFILE" secrets/field.key
  chmod 600 "$KEYFILE"; sha256sum "$KEYFILE" > "$KEYFILE.sha256"
  echo "field-key backup (store apart from the dump): $KEYFILE" >&2
fi
echo "$FILE"
