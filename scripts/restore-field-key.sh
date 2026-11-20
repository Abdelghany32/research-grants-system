#!/usr/bin/env bash
# Decrypt a field-key backup (backups/<db>-<time>.fieldkey.gpg) next to the live keyring,
# never over it. Review it, then move it into place yourself.
#   scripts/restore-field-key.sh backups/grants-....fieldkey.gpg
. "$(dirname "$0")/lib.sh"
FILE="${1:?usage: restore-field-key.sh <backup.fieldkey.gpg>}"
umask 077
export GNUPGHOME="$PWD/secrets/gnupg"
sha256sum --check --quiet "$FILE.sha256"
mapfile -t UNLOCK < <(gpg_unlock_opts)
gpg --batch --quiet "${UNLOCK[@]}" --decrypt --output secrets/field.key.restored "$FILE"
echo "restored keyring written to secrets/field.key.restored ($(cut -d: -f1 secrets/field.key.restored | tr '\n' ' ')); key ids only, no key material shown"
echo "to use it: mv secrets/field.key.restored secrets/field.key"
