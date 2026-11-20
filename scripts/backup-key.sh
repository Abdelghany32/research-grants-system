#!/usr/bin/env bash
# Custody of the backup PRIVATE key (the key that can read every backup).
#   scripts/backup-key.sh status             is the private key on this host? is a passphrase file present?
#   scripts/backup-key.sh protect            put a random passphrase on the key (secrets/gpg-passphrase)
#   scripts/backup-key.sh export <file>      write the (passphrase-protected) private key to <file>
#   scripts/backup-key.sh remove <file>      delete the private key from this host - only if <file> verifies
#   scripts/backup-key.sh import <file>      on the restore workstation (GNUPGHOME=<clean dir>): load the key for a restore
# Principle: the machine that TAKES backups needs the public key only. The private
# key and its passphrase belong to the people allowed to restore, stored apart from
# each other (e.g. two custodians). On this lab host both start in secrets/.
. "$(dirname "$0")/lib.sh"
umask 077
export GNUPGHOME="${GNUPGHOME:-$PWD/secrets/gnupg}"
KEY="grants-backup@uni.example"
mapfile -t UNLOCK < <(gpg_unlock_opts)

have_secret() { gpg --batch --list-secret-keys "$KEY" >/dev/null 2>&1; }

case "${1:-}" in
  status)
    echo "public key  : $(gpg --batch --list-keys "$KEY" >/dev/null 2>&1 && echo present || echo MISSING)"
    echo "private key : $(have_secret && echo 'present on this host' || echo 'NOT on this host (restore needs: backup-key.sh import <file>)')"
    echo "passphrase  : $([ -s secrets/gpg-passphrase ] && echo 'file present (secrets/gpg-passphrase) - the key is protected' || echo 'none - the lab key is unprotected')" ;;
  protect)
    have_secret || { echo "no private key to protect" >&2; exit 2; }
    [ ! -s secrets/gpg-passphrase ] || { echo "already protected (secrets/gpg-passphrase exists)"; exit 0; }
    openssl rand -base64 24 > secrets/gpg-passphrase.new
    gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 --change-passphrase "$KEY" < secrets/gpg-passphrase.new
    mv secrets/gpg-passphrase.new secrets/gpg-passphrase
    echo "private key now needs a passphrase; it is in secrets/gpg-passphrase. Move that file away from this host once the key is exported." ;;
  export)
    out="${2:?usage: backup-key.sh export <file>}"
    have_secret || { echo "no private key here" >&2; exit 2; }
    gpg --batch --yes --armor "${UNLOCK[@]}" --export-secret-keys --output "$out" "$KEY"
    chmod 600 "$out"; echo "private key exported to $out (still passphrase-protected: $([ -s secrets/gpg-passphrase ] && echo yes || echo NO))" ;;
  remove)
    file="${2:?usage: backup-key.sh remove <exported-file>}"
    gpg --list-packets "$file" 2>/dev/null | grep -q 'secret key packet' || { echo "refusing: $file does not contain a secret key" >&2; exit 2; }
    fpr=$(gpg --batch --with-colons --list-secret-keys "$KEY" | awk -F: '$1 == "fpr" { print $10; exit }')
    gpg --batch --yes --delete-secret-keys "$fpr"
    echo "private key removed from this host (a verified copy exists in $file). Backups can still be made; restores need an import." ;;
  import)
    file="${2:?usage: backup-key.sh import <file>}"
    # Intended for the restore workstation (a clean keyring); re-importing into the home that just
    # deleted the key can leave gpg-agent with a stale entry.
    mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
    gpg --batch "${UNLOCK[@]}" --import "$file" ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac
