#!/usr/bin/env bash
# Demonstrates separation of custody for the backup private key, on a COPY of the
# keyring in a temporary directory (the real secrets/gnupg is never modified).
# Evidence: docs/evidence/backup-key-custody.txt
. "$(dirname "$0")/lib.sh"
OUT=docs/evidence/backup-key-custody.txt
TMP=$(mktemp -d); WS=$(mktemp -d /tmp/ws.XXXXXX); trap 'rm -rf "$TMP" "$WS"' EXIT   # short paths: gpg-agent socket paths are length-limited
cp -a secrets/gnupg "$TMP/gnupg"; export GNUPGHOME="$TMP/gnupg"
mapfile -t UNLOCK < <(gpg_unlock_opts)
KEY="grants-backup@uni.example"
{
echo "BACKUP-KEY CUSTODY - $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC) - run on a temporary copy of the keyring"
echo; echo "== 1. Start: the backup host holds both halves"; scripts/backup-key.sh status
echo; echo "== 2. A decryption attempt without the passphrase fails (the key is protected)"
echo "secret" > "$TMP/plain"; gpg --batch --quiet --trust-model always --encrypt --recipient "$KEY" --output "$TMP/x.gpg" "$TMP/plain"
gpg --batch --pinentry-mode loopback --passphrase '' --decrypt "$TMP/x.gpg" 2>&1 | grep -E "No passphrase|failed" | sed 's/^/  /' || true
echo; echo "== 3. Export the protected private key to media held by the restore team, then remove it from this host"
scripts/backup-key.sh export "$TMP/custody-key.asc"; scripts/backup-key.sh remove "$TMP/custody-key.asc"; scripts/backup-key.sh status
echo; echo "== 4. The host can still TAKE backups (public key only) ..."
gpg --batch --quiet --trust-model always --encrypt --recipient "$KEY" --output "$TMP/y.gpg" "$TMP/plain" && echo "  encryption works without the private key"
echo "== ... but it can no longer READ them"
gpg --batch --quiet "${UNLOCK[@]}" --decrypt "$TMP/y.gpg" 2>&1 | grep -iE "no secret key|decryption failed" | sed 's/^/  /' || true
echo; echo "== 5. A restore happens on the restore workstation (clean keyring): the custodians bring the key file and the passphrase"
GNUPGHOME="$WS" scripts/backup-key.sh import "$TMP/custody-key.asc" 2>&1 | grep -E "secret keys imported" | sed 's/^/  /' || true
echo "  decrypted content on the workstation: $(GNUPGHOME="$WS" gpg --batch --quiet "${UNLOCK[@]}" --decrypt "$TMP/y.gpg" 2>&1 | tail -1)"
gpgconf --homedir "$WS" --kill gpg-agent 2>/dev/null || true
} 2>&1 | tee "$OUT"
gpgconf --homedir "$TMP/gnupg" --kill gpg-agent 2>/dev/null || true
