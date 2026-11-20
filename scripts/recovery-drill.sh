#!/usr/bin/env bash
# Backup -> restore -> simulated loss on the disposable copy -> timed recovery
# -> verification. The live "grants" database is only read (by pg_dump).
# Evidence: docs/evidence/recovery-drill.txt
. "$(dirname "$0")/lib.sh"
load_secrets
OUT=docs/evidence/recovery-drill.txt
TARGET=grants_drill
export GNUPGHOME="$PWD/secrets/gnupg"
mapfile -t UNLOCK < <(gpg_unlock_opts)

# One md5 per table over every row in primary-key order, plus the row count.
fingerprint() {
  for t in users grant_calls proposals reviews decisions audit_events; do
    psql_admin "$1" -Atc "SELECT '$t', count(*), md5(coalesce(string_agg(x::text, '|' ORDER BY id), '')) FROM grants.$t x"
  done
}
privileges() {
  psql_admin "$1" -Atc "SELECT grantee, table_name, string_agg(privilege_type, ',' ORDER BY privilege_type) FROM information_schema.role_table_grants
     WHERE table_schema = 'grants' AND grantee LIKE 'grants_%' AND grantee <> 'grants_owner' GROUP BY 1, 2 ORDER BY 1, 2"
  psql_admin "$1" -Atc "SELECT grantee, table_name, privilege_type, string_agg(column_name, ',' ORDER BY column_name) FROM information_schema.column_privileges
     WHERE table_schema = 'grants' AND grantee = 'grants_runtime' AND table_name IN ('users','grant_calls','proposals','reviews') AND privilege_type = 'UPDATE' GROUP BY 1, 2, 3 ORDER BY 1, 2"
  psql_admin "$1" -Atc "SELECT tablename, policyname, cmd, roles FROM pg_policies WHERE schemaname = 'grants' ORDER BY 1, 2"
}

{
echo "RECOVERY DRILL - $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
echo; echo "== 1. Encrypted backup of the live database"
FILE=$(scripts/backup.sh grants)
ls -l "$FILE"; cat "$FILE.sha256"
echo "file type        : $(file -b "$FILE")"
echo "readable without the key? pg_restore says: $(dc exec -T db pg_restore --list < "$FILE" 2>&1 | head -1)"
echo "plaintext markers in the archive (PGDMP header, a user e-mail, a proposal title): $( { grep -ac 'PGDMP' "$FILE"; grep -ac 'amina.elidrissi' "$FILE"; grep -ac 'Federated' "$FILE"; } | tr '\n' ' ')"
echo "key holders      : $(stat -c '%A %U' secrets/gnupg) secrets/gnupg (private key, this account only)"
gpg --batch "${UNLOCK[@]}" --list-packets "$FILE" 2>/dev/null | grep -m1 'pubkey enc packet' | sed 's/^/encryption       /'
KEYBK="${FILE%.dump.gpg}.fieldkey.gpg"
KEYSTATUS=$(scripts/backup-key.sh status)
echo "private key      : $(grep '^private key' <<<"$KEYSTATUS" | cut -d: -f2- | sed 's/^ //'); $(grep '^passphrase' <<<"$KEYSTATUS" | cut -d: -f2- | sed 's/^ //')"
echo "field-key backup : $KEYBK ($(stat -c %s "$KEYBK") bytes, separate file), checksum: $(sha256sum --check --quiet "$KEYBK.sha256" && echo OK)"
echo "keyring ids in the key backup (ids only, no key material): $(gpg --batch --quiet "${UNLOCK[@]}" --decrypt "$KEYBK" | cut -d: -f1 | tr '\n' ' ')"
gpg --batch --quiet "${UNLOCK[@]}" --decrypt "$KEYBK" | cmp - secrets/field.key && echo "decrypted key backup is IDENTICAL to the live keyring"

echo; echo "== 2. First restore into the disposable database $TARGET"
scripts/restore.sh "$FILE" "$TARGET" 2>&1 | grep -v NOTICE

echo; echo "== 3. Simulated loss, on the disposable copy only"
psql_admin "$TARGET" -c "DROP SCHEMA grants CASCADE" 2>&1 | grep -cE "cascades to (function|table|view) " | sed "s/^/objects destroyed by DROP SCHEMA grants CASCADE: 1 schema + /"
echo "tables left in $TARGET.grants: $(psql_admin "$TARGET" -Atc "SELECT count(*) FROM pg_tables WHERE schemaname = 'grants'")"
echo "live database untouched, tables in grants.grants: $(psql_admin grants -Atc "SELECT count(*) FROM pg_tables WHERE schemaname = 'grants'")"

echo; echo "== 4. Timed recovery of $TARGET from the encrypted archive"
scripts/restore.sh "$FILE" "$TARGET" 2>&1 | grep -v NOTICE

echo; echo "== 5. Record values: table, rows, md5 over all rows (source vs restored)"
fingerprint grants > /tmp/grants-src.$$; fingerprint "$TARGET" > /tmp/grants-dst.$$
paste -d' ' /tmp/grants-src.$$ /tmp/grants-dst.$$ | awk -F'[| ]' '{printf "%-13s source %4s %s   restored %4s %s   %s\n", $1, $2, $3, $5, $6, ($2==$5 && $3==$6) ? "MATCH" : "DIFFERENT"}'
echo "funds remaining (call, source, restored):"
paste -d' ' <(psql_admin grants -Atc "SELECT id, remaining_budget FROM grants.grant_calls ORDER BY id") <(psql_admin "$TARGET" -Atc "SELECT remaining_budget FROM grants.grant_calls ORDER BY id") | sed 's/^/  /'

echo; echo "== 6. Privileges and policies (source vs restored)"
privileges grants > /tmp/grants-src.$$; privileges "$TARGET" > /tmp/grants-dst.$$
echo "privilege and policy lines: source $(wc -l < /tmp/grants-src.$$), restored $(wc -l < /tmp/grants-dst.$$)"
diff /tmp/grants-src.$$ /tmp/grants-dst.$$ && echo "IDENTICAL: table privileges, column privileges and RLS policies"
rm -f /tmp/grants-src.$$ /tmp/grants-dst.$$

echo; echo "== 7. Behaviour of the restored database under the restricted accounts"
ops_run -e DB_NAME="$TARGET" ops php scripts/verify_restore.php
echo "verification exit code: $?"
} 2>&1 | tee "$OUT"
grep -q "verification exit code: 0" "$OUT" && ! grep -q DIFFERENT "$OUT"
