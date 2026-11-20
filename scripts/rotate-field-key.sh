#!/usr/bin/env bash
# Field-encryption key lifecycle (review comments). The keyring is secrets/field.key,
# one "<id>:<base64 key>" per line, FIRST line = active key.
#   scripts/rotate-field-key.sh status        which key ids exist, and how many rows use each
#   scripts/rotate-field-key.sh add           generate a new active key (the old ones stay, to decrypt)
#   scripts/rotate-field-key.sh reencrypt     rewrite every comment under the active key
#   scripts/rotate-field-key.sh retire <id>   remove an old key - refused while any row still uses it
# Normal rotation: add -> reencrypt -> status (zero rows on the old id) -> backup -> retire.
. "$(dirname "$0")/lib.sh"
load_secrets
DB="${DB:-grants}"; valid_db_name "$DB"
KEYRING=secrets/field.key
umask 077

# Everything the field keyring protects: review comments ('r') and the TOTP secrets ('t').
ROWS="SELECT 'r' AS kind, id, comments_enc AS v FROM grants.reviews WHERE comments_enc IS NOT NULL UNION ALL SELECT 't', id, totp_secret_enc FROM grants.users WHERE totp_secret_enc IS NOT NULL"
usage_by_key() {
  psql_admin "$DB" -At -F ' rows: ' -c "SELECT CASE WHEN v LIKE 'v1:%' THEN 'k1 (legacy v1 format)' ELSE split_part(v, ':', 2) END AS key_id, count(*)
                                          FROM ($ROWS) x GROUP BY 1 ORDER BY 1" | sed 's/^/  key /'
}
key_ids() { cut -d: -f1 "$KEYRING" | awk 'NF && $0 !~ /^#/ { if (index($0, "=") || length($0) > 16) print "k1"; else print $0 }'; }
write_in_place() { cat "$1" > "$KEYRING"; }          # same inode: the container's bind mount sees the new content

case "${1:-}" in
  status)
    echo "keyring $KEYRING (first = active):"; key_ids | awk '{ print "  " $0 (NR == 1 ? "   <- active" : "") }'
    echo "protected values in $DB (review comments and TOTP secrets) by key:"; usage_by_key ;;
  add)
    last=$(key_ids | sed -n 's/^k\([0-9]*\)$/\1/p' | sort -n | tail -1); new="k$(( ${last:-0} + 1 ))"
    cp "$KEYRING" "$KEYRING.$(date -u +%Y%m%dT%H%M%SZ).bak"
    tmp=$(mktemp); printf '%s:%s\n' "$new" "$(openssl rand -base64 32)" > "$tmp"
    # A legacy single-line file is converted to an explicit "k1:" line.
    awk 'NF && $0 !~ /^#/ { if (index($0, ":")) print; else print "k1:" $0 }' "$KEYRING" >> "$tmp"
    write_in_place "$tmp"; rm -f "$tmp"
    echo "new active key '$new' added; previous keys kept for decryption. Now run: $0 reencrypt" ;;
  reencrypt)
    n=$(psql_admin "$DB" -Atc "SELECT count(*) FROM ($ROWS) x")
    echo "re-encrypting $n value(s) (review comments and TOTP secrets) in $DB under the active key ..."
    psql_admin "$DB" -At -F $'\t' -c "SELECT kind, id, v FROM ($ROWS) x ORDER BY kind, id" \
      | ops_run ops php scripts/reencrypt-comments.php \
      | psql_admin "$DB" -q
    "$0" status ;;
  retire)
    id="${2:?usage: rotate-field-key.sh retire <key id>}"
    [ "$id" != "$(key_ids | head -1)" ] || { echo "refusing: '$id' is the active key" >&2; exit 2; }
    pattern="^$id\$"; [ "$id" = k1 ] && pattern='^(k1 \(legacy v1 format\)|k1)$'
    still=$(psql_admin "$DB" -At -F '|' -c "SELECT CASE WHEN v LIKE 'v1:%' THEN 'k1' ELSE split_part(v, ':', 2) END, count(*) FROM ($ROWS) x GROUP BY 1" \
            | awk -F'|' -v id="$id" '$1 == id { print $2 }')
    [ -z "${still:-}" ] || { echo "refusing: $still row(s) still use key '$id'; run reencrypt first" >&2; exit 2; }
    cp "$KEYRING" "$KEYRING.$(date -u +%Y%m%dT%H%M%SZ).bak"
    tmp=$(mktemp); awk -F: -v id="$id" '!(NF && $1 == id) { print }' "$KEYRING" > "$tmp"; write_in_place "$tmp"; rm -f "$tmp"
    echo "key '$id' retired (a backup of the previous keyring was kept next to it; keep it with the backups made under that key)" ;;
  *) sed -n '2,9p' "$0"; exit 2 ;;
esac
