#!/usr/bin/env bash
# Verifies pgaudit and the log shipper in the RUNNING stack:
#   * pgaudit is loaded and records DDL, writes, and EVERYTHING the superuser does
#   * those records reach the shipped archive, whose hash chain verifies
#   * an edited, removed or reordered record is detected
#   * the archive is written by nothing but the shipper, which has no network and no secrets
# Evidence: docs/evidence/logship.txt   (exit 1 when any check fails)
. "$(dirname "$0")/lib.sh"
load_secrets
OUT=docs/evidence/logship.txt
R=0; F=0
ok()  { R=$((R+1)); printf 'PASS  %s\n' "$1"; }
bad() { F=$((F+1)); printf 'FAIL  %s\n' "$1"; }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
ship() { dc exec -T logship php /srv/ship/logship.php "$@"; }
{
echo "AUDIT AND LOG SHIPPING - $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
echo; echo "== pgaudit"
check "pgaudit is preloaded by the server" "[ \"\$(psql_admin postgres -Atc 'SHOW shared_preload_libraries')\" = pgaudit ]"
check "the server runs with pgaudit.log = ddl, role, write (command line, so it cannot drift)" "dc exec -T db sh -c \"tr '\\\\0' ' ' </proc/1/cmdline\" | grep -q 'pgaudit.log=ddl,role,write'"
check "the superuser logs everything (pgaudit.log = all)" "psql_admin postgres -Atc \"SELECT setconfig FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole WHERE r.rolname='postgres'\" | grep -q 'pgaudit.log=all'"
MARK="logship_probe_$(date +%s)"
psql_admin grants -q -c "CREATE TABLE $MARK(x int); INSERT INTO $MARK VALUES (1); SELECT * FROM $MARK; DROP TABLE $MARK" >/dev/null 2>&1
START=$(date -u -d '-1 minute' +%Y-%m-%dT%H:%M:%SZ)
for i in $(seq 1 15); do ship export "$START" db 2>/dev/null | grep -q "DROP TABLE $MARK" && break; sleep 1; done
EXP=$(ship export "$START" db 2>/dev/null)
check "the DDL is in the shipped archive (CREATE TABLE)" "grep -q 'AUDIT: SESSION.*DDL,CREATE TABLE.*$MARK' <<<\"\$EXP\""
check "the write is in the shipped archive (INSERT)" "grep -q 'AUDIT: SESSION.*WRITE,INSERT.*$MARK' <<<\"\$EXP\""
check "the superuser's READ is in the shipped archive (SELECT)" "grep -q 'AUDIT: SESSION.*READ,SELECT.*$MARK' <<<\"\$EXP\""
echo "  sample: $(grep "WRITE,INSERT.*$MARK" <<<"$EXP" | head -1 | cut -c1-200)"

echo; echo "== the archive"
VER=$(ship verify 2>&1); echo "  $VER"
check "the hash chain verifies" "grep -q '^OK' <<<\"\$VER\""
ANCHOR=$(ship head); echo "  anchor $ANCHOR   (kept outside the shipper: docs/evidence/logship-anchor.txt)"; echo "$ANCHOR" > docs/evidence/logship-anchor.txt
# Tampering is tried on COPIES of the archive in the shipper's scratch space; the real archive is never touched.
tamper() { dc exec -T logship sh -c "rm -rf /tmp/t; mkdir /tmp/t; cp /out/archive.ndjson /tmp/t/archive.ndjson; cd /tmp/t; $1; LOGSHIP_OUT=/tmp/t php /srv/ship/logship.php verify" 2>&1; }
r=$(tamper "sed -i '3s/\"line\":\"/\"line\":\"X/' archive.ndjson") || true; echo "  edit record 3:    $r"
grep -q 'BROKEN at record 3' <<<"$r" && ok "an edited record is detected" || bad "an edited record is detected"
r=$(tamper "sed -i 5d archive.ndjson") || true; echo "  remove record 5:  $r"
grep -q 'BROKEN at record 5' <<<"$r" && ok "a removed record is detected" || bad "a removed record is detected"
r=$(tamper "awk 'NR==7{a=\$0;next} NR==8{print;print a;next}{print}' archive.ndjson > s; mv s archive.ndjson") || true; echo "  swap 7 and 8:     $r"
grep -q 'BROKEN at record 7' <<<"$r" && ok "two swapped records are detected" || bad "two swapped records are detected"
r=$(tamper "head -n -3 archive.ndjson > s; mv s archive.ndjson") || true; echo "  cut off the end:  $r"
grep -q '^OK' <<<"$r" && ok "(the chain alone cannot see a cut-off tail ...)" || bad "tail truncation behaves unexpectedly"
r=$(dc exec -T logship sh -c "rm -rf /tmp/t; mkdir /tmp/t; head -n $(( ${ANCHOR%%:*} - 3 )) /out/archive.ndjson > /tmp/t/archive.ndjson; LOGSHIP_OUT=/tmp/t php /srv/ship/logship.php verify '$ANCHOR'" 2>&1) || true; echo "  ... with the anchor: $r"
grep -q 'BROKEN: the anchored record' <<<"$r" && ok "(... but the anchor, kept elsewhere, proves it was cut off)" || bad "anchor does not detect truncation"
dc exec -T logship rm -rf /tmp/t >/dev/null 2>&1 || true

echo; echo "== who can write the archive"
check "the shipper has no network (network mode none)" "[ \"\$(docker inspect -f '{{.HostConfig.NetworkMode}}' \$(dc ps -q logship))\" = none ]"
check "the shipper's root file system is read-only" "[ \"\$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' \$(dc ps -q logship))\" = true ]"
check "the shipper holds no secret (no password or key variable)" "! dc exec -T logship sh -c 'env | grep -Eq \"PASSWORD|SECRET|API_KEY|ACTOR_KEY|FIELD_KEY\"'"
check "the shipper cannot modify the database log it reads" "! dc exec -T logship sh -c 'echo x >> /in/db/\$(ls /in/db | head -1)'"
check "the shipper cannot modify the application log it reads" "! dc exec -T logship sh -c 'echo x >> /in/app/php-error.log'"
check "the database container cannot see the archive" "! dc exec -T db test -e /out/archive.ndjson"
check "the web container cannot see the archive" "! dc exec -T web test -e /out/archive.ndjson"
check "the database cannot rewrite its own shipped records (it has no write access to the archive volume)" "! dc exec -T db sh -c 'ls /out'"
echo; echo "SUMMARY: $R checks passed, $F failed"
[ "$F" -eq 0 ]
} 2>&1 | tee "$OUT"
exit "${PIPESTATUS[0]}"
