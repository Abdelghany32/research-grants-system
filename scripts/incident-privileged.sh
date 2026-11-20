#!/usr/bin/env bash
# SIMULATED INCIDENT 2 - stolen runtime database credential (disposable grants_test only).
# Part 1 plays the attacker. Part 2 is the investigation, using ONLY what a defender has:
# the application audit trail (read through the auditor account) and the PostgreSQL server log as SHIPPED to the log archive.
# Evidence: docs/evidence/incident-privileged.txt
. "$(dirname "$0")/lib.sh"
load_secrets
db_exists grants_test || { echo "grants_test missing: run scripts/test.sh first" >&2; exit 2; }
OUT=docs/evidence/incident-privileged.txt
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sleep 1
audit() { ops_run -e DB_NAME=grants_test ops php scripts/audit_report.php "$START" "$@"; }
{
echo "SIMULATED INCIDENT 2: STOLEN SERVICE CREDENTIAL - started $START (UTC) - database grants_test (disposable)"
echo
echo "################ PART 1 - the attacker's session (what actually happened) ################"
ops_run -e DB_NAME=grants_test -e PENTEST_LAB=1 ops php scripts/incident_privileged.php
sleep 1

echo
echo "################ PART 2 - the investigation (evidence only) ################"
echo
echo "---- 2a. Application audit trail since the alert (auditor account, audit_timeline view) ----"
audit
echo
echo "---- 2b. Anomaly query: events the web application cannot have written ----"
echo "     (every event written by the application carries a request correlation id AND a source address; this run should return none)"
audit anomalies
echo
echo "---- 2c. PostgreSQL server log - read from the SHIPPED archive (off the database host, hash-chained): who connected, from where, what the server refused ----"
LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT
for i in $(seq 1 15); do dc exec -T logship php /srv/ship/logship.php export "$START" db > "$LOG" 2>&1; grep -q "application_name=stolen-credential" "$LOG" && break; sleep 1; done
PID=$(grep -m1 'application_name=stolen-credential' "$LOG" | sed -E 's/.*\[([0-9]+)\].*/\1/')
echo "connection of interest: pid $PID (application_name=stolen-credential is not a name the web application uses)"
grep -E "\[$PID\]" "$LOG" | grep -vE "^\s*$" | sed -E 's/^[0-9-]+ ([0-9:.]+) UTC/\1/' | cut -c1-200
echo
echo "---- 2d. Reading of the evidence ----"
cat <<'TXT'
 WHAT HAPPENED   A session using the grants_app account, from the web container's network and with an application name the
                 web application never uses, ran outside any HTTP request. It listed the accounts (the only thing it could
                 read), claimed an officer identity in two ways, tried to move money, to award through the function, to
                 erase its tracks and to forge audit records. NOTHING succeeded except the account listing.
 WHEN / WHO      Times in 2c (UTC). Account: grants_app (the web service credential). Claimed identity: the officer account.
 RESOURCES       users (e-mail, name, role: read). Nothing was changed; the audit trail (2a, 2b) contains no event from this session.
 CONTROLS THAT HELD
   * Identity is PROVED, not asserted (findings O02): neither the old app.user_id claim nor a self-signed actor token yields an
     identity, so row-level security answers "no rows" and record_decision() refuses (42501). The key is not in the database
     password's reach (secrets/actor.key is readable by the web process only; its copy in the database is owner-only).
   * No audit forgery (finding O03): the web account has no INSERT on audit_events, audit_append() needs a valid actor token
     for any named actor, and the audit-writer account (a different credential) cannot be used from this session.
   * No partial award (F01), no hash or audit read, audit immutable (UPDATE/DELETE/TRUNCATE refused).
   * Every refusal appears in the PostgreSQL log with user, database, time and the exact statement - this is how the
     incident is investigated, because nothing reached the audit trail.
 CONTROLS THAT FAILED / WEAK
   * The attacker could still read the accounts table (e-mail, name, role) with the stolen credential: the web account needs
     that read, and the credential helper still returns one password hash per e-mail address (observation O01).
   * The attacker was only caught by the server log: nothing in the application audit trail shows an attempt. Alert on
     'permission denied' lines for grants_app that do not match any HTTP request.
   * Residual: an attacker who ALSO takes secrets/actor.key (that is, compromises the web process itself) can act as any user
     again. Compare docs/evidence/incident-privileged-before-binding.txt, where the credential alone was enough.
 CORRECTIVE ACTIONS
   1. Rotate the grants_app password now; treat secrets/web.env as exposed and review who could read it. The actor key did not
      leak in this scenario, but rotate it too if the web host is suspect (re-run scripts/db-apply.sh after replacing secrets/actor.key).
   2. Alert on PostgreSQL 'permission denied' errors for grants_app and on application names the web application does not use.
   3. Tighten pg_hba.conf to the web container address and add pgaudit for statement-level coverage.
   4. Ship the PostgreSQL log to a separate host so the evidence survives a host compromise.
   5. Next: split the web process into a front end and an audit/identity service so that one process does not hold every key.
TXT
} 2>&1 | tee "$OUT"
