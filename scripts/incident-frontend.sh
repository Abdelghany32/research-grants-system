#!/usr/bin/env bash
# SIMULATED INCIDENT 3 - the web FRONT END process is compromised. A victim is signed in; the attacker runs inside the web
# container with only what that process holds. Part 2 reads what the defender can see (audit trail, PostgreSQL log).
# Evidence: docs/evidence/incident-frontend.txt
. "$(dirname "$0")/lib.sh"
load_secrets
OUT=docs/evidence/incident-frontend.txt
BASE=https://localhost:${HTTPS_PORT:-8443}
JAR=$(mktemp -d); trap 'rm -rf "$JAR"' EXIT
START=$(date -u +%Y-%m-%dT%H:%M:%SZ); sleep 1
tok() { curl -ks -b "$JAR/v" -c "$JAR/v" "$BASE$1" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | cut -d'"' -f4; }
{
echo "SIMULATED INCIDENT 3: COMPROMISED WEB FRONT END - started $START (UTC) - live stack"
echo
echo "################ PART 1 - setup: a legitimate user is signed in (the victim) ################"
PW=$(grep '^amina.elidrissi' secrets/demo-credentials.txt | cut -f2)
curl -ks -b "$JAR/v" -c "$JAR/v" -o /dev/null -w "  amina.elidrissi signs in through the web front end -> HTTP %{http_code}\n" \
  --data-urlencode "_csrf=$(tok /login)" --data-urlencode "email=amina.elidrissi@uni.example" --data-urlencode "password=$PW" "$BASE/login"
echo
psql_admin grants -c "DELETE FROM grants.login_failures WHERE host(source_ip) = '198.51.100.99' OR host(source_ip) LIKE '203.0.113.%'" >/dev/null   # a clean start (operator cleanup)
echo "################ PART 2 - the attacker's session (code execution inside the web container) ################"
dc exec -T web php < scripts/incident_frontend.php
sleep 1
echo
echo "################ PART 3 - the investigation (evidence only) ################"
echo
echo "---- 3a. Application audit trail since the alert ----"
ops_run -e DB_NAME=grants ops php scripts/audit_report.php "$START" | cut -c1-200
echo
echo "---- 3b. Reading of the evidence ----"
cat <<'TXT'
 WHAT HAPPENED   Code ran inside the web front end. It could not read a single password hash, the identity table, the actor key, the
                 audit-writer or notifier passwords, or write an audit event: none of them is in that container or reachable with its
                 database account. It could use the identity service's API (it holds the API key) and see the handles of users
                 signed in at that moment.
 CONTROLS THAT HELD
   * No hashes (O01 closed), no identity secrets, no forged "proved" audit events, no token for a user without a live session.
   * The identity service refuses unsigned calls and methods outside its whitelist; row-level security still limits a stolen
     session to that one user's rows.
 WEAKNESSES THAT REMAIN (stated, not hidden)
   * Sessions: the process can act as the users who are signed in right now (it sees their handles), until they log out or expire.
     Before the split it could act as ANY user.
   * Guessing: the client address is reported by the front end, so a compromised front end can spread guesses over many fake
     addresses and avoid the per-address throttle. Officers and auditors still need the second factor; researchers and reviewers
     are exposed to slow, Argon2-limited guessing. Mitigation to add: an account-level slow-down independent of the reported address.
   * The compromised process still sees plaintext passwords as users type them (it terminates the login form).
 CORRECTIVE ACTIONS
   1. Rotate IDENTITY_API_KEY and the web database password; end all sessions (DELETE FROM identity_sessions).
   2. Find the entry point (web logs, PostgreSQL log, container image provenance) and rebuild the front end from a clean image.
   3. Add an account-level slow-down and alerting on many failures for one account (auth.suspicious_volume already fires at 20/hour).
   4. Phishing-resistant second factor (WebAuthn) and short session lifetimes for privileged roles.
TXT
} 2>&1 | tee "$OUT"
