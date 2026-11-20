#!/usr/bin/env bash
# Simulated incident, using only normal application actions over HTTPS:
#   1. reviewer Karim tries to open a review that is assigned to Salma  -> denied
#   2. officer Nadia records a legitimate award on that proposal        -> success
# Then the events are read back through the auditor account.
# Evidence: docs/evidence/incident-timeline.txt
. "$(dirname "$0")/lib.sh"
load_secrets
BASE=https://localhost:8443
JAR=$(mktemp -d)
OUT=docs/evidence/incident-timeline.txt
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)

token() { curl -ks -b "$JAR/$1" -c "$JAR/$1" "$BASE$2" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | cut -d'"' -f4; }
login() {
  local pw out status loc; pw=$(grep "^$1" secrets/demo-credentials.txt | cut -f2)
  out=$(curl -ks -b "$JAR/$1" -c "$JAR/$1" -o /dev/null -w '%{http_code} %{redirect_url}' \
    --data-urlencode "_csrf=$(token "$1" /login)" --data-urlencode "email=$1" --data-urlencode "password=$pw" "$BASE/login")
  status=${out%% *}; loc=${out#* }
  if [[ "$loc" == */login/mfa ]] && grep -q "^$1" secrets/demo-totp.txt; then          # officers and auditors: second factor
    local second; second=$(curl -ks -b "$JAR/$1" -c "$JAR/$1" -o /dev/null -w '%{http_code}' \
      --data-urlencode "_csrf=$(token "$1" /login/mfa)" --data-urlencode "code=$(python3 scripts/totp.py "$1" --fresh)" "$BASE/login/mfa")
    echo "  login $1 -> HTTP $status (password), then HTTP $second (second factor)"
  else
    echo "  login $1 -> HTTP $status"
  fi
}
PROPOSAL=$(psql_admin grants -Atc "SELECT id FROM grants.proposals WHERE title LIKE 'Federated Learning%'")
REVIEW=$(psql_admin grants -Atc "SELECT id FROM grants.reviews WHERE proposal_id = $PROPOSAL ORDER BY id LIMIT 1")
state() { psql_admin grants -c "SELECT p.id AS proposal, p.status, p.requested_amount, d.outcome, d.awarded_amount, c.id AS call, c.remaining_budget
  FROM grants.proposals p JOIN grants.grant_calls c ON c.id = p.call_id LEFT JOIN grants.decisions d ON d.proposal_id = p.id WHERE p.id = $PROPOSAL"; }

{
echo "SIMULATED INCIDENT - run started $START (UTC)"
echo "Proposal #$PROPOSAL, review #$REVIEW (assigned to salma.tazi)."
echo; echo "== Record state before"; state
echo "== Step 1: karim.ouazzani (reviewer, NOT assigned) requests /reviews/$REVIEW"
login karim.ouazzani@uni.example
curl -ks -b "$JAR/karim.ouazzani@uni.example" -o /dev/null -w "  GET /reviews/$REVIEW -> HTTP %{http_code}\n" "$BASE/reviews/$REVIEW"
curl -ks -b "$JAR/karim.ouazzani@uni.example" -o /dev/null -w "  GET /officer/proposals/$PROPOSAL -> HTTP %{http_code}\n" "$BASE/officer/proposals/$PROPOSAL"
echo "== Step 2: nadia.berrada (officer) records a legitimate award of 150,000.00"
login nadia.berrada@uni.example
curl -ks -b "$JAR/nadia.berrada@uni.example" -o /dev/null -w "  POST /officer/proposals/$PROPOSAL/decision -> HTTP %{http_code}\n" \
  --data-urlencode "_csrf=$(token nadia.berrada@uni.example /officer/proposals/$PROPOSAL)" \
  --data-urlencode "outcome=approved" --data-urlencode "awarded_amount=150000.00" \
  --data-urlencode "rationale=Approved at a reduced amount." "$BASE/officer/proposals/$PROPOSAL/decision"
echo; echo "== Record state after"; state
echo "== Events since $START, read through the grants_auditor account (audit_timeline view)"
ops_run ops php scripts/audit_report.php "$START"
} 2>&1 | tee "$OUT"
