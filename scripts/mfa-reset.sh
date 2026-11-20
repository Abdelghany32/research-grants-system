#!/usr/bin/env bash
# Operator tool: reset ONE person's second factor (lost phone AND recovery codes; their security keys are removed too). They enrol a new authenticator
# app at their next sign-in. The reset is recorded in the audit trail (admin.mfa_reset).
#   scripts/mfa-reset.sh nadia.berrada@uni.example [database]
. "$(dirname "$0")/lib.sh"
load_secrets
EMAIL="${1:?usage: mfa-reset.sh <e-mail> [database]}"; DB="${2:-grants}"; valid_db_name "$DB"
clean=$(printf '%s' "$EMAIL" | tr -cd 'A-Za-z0-9@._+-'); found=$(psql_admin "$DB" -Atc "SELECT count(*) FROM grants.users WHERE email = lower('$clean')" 2>/dev/null || true)
[ "$found" = "1" ] || { echo "no such account: $EMAIL" >&2; exit 2; }
psql_admin "$DB" -v email="$EMAIL" <<'SQL'
WITH u AS (UPDATE grants.users SET totp_secret_enc = NULL, totp_enrolled_at = NULL, totp_last_step = 0
            WHERE email = lower(:'email') RETURNING id),
     d AS (DELETE FROM grants.mfa_recovery_codes WHERE user_id IN (SELECT id FROM u)),
     k AS (DELETE FROM grants.webauthn_credentials WHERE user_id IN (SELECT id FROM u))
INSERT INTO grants.audit_events (action, resource_type, resource_id, outcome, details)
SELECT 'admin.mfa_reset', 'user', id, 'success', jsonb_build_object('by', 'database administrator', 'database', current_database()) FROM u;
SQL
echo "second factor reset for $EMAIL in $DB: they enrol again at the next sign-in"
