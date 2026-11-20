#!/usr/bin/env bash
# Demonstrates the field-key lifecycle on the live demo database: add a key, keep
# reading old data, refuse an unsafe retirement, re-encrypt, verify, retire.
# Evidence: docs/evidence/key-rotation.txt (key material is never printed).
. "$(dirname "$0")/lib.sh"
load_secrets
OUT=docs/evidence/key-rotation.txt
verify() { ops_run ops php scripts/verify-comments.php; }
{
echo "FIELD-KEY ROTATION DRILL - $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC) - database grants"
OLD=$(scripts/rotate-field-key.sh status | sed -n '2p' | awk '{print $1}')
echo; echo "== 1. Before"; scripts/rotate-field-key.sh status; verify
echo; echo "== 2. Add a new active key (the previous keys stay in the keyring, for decryption only)"
scripts/rotate-field-key.sh add; scripts/rotate-field-key.sh status
echo; echo "== 3. Nothing breaks at the moment of the key change: old values still decrypt"; verify
echo; echo "== 4. Retiring the previous key now is refused, because rows still depend on it"
scripts/rotate-field-key.sh retire "$OLD" || echo "(refused, exit code $?)"
echo; echo "== 5. Re-encrypt every comment under the new key (one transaction, audited as admin.rotate_field_key)"
scripts/rotate-field-key.sh reencrypt
echo; echo "== 6. Verify through the application path"; verify
echo; echo "== 7. Now the previous key can be retired"
scripts/rotate-field-key.sh retire "$OLD"; scripts/rotate-field-key.sh status; verify
echo; echo "== 8. The rotation is in the audit trail (read through the auditor account)"
ops_run ops php scripts/audit_report.php "$(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%SZ)" | grep -E "rotate_field_key|^id" || true
} 2>&1 | tee "$OUT"
