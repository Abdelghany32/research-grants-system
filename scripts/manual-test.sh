#!/usr/bin/env bash
# Open the project for MANUAL testing: brings the stack up if needed, shows the demo accounts with their passwords and
# the CURRENT two-step codes, opens the browser, and prints a checklist of things to try.
#
#   scripts/manual-test.sh            start (if needed), print everything, open the browser
#   scripts/manual-test.sh --reset    first rebuild the demo data from scratch (accounts, proposals, reviews)
#   scripts/manual-test.sh --no-open  do not launch the browser
#   scripts/manual-test.sh codes      keep printing the current codes for the officer and the auditor (Ctrl-C to stop)
#   scripts/manual-test.sh stop       stop the stack (data is kept)
#   scripts/manual-test.sh logs       follow the application, database-audit and mail logs
. "$(dirname "$0")/lib.sh"
URL="https://localhost:${HTTPS_PORT:-8443}"
OFFICER=nadia.berrada@uni.example; AUDITOR=omar.chraibi@uni.example

code_for() { python3 scripts/totp.py "$1" 2>/dev/null || echo "------"; }
left() { echo $((30 - $(date +%s) % 30)); }

case "${1:-}" in
  codes)
    echo "Current two-step codes for the demo officer and auditor (they change every 30 seconds; Ctrl-C to stop)"
    while true; do printf '\r  officer %s   auditor %s   (%2ss left)  ' "$(code_for $OFFICER)" "$(code_for $AUDITOR)" "$(left)"; sleep 1; done ;;
  stop)  dc stop; echo "stopped. Start again with scripts/manual-test.sh"; exit 0 ;;
  logs)  dc logs -f --tail 20 web identity notifier logship; exit 0 ;;
esac

RESET=0; OPEN=1
for a in "$@"; do case "$a" in --reset) RESET=1 ;; --no-open) OPEN=0 ;; esac; done

# 1. Make sure everything is installed and running.
if [ ! -s secrets/demo-credentials.txt ] || ! dc ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx web; then
  echo "== starting the stack (first start builds the images; this can take a few minutes)"
  scripts/setup.sh >/dev/null
fi
dc up -d web identity notifier logship >/dev/null 2>&1
load_secrets
if [ "$RESET" = 1 ]; then
  echo "== rebuilding the demo data"
  scripts/db-apply.sh grants --reset >/dev/null 2>&1
  scripts/seed.sh grants >/dev/null 2>&1
fi
for _ in $(seq 1 30); do curl -ksf -o /dev/null "$URL/login" && break; sleep 1; done
curl -ksf -o /dev/null "$URL/login" || { echo "The application does not answer on $URL. Look at: docker compose logs web identity" >&2; exit 1; }

# 2. What to open and how to sign in.
echo
echo "================================================================================"
echo " RESEARCH GRANTS - ready for manual testing"
echo "================================================================================"
echo " Application   $URL      (self-signed certificate: accept the browser warning once)"
echo " Mail outbox   $(pwd)/logs/outbox/            (every e-mail the system sends is written here as a .eml file)"
echo " Audit log     $URL/audit                     (sign in as the auditor)"
echo
printf ' %-30s %-11s %-22s %s\n' "ACCOUNT" "ROLE" "PASSWORD" "TWO-STEP CODE NOW"
while IFS=$'\t' read -r email name dept role; do
  [ "$email" = email ] && continue
  pw=$(awk -F'\t' -v e="$email" '$1==e {print $2}' secrets/demo-credentials.txt)
  c="-"; case "$role" in officer|auditor) c="$(code_for "$email")" ;; esac
  printf ' %-30s %-11s %-22s %s\n' "$email" "$role" "$pw" "$c"
done < database/seed_users.tsv
echo
echo " Officers and auditors are asked for a 6-digit code after the password. The code changes every 30 seconds"
echo " (a code is accepted once). Keep scripts/manual-test.sh codes open in a second terminal to read them."
cat <<TXT

 THINGS TO TRY (about 20 minutes)
  1. As a researcher (amina) create a proposal, save it as a draft, edit it, submit it. Try to open another
     researcher's proposal by changing the number in the address: you get "not found", never their data.
  2. As the officer (nadia) assign a reviewer to the submitted proposal. Look in logs/outbox/ for the e-mail the
     reviewer received (it names a link, never the proposal's content).
  3. As the reviewer (salma) write and submit a review. Comments are stored encrypted.
  4. As the officer record a decision: try an award larger than the request or than the remaining budget (refused),
     then a valid one. Try to decide the same proposal twice (refused).
  5. As the auditor (omar) open Audit: every step above is there, with who, what, when. Filter, export the CSV.
  6. Sign-in security: enter a wrong password five times (the account is locked for that address for a while,
     and the message never says whether the e-mail exists). Enter a wrong two-step code.
  7. Security key: as officer or auditor open Security (bottom of the left menu), add a key. A real key, a phone
     or the browser's built-in passkey works on https://localhost:8443. Sign out, sign in again and choose
     "Use security key" instead of the code. (Chrome DevTools > More tools > WebAuthn has a virtual key.)
  8. Role walls: as the researcher open $URL/audit or $URL/officer: forbidden, and recorded in the audit log.
  9. Break-glass: scripts/mfa-reset.sh $OFFICER  removes an officer's second factor and keys (lost phone).
 10. Database side (for the oral defence): scripts/check-isolation.sh, scripts/check-logship.sh, scripts/test.sh,
     scripts/pentest.sh  and  docker compose exec logship php /srv/ship/logship.php export 2026-01-01 db | tail

 Start over with fresh demo data: scripts/manual-test.sh --reset      Stop: scripts/manual-test.sh stop
TXT
if [ "$OPEN" = 1 ]; then
  (command -v xdg-open >/dev/null && xdg-open "$URL" || command -v open >/dev/null && open "$URL") >/dev/null 2>&1 || true
fi
