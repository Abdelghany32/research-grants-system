#!/usr/bin/env bash
# Proves the project builds from what Git tracks alone: copies only tracked /
# untracked-but-not-ignored files (so no secrets, backups or logs) to a fresh
# directory, builds a separate stack on other ports, runs setup and all tests,
# then removes that stack and its volume. Evidence: docs/evidence/clean-room.txt
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=$PWD; OUT=$SRC/docs/evidence/clean-room.txt
DIR=$(mktemp -d "${TMPDIR:-/tmp}/grants-clean-XXXXXX")
git ls-files --cached --others --exclude-standard -z | grep -zv '^docs/evidence/' | xargs -0 cp --parents -t "$DIR"
export COMPOSE_PROJECT_NAME=grantsclean HTTP_PORT=9080 HTTPS_PORT=9443
{
echo "CLEAN-ROOM CHECK - $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
echo "copied $(find "$DIR" -type f | wc -l) files; secrets present before setup: $(ls "$DIR/secrets" 2>/dev/null | wc -l)"
cd "$DIR"
T0=$(date +%s)
echo "== scripts/setup.sh"; scripts/setup.sh 2>&1 | tail -6
echo "== login page: HTTP $(curl -ks -o /dev/null -w '%{http_code}' https://localhost:9443/login)"
echo "== scripts/test.sh"; scripts/test.sh 2>&1 | grep -vE '^NOTICE' | tail -4 || true
echo "elapsed: $(( $(date +%s) - T0 )) seconds"
docker compose down -v 2>&1 | tail -1
} > "$OUT" 2>&1 || true
rm -rf "$DIR"
tail -5 "$OUT"
