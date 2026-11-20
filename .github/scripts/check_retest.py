#!/usr/bin/env python3
"""Fail the build when a retest result says a finding is still exploitable or the run did not complete.

Reads the JSON written by scripts/pentest/retest-auth.py or scripts/pentest/deep-db.php: a list of
{"id", "status", "evidence"}. Statuses that are fine: REMEDIATED, CONTROL, PASS, OBSERVED_*, CONFIRMED_TRUST_BOUNDARY
(documented observations such as O01 that are open by design).
"""
import json, sys

bad = {"STILL_OPEN", "STILL_EXPLOITABLE", "FAIL", "INCOMPLETE", "CONFIRMED_FINDING"}
results = json.load(open(sys.argv[1]))
problems = [r for r in results if r["status"] in bad]
for r in results:
    print(f'{r["id"]:10} {r["status"]}')
if problems:
    print("\nNOT REMEDIATED / INCOMPLETE:", ", ".join(r["id"] for r in problems))
    sys.exit(1)
