#!/usr/bin/env python3
"""Render excerpts of the REAL evidence files as dark-terminal PNG figures for the report.

Reads only docs/evidence/* (it never touches the database or re-runs a test), builds a small HTML page per
excerpt and screenshots it with headless Google Chrome. Output: docs/evidence/figures/*.png.

  python3 scripts/render-evidence-figures.py

Rules: excerpts are cut from the evidence files unchanged, except that (a) very long lines are wrapped,
(b) a few verbose driver messages are shortened (marked with the word "condensed" in the report caption) and
(c) 32-hex md5 digests are truncated to 8 characters. A scan refuses to write a figure that contains key material,
long hex strings, password hashes or environment-variable secrets.
"""
import html, json, re, subprocess, sys, tempfile, textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EV = ROOT / 'docs/evidence'
OUT = EV / 'figures'
OUT.mkdir(parents=True, exist_ok=True)
WRAP = 118
FORBIDDEN = [r'BEGIN [A-Z ]*KEY', r'[0-9a-f]{33,}', r'\$argon2id\$', r'PASSWORD=', r'PRIVATE KEY']


def read(name):
    return (EV / name).read_text().splitlines()


def between(lines, start, end=None, include_start=True):
    """Lines from the first line containing `start` up to (not including) the next line containing `end`."""
    i = next(k for k, l in enumerate(lines) if start in l)
    j = len(lines)
    if end:
        j = next((k for k in range(i + 1, len(lines)) if end in lines[k]), len(lines))
    return lines[i if include_start else i + 1:j]


def shorten_md5(line):
    return re.sub(r'\b([0-9a-f]{8})[0-9a-f]{24}\b', r'\1...', line)


def classify(line):
    s = line
    if s.startswith('PASS'):
        return 'g'          # a passing test stays green even when its name says "refused" or "denied"
    if re.match(r'^\s*(==|####|----)', s) or s.startswith('RECOVERY DRILL') or s.startswith('SIMULATED') or s.startswith('BACKUP-KEY') \
            or s.startswith('FIELD-KEY') or s.startswith('SQL INJECTION LAB') or s.startswith('PENETRATION'):
        return 'h'
    if re.search(r'REFUSED|refused|ERROR|denied|FAIL|failed|STILL|permission denied|leaked|rejects', s) and not re.search(r'0 failed', s):
        return 'r'
    if re.search(r'\bPASS\b|MATCH|IDENTICAL|REMEDIATED|RESISTED|OK\b|resisted|0 failed|no error|no longer exploitable|IMPACT LIMITED|decrypt', s):
        return 'g'
    if re.match(r'^\s*(Phase|PART|A\d|---- )', s):
        return 'y'
    return ''


CSS = """
body{margin:0;background:#0b1220;font-family:'DejaVu Sans Mono',monospace}
.win{background:#0f172a;border:1px solid #334155;border-radius:10px;overflow:hidden;width:1100px}
.bar{background:#1e293b;height:30px;display:flex;align-items:center;padding:0 12px;color:#94a3b8;font-size:13px}
.dot{width:11px;height:11px;border-radius:50%;margin-right:7px;display:inline-block}
.t{margin-left:10px}
pre{margin:0;padding:12px 16px 14px 16px;color:#e2e8f0;font-size:14px;line-height:20px;white-space:pre}
.h{color:#7dd3fc;font-weight:bold}.g{color:#86efac}.r{color:#fca5a5}.y{color:#fde68a}.m{color:#94a3b8}
"""


def render(name, title, lines):
    wrapped = []
    for l in lines:
        l = l.rstrip()
        if len(l) <= WRAP:
            wrapped.append(l)
        else:
            indent = len(l) - len(l.lstrip())
            parts = textwrap.wrap(l, WRAP, subsequent_indent=' ' * (indent + 4), break_long_words=True, replace_whitespace=False)
            wrapped.extend(parts)
    text = '\n'.join(wrapped)
    for pat in FORBIDDEN:
        if re.search(pat, text):
            sys.exit(f'refusing to render {name}: matches forbidden pattern {pat}')
    body = '\n'.join(f'<span class="{classify(l)}">{html.escape(l)}</span>' for l in wrapped)
    page = f"""<!doctype html><meta charset=utf-8><style>{CSS}</style><body><div class=win>
<div class=bar><span class=dot style=background:#f87171></span><span class=dot style=background:#fbbf24></span><span class=dot style=background:#4ade80></span>
<span class=t>{html.escape(title)}</span></div><pre>{body}</pre></div></body>"""
    height = 30 + 26 + 20 * len(wrapped) + 16
    with tempfile.NamedTemporaryFile('w', suffix='.html', delete=False) as f:
        f.write(page)
        path = f.name
    subprocess.run(['google-chrome', '--headless=new', '--disable-gpu', '--hide-scrollbars', '--force-device-scale-factor=2',
                    f'--window-size=1104,{height + 4}', f'--screenshot={OUT / (name + ".png")}', f'file://{path}'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
    Path(path).unlink()
    print(f'{name}.png  {len(wrapped)} lines')


# ------------------------------------------------------------------------------------------ privileges
priv = read('privileges.txt')
ops = between(priv, 'Operations attempted under the real restricted accounts', 'Even the schema owner')
ops = [re.sub(r'SQLSTATE\[(\w+)\]: [A-Za-z ]+: \d+ ERROR: ', r'\1 ', l).replace('REFUSED 42501 ', 'REFUSED 42501 ') for l in ops if l.strip()]
ops = [re.sub(r'\s{2,}=>', ' =>', l) for l in ops]
render('fig-privileges', 'scripts/evidence.sh  -  statements tried under the real restricted accounts (condensed)', ops[:18])

# ------------------------------------------------------------------------------------------ SQL injection lab
sq = read('sqli-demo.txt')
before = [sq[0][:112]] + [''] + between(sq, 'A2  UNION: read every account', 'A5  UNION')[:11] + between(sq, 'A5  UNION', 'A7  stacked')[:0]
a34 = between(sq, 'A3  UNION: read password hashes', 'A5  UNION')
a34 = [re.sub(r'SQLSTATE\[(\w+)\]: [A-Za-z ]+: \d+ ERROR: ', r'\1 ', l) for l in a34]
imp = between(sq, 'IMPACT (what the attacker obtained)', '== 2.')
render('fig-sqli-before', 'scripts/sqli-demo.sh  -  BEFORE the fix: what the injection obtained and what it could not (condensed)',
       [sq[0][:112], ''] + between(sq, 'A2  UNION: read every account', 'A3  UNION')[:11] + a34 + [''] + [l for l in imp if l.strip()])
after = between(sq, '== 3. AFTER remediation', '== 4.')
render('fig-sqli-after', 'scripts/sqli-demo.sh  -  AFTER the fix: the same nine payloads through the parameterised query',
       [l for l in after if l.strip()] + [''] + [sq[-1]])

# ------------------------------------------------------------------------------------------ incident 2
inc = read('incident-privileged.txt')
att = between(inc, 'ATTACKER SESSION', '################ PART 2')
render('fig-incident-attacker', 'scripts/incident_privileged.php  -  the attacker session with the stolen grants_app credential (lab)',
       [l for l in att if l.strip()])
anom = between(inc, '---- 2b. Anomaly query', '---- 2c.')
anom = [re.sub(r'\{.*', '{...}', l) if re.match(r'^\d+\s', l) else l for l in anom if l.strip()]
log = between(inc, '---- 2c. PostgreSQL server log', '---- 2d.')
log = [re.sub(r'^(\d\d:\d\d:\d\d\.\d+) \[(\d+)\] ', r'\1 [\2] ', l) for l in log if l.strip()]
log = [re.sub(r'\(/var/lib[^)]*\)', '', l) for l in log]
log = [re.sub(r' \(protocol=TLSv1.3, cipher=.*', ' (TLSv1.3)', l) for l in log]
render('fig-incident-log', 'incident 2 investigation  -  anomaly query on the audit trail, then the PostgreSQL server log for one pid',
       anom + [''] + log[:36])

# ------------------------------------------------------------------------------------------ key management
kr = read('key-rotation.txt')
keep = []
for l in kr:
    if re.search(r'^== (2|4|5|7)\.|new active key|refusing|re-encrypt|value\(s\)|retired|<- active|^  k\d|by key|\(refused', l):
        keep.append(l)
render('fig-keyrotation', 'scripts/key-rotation-drill.sh  -  add, keep reading, refuse unsafe retirement, re-encrypt, retire (key ids only)', keep)
cu = [l for l in read('backup-key-custody.txt') if l.strip()]
render('fig-custody', 'scripts/backup-key-custody-demo.sh  -  separation of custody of the backup private key (temporary keyring copy)', cu)

# ------------------------------------------------------------------------------------------ recovery drill
rd = read('recovery-drill.txt')
sel = [rd[0]]
sel += between(rd, '== 3. Simulated loss', '== 4.')
sel += between(rd, '== 4. Timed recovery', '== 5.')
sel += between(rd, '== 5. Record values', '== 6.')
sel += between(rd, '== 6. Privileges and policies', '== 7.')
sel += between(rd, '== 7. Behaviour', '')[:0]
sel += [l for l in rd if re.match(r'^(PASS|FAIL) |^\d+ checks,|^verification exit|^restored database', l)]
sel += [l for l in rd if 'IDENTICAL: table privileges' in l and l not in sel]
sel = [shorten_md5(l) for l in sel if l.strip()]
render('fig-recovery', 'scripts/recovery-drill.sh  -  loss, timed restore, per-table checksums, privileges, behaviour (md5 digests truncated)', sel)

# ------------------------------------------------------------------------------------------ tests
tr = read('test-results.txt')
suites, cur = {}, None
for l in tr:
    m = re.match(r'^--- (\S+)', l)
    if m:
        cur = m.group(1)
        suites[cur] = [0, 0]
    elif cur and l.startswith('PASS'):
        suites[cur][0] += 1
    elif cur and l.startswith('FAIL'):
        suites[cur][1] += 1
total = re.search(r'^(\d+) tests', ' '.join(l for l in tr if re.match(r'^\d+ tests', l)))
lines = [f'scripts/test.sh  ({total.group(1) if total else "?"} tests against real PostgreSQL, restricted accounts)', '']
for k, (p, f) in suites.items():
    lines.append(f'--- {k:<22} PASS {p:>2}   FAIL {f}')
lines.append('')
lines += [l for l in tr if re.match(r'^\d+ tests,|^\d+ owner-level|^exit code', l)]
lines.append('')
lines += [l for l in tr if l.startswith('PASS  OWNER') and ('HMAC' in l or 'audit' in l or 'balance' in l)][:5]
render('fig-tests', 'docs/evidence/test-results.txt  -  results by suite and the owner-level guard checks (excerpt)', lines)

# ------------------------------------------------------------------------------------------ retest summary
ar = json.loads((EV / 'pentest-after/auth-retest.json').read_text())
db = {r['id']: r for r in json.loads((EV / 'pentest-after/deep-db.json').read_text())}
by = {r['id']: r for r in ar}
s3 = by['F03']['evidence']['samples']
lines = ['retest of the original probes (same randomized order and seed as 11 November)', '']
lines.append('F01 ' + db['DB04']['status'] + '  lone INSERT decisions: ' + db['DB04']['evidence']['original_probe_insert_only_decision']['sqlstate']
             + ' | lone balance UPDATE: ' + db['DB04']['evidence']['balance_only_update']['sqlstate']
             + ' | researcher calls record_decision(): ' + db['DB04']['evidence']['researcher_calls_record_decision']['sqlstate'])
lines.append('    single-door award 1.00: remaining ' + db['DB04']['evidence']['single_door_award_1.00']['remaining_after']
             + ' (was ' + db['DB04']['evidence']['budget_before'] + '), invariant difference ' + db['DB04']['evidence']['allocation_invariant_difference'])
e = by['F02']['evidence']
lines.append(f"F02 {by['F02']['status']}  failures {e['failed_statuses']}  account-wide lock set: {e['account_wide_lock_set']}  attacker address: {e['attacker_address_gate']}  owner's other address: {e['owner_from_another_address_gate']}")
lines.append(f"F03 {by['F03']['status']}  medians (ms, n=20): unknown {s3['unknown']['median_ms']} | unlocked {s3['unlocked']['median_ms']} | locked {s3['locked']['median_ms']}  spread ratio {by['F03']['evidence']['spread_ratio']}")
lines.append('    before (11 Nov): unknown 251.756 | unlocked 254.366 | locked 27.996  (ratio 9.1)')
e = by['F04']['evidence']
lines.append(f"F04 {by['F04']['status']}  30 attempts: {e['status_counts']}  Retry-After {e['retry_after']}  correct password while throttled: {e['correct_password_while_throttled']}")
lines.append(f"F05 {by['F05']['status']}  " + ', '.join(by['F05']['evidence']['headers'].keys()))
lines.append('O02 ' + db['DB03']['status'] + '  claimed officer sees ' + str(db['DB03']['evidence']['claimed_officer_visible_proposals']) + ' proposals with the database password only (before: 18)')
lines.append('O03 ' + db['DB05']['status'] + '  direct INSERT: ' + db['DB05']['evidence']['direct_insert_sqlstate'] + ' | audit_append without token: ' + db['DB05']['evidence']['audit_append_without_token_sqlstate'] + ' | forged rows visible to the auditor: ' + str(db['DB05']['evidence']['forged_rows_visible_to_auditor']))
lines.append(f"AUTH04 {by['AUTH04']['status']}  valid login after cleanup: {by['AUTH04']['evidence']['after_cleanup_valid_login']}")
render('fig-retest', 'pentest-after/auth-retest.json and deep-db.json  -  retest of F01 to F05 (summary)', lines)

# ------------------------------------------------------------------------------------------ black-box pentest
pt = sorted(EV.glob('pentest-2*.txt'))[-1]
pl = pt.read_text().splitlines()
fam = {}
for l in pl:
    m = re.match(r'^RESISTED\s+(\S+)', l)
    if m:
        k = m.group(1).split('-')[0]
        fam[k] = fam.get(k, 0) + 1
lines = [f'scripts/pentest.sh  ({pt.name})  -  black-box checks against the live lab', '']
row = []
for k, v in sorted(fam.items(), key=lambda kv: -kv[1]):
    row.append(f'{k:<8}{v:>3}')
for i in range(0, len(row), 4):
    lines.append('   '.join(row[i:i + 4]))
lines.append('')
lines += [l for l in pl if re.match(r'^RESISTED\s+BRUTE', l)][:8]
lines += [l for l in pl if l.startswith('INFO') or l.startswith('SUMMARY')]
render('fig-pentest', 'scripts/pentest.sh  -  resisted checks per family, the F02-F04 lines and the summary (excerpt)', lines)

# ------------------------------------------------------------------------------------------ incident 2 BEFORE the identity binding
bf = read('incident-privileged-before-binding.txt')
att0 = between(bf, 'ATTACKER SESSION', '################ PART 2')
render('fig-incident-before', 'incident 2 BEFORE identity binding (15:21 UTC)  -  the same attacker session; compare with the run after the fix',
       [l for l in att0 if l.strip()])

# ------------------------------------------------------------------------------------------ release 2 tests
tests2 = [l for l in tr if re.match(r'^PASS  (IDENT|MFA|DEADLINE|EXPORT|MAIL) ', l)]
render('fig-tests-release2', 'docs/evidence/test-results.txt  -  the tests added by release 2 (identity binding, second factor, deadlines, export, mail)',
       [re.sub(r'^PASS  ', 'PASS  ', l)[:150] for l in tests2])

# ------------------------------------------------------------------------------------------ CI workflow
ci = (ROOT / '.github/workflows/ci.yml').read_text().splitlines()
cl = ['.github/workflows/ci.yml  -  jobs and steps (runs on every push and pull request)', '']
for l in ci:
    m = re.match(r'^  (\w+):\s*$', l)
    if m and m.group(1) in ('lint', 'verify', 'image'):
        cl.append(f'job {m.group(1)}')
        continue
    m = re.match(r'^    name: (.*)$', l)
    if m:
        cl[-1] += '  -  ' + m.group(1)
        continue
    m = re.match(r'^      - name: "?(.*?)"?\s*$', l)
    if m:
        cl.append('    - ' + m.group(1))
render('fig-ci', 'CI workflow: what runs on every push (configured in the repository; the first run is on GitHub)', cl)

# ------------------------------------------------------------------------------------------ release 3: identity split, security keys, log shipping
def hex_short(l):
    return re.sub(r'\b([0-9a-f]{12})[0-9a-f]{20,}\b', r'\1...', l)

tests3 = [l for l in tr if re.match(r'^PASS  (SPLIT|WEBAUTHN) ', l)]
render('fig-tests-release3', 'docs/evidence/test-results.txt  -  the tests added by release 3 (identity service split, security keys)',
       [l[:150] for l in tests3])

iso = read('isolation.txt')
keep = [l for l in iso if l.startswith('==') or l.startswith('web account refused') or l.startswith('PASS  web has no ACTOR')
        or l.startswith('PASS  identity holds') or l.startswith('PASS  web has IDENTITY_MODE')]
render('fig-isolation', 'scripts/check-isolation.sh  -  what each process holds (excerpt: the web front end is refused every identity function)',
       [l[:150] for l in iso[:2]] + keep + [l[:150] for l in iso if l.startswith('PASS  web account refused')][:7] + [l for l in iso if l.startswith('SUMMARY')])

fe = read('incident-frontend.txt')
render('fig-incident-frontend', 'incident 3  -  a compromised web front end: what it holds, what the database refuses, what the identity service allows',
       [l for l in between(fe, 'COMPROMISED FRONT END', '################ PART 3') if l.strip()][:46])

ls = [hex_short(l) for l in read('logship.txt')]
render('fig-logship', 'scripts/check-logship.sh  -  pgaudit records reach the hash-chained archive; tampering is detected', [l[:150] for l in ls])

# ------------------------------------------------------------------------------------------ cropped screenshots for the report
# Very tall full-page screenshots are cropped to their top part (the part that carries the claim) so that
# they stay legible in the gallery; the originals in docs/evidence/screenshots/ are unchanged.
from PIL import Image
SHOTS = ROOT / 'docs/latex/shots'
SHOTS.mkdir(parents=True, exist_ok=True)
for name, height in {'24-auditor-export-csv-desktop.png': 1000, '23-officer-extend-deadline-desktop.png': 1000, '15-auditor-timeline-desktop.png': 1000, '17-auditor-timeline-grayscale-desktop.png': 1000,
                     '15-auditor-timeline-mobile.png': 2300, '03-researcher-inbox-mobile.png': 2300,
                     '06-researcher-long-title-inbox-mobile.png': 2300, '09-reviewer-workspace-mobile.png': 2300,
                     '11-officer-queue-mobile.png': 2300, '12-officer-decision-mobile.png': 2300,
                     '31-security-keys-empty-desktop.png': 800, '32-security-keys-registered-desktop.png': 800, '33-security-key-signin-desktop.png': 800}.items():
    im = Image.open(ROOT / 'docs/evidence/screenshots' / name)
    im.crop((0, 0, im.width, min(height, im.height))).save(SHOTS / name, optimize=True)
    print(f'shots/{name} cropped to {min(height, im.height)} px')
