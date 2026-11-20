// Captures real screenshots and runs three interface checks with headless
// Chrome (DevTools protocol, no npm packages):
//   - no horizontal scrolling at a narrow mobile width
//   - Tab moves a visible focus ring through the controls
//   - a very long proposal title wraps instead of breaking the layout
// usage: node scripts/screenshots.mjs        (the application must be running)
import { spawn, execSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const BASE = 'https://localhost:8443';
const OUT = 'docs/evidence/screenshots';
const PORT = 9333;
mkdirSync(OUT, { recursive: true });
// Two-step sign-in for officers and auditors: the demo TOTP secrets are in secrets/demo-totp.txt (written by scripts/seed.sh).
const totpSecrets = Object.fromEntries(readFileSync('secrets/demo-totp.txt', 'utf8').trim().split('\n').filter(Boolean).map(l => l.split('\t')).map(p => [p[0], p[1]]));
const b32 = s => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = ''; for (const ch of s.replace(/=+$/, '')) bits += A.indexOf(ch).toString(2).padStart(5, '0'); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const totpAt = (secret, step) => { const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(step)); const m = createHmac('sha1', b32(secret)).update(c).digest(); const o = m[19] & 15; return String(((m[o] & 127) << 24 | m[o + 1] << 16 | m[o + 2] << 8 | m[o + 3]) % 1000000).padStart(6, '0'); };
const lastStep = {};
const nextCode = async who => { let step = Math.floor(Date.now() / 30000); while (lastStep[who] !== undefined && step <= lastStep[who]) { await new Promise(r => setTimeout(r, 1000)); step = Math.floor(Date.now() / 30000); } lastStep[who] = step; return totpAt(totpSecrets[who], step); };
const creds = Object.fromEntries(readFileSync('secrets/demo-credentials.txt', 'utf8').trim().split('\n').map(l => l.split('\t')));
const DESKTOP = { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false };
const MOBILE = { width: 390, height: 844, deviceScaleFactor: 2, mobile: true };

const chrome = spawn('google-chrome', ['--headless=new', `--remote-debugging-port=${PORT}`, '--ignore-certificate-errors',
  `--user-data-dir=${mkdtempSync(join(tmpdir(), 'grants-chrome-'))}`, '--no-first-run', '--hide-scrollbars', 'about:blank'], { stdio: 'ignore' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) {
  await sleep(200);
  try { target = (await (await fetch(`http://127.0.0.1:${PORT}/json`)).json()).find(t => t.type === 'page'); } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r));
let seq = 0; const pending = new Map(); const waiters = [];
ws.addEventListener('message', ev => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result ?? m); pending.delete(m.id); }
  if (m.method === 'Page.loadEventFired') { waiters.splice(0).forEach(w => w()); }
});
const send = (method, params = {}) => new Promise(r => { const id = ++seq; pending.set(id, r); ws.send(JSON.stringify({ id, method, params })); });
const loaded = () => new Promise(r => waiters.push(r));
const js = async expression => (await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })).result?.value;
await send('Page.enable'); await send('Runtime.enable');
// Accept confirm() dialogs automatically (final-action confirmations).
ws.addEventListener('message', ev => { const m = JSON.parse(ev.data); if (m.method === 'Page.javascriptDialogOpening') send('Page.handleJavaScriptDialog', { accept: true }); });

const goto = async path => { const l = loaded(); await send('Page.navigate', { url: BASE + path }); await l; await sleep(150); };
const view = v => send('Emulation.setDeviceMetricsOverride', v);
const report = { captured: [], checks: [] };
const check = (name, pass, detail) => { report.checks.push({ name, pass, detail }); console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? '  [' + detail + ']' : ''}`); };
const shot = async (name) => {
  const { data } = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  writeFileSync(join(OUT, name + '.png'), Buffer.from(data, 'base64'));
  report.captured.push(name + '.png');
};
const noSideScroll = async name => {
  const d = await js('({sw: document.documentElement.scrollWidth, iw: window.innerWidth})');
  check(`mobile 390px: no horizontal scroll on ${name}`, d.sw <= d.iw, `scrollWidth ${d.sw} <= viewport ${d.iw}`);
};
const login = async who => {
  await send('Network.clearBrowserCookies');
  await goto('/login');
  const l = loaded();
  await js(`document.getElementById('email').value=${JSON.stringify(who)};document.getElementById('password').value=${JSON.stringify(creds[who])};document.querySelector('form').submit()`);
  await l; await sleep(150);
  if ((await js('location.pathname')) === '/login/mfa') {          // the second factor, for roles that require it
    const l2 = loaded();
    await js(`document.getElementById('code').value=${JSON.stringify(await nextCode(who))};document.querySelector('form').submit()`);
    await l2; await sleep(150);
  }
};
const submitWith = async (fill, buttonSelector) => { const l = loaded(); await js(`${fill};document.querySelector(${JSON.stringify(buttonSelector)}).click()`); await l; await sleep(150); };
const firstHref = prefix => js(`(document.querySelector('a.title-link[href^="${prefix}"]')||{}).getAttribute?.('href')`);
const both = async (name, path, mobileCheck = true) => {
  await view(DESKTOP); await goto(path); await shot(name + '-desktop');
  await view(MOBILE); await goto(path); await shot(name + '-mobile');
  if (mobileCheck) await noSideScroll(name);
  await view(DESKTOP);
};

try {
  // ---- login + keyboard focus -------------------------------------------------
  await view(DESKTOP); await send('Network.enable'); await send('Network.clearBrowserCookies');
  await goto('/login'); await shot('01-login-desktop');
  const tab = async () => {
    for (const type of ['keyDown', 'keyUp']) await send('Input.dispatchKeyEvent', { type, key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
    return js(`(()=>{const a=document.activeElement,s=getComputedStyle(a);return {el:(a.id||a.className||a.tagName)+'',text:(a.innerText||a.value||'').trim().slice(0,30),outline:s.outlineStyle+' '+s.outlineWidth}})()`);
  };
  const order = []; for (let i = 0; i < 4; i++) order.push(await tab());
  check('keyboard: Tab order on login is skip link, e-mail, password, Sign in',
    order.map(o => o.el).join(' > ') === 'skip-link > email > password > btn btn-primary', order.map(o => o.el).join(' > '));
  check('keyboard: every focused control shows a visible outline', order.every(o => /solid 3px/.test(o.outline)), order.map(o => o.outline).join(', '));
  await js(`document.getElementById('email').focus()`); await shot('02-login-keyboard-focus-desktop');

  // ---- researcher ---------------------------------------------------------------
  await login('amina.elidrissi@uni.example');
  await both('03-researcher-inbox', '/proposals');
  await view(DESKTOP); await goto('/proposals/3');            // another researcher's proposal: denied + audited
  check('researcher A is refused researcher B\'s proposal page', (await js('document.title')).startsWith('Not found'), await js('document.title'));
  await shot('04-researcher-denied-other-proposal-desktop');
  await goto('/proposals/new?call=1');
  await submitWith(`document.getElementById('title').value='AI';document.getElementById('abstract').value='Text the researcher typed is kept.';document.getElementById('requested_amount').value='twelve thousand'`, 'button[value="save"]');
  await shot('05-researcher-form-validation-desktop');
  check('form: values preserved and errors tied to fields after a failed save',
    await js(`document.getElementById('abstract').value.includes('is kept') && document.getElementById('requested_amount').value==='twelve thousand' && document.getElementById('title').getAttribute('aria-describedby')==='title-error' && !!document.getElementById('requested_amount-error')`));
  // long title: 200 characters, the first 90 without a single space
  const longTitle = 'Hyperparametrisierungsoptimierungsverfahrensdokumentationsgenerierungsinfrastrukturkomponenten'.slice(0, 90) + ' and a Deliberately Long Proposal Title That Keeps Going to Test Wrapping in Tables and Headings on Narrow Screens';
  await goto('/proposals/new?call=1');
  await submitWith(`document.getElementById('title').value=${JSON.stringify(longTitle.slice(0, 200))};document.getElementById('abstract').value='Long-title layout check (fictional).';document.getElementById('requested_amount').value='1234.5'`, 'button[value="save"]');
  const draftPath = await js('location.pathname');
  await both('06-researcher-long-title-inbox', '/proposals');
  await view(MOBILE); await goto(draftPath); await noSideScroll('draft form with a 200-character title'); await view(DESKTOP);
  await goto(draftPath);
  await submitWith('void 0', '.danger-zone button');            // clean up the layout-test draft
  check('long-title draft removed after the check', !(await js('document.body.innerText')).includes('Hyperparametrisierungs'));
  await goto('/proposals/6'); await shot('07-researcher-decision-view-desktop');

  // ---- reviewer -----------------------------------------------------------------
  await login('karim.ouazzani@uni.example');
  await goto('/reviews'); await shot('08-reviewer-list-desktop');
  await both('09-reviewer-workspace', await firstHref('/reviews/'));
  await login('salma.tazi@uni.example');
  await goto('/reviews/1'); await shot('10-reviewer-final-review-locked-desktop');

  // ---- officer ------------------------------------------------------------------
  await login('nadia.berrada@uni.example');
  await both('11-officer-queue', '/officer');
  await view(DESKTOP); await goto('/officer/proposals/1');
  await js(`document.querySelector('input[value="approved"]').click();const a=document.getElementById('awarded_amount');a.value='150000';a.dispatchEvent(new Event('input',{bubbles:true}))`);
  check('decision screen previews the resulting balance (600,000 - 150,000)', (await js(`document.getElementById('resulting-balance').textContent`)) === '450,000.00', await js(`document.getElementById('resulting-balance').textContent`));
  await shot('12-officer-decision-desktop');
  await view(MOBILE); await goto('/officer/proposals/1'); await shot('12-officer-decision-mobile'); await noSideScroll('officer decision screen'); await view(DESKTOP);
  await goto('/officer/proposals/4'); await shot('13-officer-decision-unavailable-explained-desktop');
  await goto('/officer/calls'); await shot('14-officer-calls-desktop');

  // ---- auditor ------------------------------------------------------------------
  await login('omar.chraibi@uni.example');
  await both('15-auditor-timeline', '/audit');
  await view(DESKTOP); await goto('/audit?outcome=denied'); await shot('16-auditor-filter-denied-desktop');
  await goto('/audit');
  await send('Emulation.setEmulatedVisionDeficiency', { type: 'achromatopsia' });
  await shot('17-auditor-timeline-grayscale-desktop');
  await send('Emulation.setEmulatedVisionDeficiency', { type: 'none' });
  const g = await js(`(()=>{const d=document.querySelector('tr.outcome-denied td'),s=document.querySelector('tr.outcome-success td');if(!d||!s)return null;const a=getComputedStyle(d),b=getComputedStyle(s);return {deniedWeight:a.fontWeight,successWeight:b.fontWeight,deniedMarker:a.boxShadow!=='none',deniedBadge:getComputedStyle(document.querySelector('.badge-denied'),'::before').borderRadius,successBadge:getComputedStyle(document.querySelector('.badge-success'),'::before').borderRadius}})()`);
  check('timeline: denied differs from success without colour (weight, edge marker, badge shape)',
    !!g && g.deniedWeight !== g.successWeight && g.deniedMarker && g.deniedBadge !== g.successBadge, JSON.stringify(g));

  // ---- security controls added by the remediation release (findings F02-F05) ----------
  // 20 failed sign-ins from this address, then the 21st is refused with HTTP 429 before any hashing.
  await send('Network.clearBrowserCookies');
  await goto('/login');
  const refused = await js(`(async () => {
    const token = document.querySelector('input[name=_csrf]').value;
    const codes = [];
    for (let i = 0; i < 20; i++) {
      const r = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ _csrf: token, email: 'spray' + i + '@uni.example', password: 'Password1' }) });
      codes.push(r.status);
    }
    return codes.join(',');
  })()`);
  check('throttle: 20 failed sign-ins from one address are all processed (401)', refused === Array(20).fill(401).join(','), refused);
  await js(`document.getElementById('email').value='amina.elidrissi@uni.example';document.getElementById('password').value='not-checked';`);
  const lt = loaded();
  await js(`document.querySelector('form').submit()`); await lt; await sleep(150);
  const bodyText = await js('document.body.innerText');
  check('throttle: the 21st attempt is refused with a message that names no account', /Too many failed attempts/.test(bodyText) && !/amina/i.test(bodyText.replace(/E-mail[^\n]*/g, '')), bodyText.split('\n').find(l => /Too many/.test(l)));
  await shot('18-login-throttled-desktop');
  // Operator clears the throttle (the application itself cannot): a legitimate sign-in works again.
  execSync(`docker compose exec -T -u postgres db psql -X -q -d grants -c "DELETE FROM grants.login_failures"`, { stdio: 'ignore' });
  await login('omar.chraibi@uni.example');
  await goto('/audit?action=auth.throttle'); await shot('19-auditor-throttle-event-desktop');
  check('auditor sees the throttle event (written once, not once per request)', (await js(`document.querySelectorAll('table tbody tr').length`)) === 1, String(await js(`document.querySelectorAll('table tbody tr').length`)));

  // ---- second factor, deadlines and export (remediation release 2) ---------------------------------------
  const passwordStep = async who => {                           // password only: stops at the second-factor page
    await send('Network.clearBrowserCookies'); await goto('/login');
    const l = loaded();
    await js(`document.getElementById('email').value=${JSON.stringify(who)};document.getElementById('password').value=${JSON.stringify(creds[who])};document.querySelector('form').submit()`);
    await l; await sleep(150);
  };
  await view(DESKTOP);
  await passwordStep('omar.chraibi@uni.example');
  check('two-step: after the password an auditor is sent to the second factor, not signed in', (await js('location.pathname')) === '/login/mfa', await js('location.pathname'));
  await shot('20-mfa-challenge-desktop');
  await goto('/audit');
  check('two-step: the audit page is still closed without the code', (await js('location.pathname')) === '/login', await js('location.pathname'));

  // Enrolment: reset the officer's factor as an operator, then sign in with the password only.
  execSync('scripts/mfa-reset.sh nadia.berrada@uni.example', { stdio: 'ignore' });
  await passwordStep('nadia.berrada@uni.example');
  check('two-step: an officer without a second factor is sent to set one up', /Set up two-step sign-in/.test(await js('document.body.innerText')), await js('location.pathname'));
  await shot('21-mfa-enrollment-desktop');
  await view(MOBILE); await goto('/login/mfa'); await noSideScroll('two-step enrolment page (long otpauth address wraps)'); await view(DESKTOP);
  const newSecret = (await js(`document.getElementById('mfa-secret').textContent`)).replace(/\s+/g, '');
  const l3 = loaded();
  await js(`document.getElementById('code').value=${JSON.stringify(totpAt(newSecret, Math.floor(Date.now() / 30000)))};document.querySelector('form').submit()`);
  await l3; await sleep(150);
  check('two-step: the right code enrols the app and shows eight recovery codes once', (await js(`document.querySelectorAll('#recovery-codes li').length`)) === 8, String(await js(`document.querySelectorAll('#recovery-codes li').length`)));
  await shot('22-mfa-recovery-codes-desktop');
  // Put the demo account back on its shared demo secret (the same operation scripts/seed.sh performs).
  execSync('scripts/mfa-reset.sh nadia.berrada@uni.example', { stdio: 'ignore' });
  execSync('docker compose --profile ops exec -T -u grantsweb -e DB_NAME=grants ops php scripts/seed_mfa.php', { stdio: 'ignore' });
  delete lastStep['nadia.berrada@uni.example'];

  await login('nadia.berrada@uni.example');
  await goto('/officer/proposals/3'); await shot('23-officer-extend-deadline-desktop');
  check('deadlines: the officer sees a form to extend an open review', /Extend deadline/.test(await js('document.body.innerText')), 'Extend deadline');
  await login('omar.chraibi@uni.example');
  await goto('/audit'); await shot('24-auditor-export-csv-desktop');
  check('export: the auditor timeline offers a CSV download', (await js(`!!document.querySelector('a[href^="/audit/export.csv"]')`)) === true, 'Export CSV');

  // Security keys (WebAuthn) with Chrome's virtual authenticator: register a key, then sign in with it instead of a code.
  await send('WebAuthn.enable');
  await send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await login('omar.chraibi@uni.example');
  await goto('/account/security'); await shot('31-security-keys-empty-desktop');
  await js(`document.getElementById('wa-name').value='Office security key';document.getElementById('wa-add').click()`);
  for (let i = 0; i < 40 && (await js('location.pathname')) === '/account/security' && !/Office security key/.test(await js('document.body.innerText')); i++) { await sleep(250); }
  await sleep(500);
  check('security key: a key is registered from the account page and listed by name', /Office security key/.test(await js('document.body.innerText')), 'listed');
  await shot('32-security-keys-registered-desktop');
  await passwordStep('omar.chraibi@uni.example');
  check('security key: the second-factor page offers the key', (await js(`!!document.getElementById('wa-go') && !document.getElementById('wa-login').hidden`)) === true, 'button visible');
  await shot('33-security-key-signin-desktop');
  await js(`document.getElementById('wa-go').click()`);
  for (let i = 0; i < 40 && (await js('location.pathname')) === '/login/mfa'; i++) { await sleep(250); }
  check('security key: touching the key signs the auditor in without a code', (await js('location.pathname')) === '/audit', await js('location.pathname'));
  await goto('/account/security');
  await js(`document.querySelector('form[action$="/delete"] button').click()`); await sleep(800);
  check('security key: the key can be removed again', !/Office security key/.test(await js('document.body.innerText')), 'removed');
  await send('WebAuthn.disable');
} finally {
  writeFileSync('docs/evidence/ui-checks.json', JSON.stringify({ ranAt: new Date().toISOString(), chrome: 'Google Chrome headless', ...report }, null, 2));
  ws.close(); chrome.kill();
}
const failed = report.checks.filter(c => !c.pass).length;
console.log(`\n${report.captured.length} screenshots, ${report.checks.length} checks, ${failed} failed`);
process.exit(failed ? 1 : 0);
