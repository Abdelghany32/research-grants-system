# Screenshots

Captured by `node scripts/screenshots.mjs` with headless Google Chrome against the running application
(desktop 1280 px, mobile 390 px). Each caption states the claim the image supports.

| File | Claim it supports |
| --- | --- |
| `01-login-desktop.png` | Sign-in is a labelled two-field form with no information about which accounts exist. |
| `02-login-keyboard-focus-desktop.png` | Keyboard focus is visible (3 px outline) on form controls. |
| `03-researcher-inbox-desktop.png`, `-mobile.png` | The inbox leads with open calls, deadlines and "Start proposal"; "My proposals" shows title, call, amount, status and next action; counts cover only the researcher's own rows. |
| `04-researcher-denied-other-proposal-desktop.png` | A researcher requesting another researcher's proposal gets "Not found" with no hint that it exists. |
| `05-researcher-form-validation-desktop.png` | Validation errors appear next to the fields and typed values are preserved. |
| `06-researcher-long-title-inbox-desktop.png`, `-mobile.png` | A 200-character title with a 90-character unbroken word wraps without breaking the layout. |
| `07-researcher-decision-view-desktop.png` | The applicant sees the final decision and the office's message, not the review. |
| `08-reviewer-list-desktop.png` | A reviewer sees only their own assignments. |
| `09-reviewer-workspace-desktop.png`, `-mobile.png` | Proposal summary beside the score and confidential-comments form; panels stack on a narrow screen. |
| `10-reviewer-final-review-locked-desktop.png` | A submitted review is shown as final with no edit form. |
| `11-officer-queue-desktop.png`, `-mobile.png` | The officer queue lists submitted proposals with review progress; tables become labelled records on mobile. |
| `12-officer-decision-desktop.png`, `-mobile.png` | Requested funds, available funds, completed review, proposed award and resulting balance are visible together. |
| `13-officer-decision-unavailable-explained-desktop.png` | When no decision is possible the screen says why in plain language. |
| `14-officer-calls-desktop.png` | Call budgets and remaining balances are right-aligned with two decimals. |
| `15-auditor-timeline-desktop.png`, `-mobile.png` | Timeline shows time, actor, action, resource and outcome with filters; no proposal text. |
| `16-auditor-filter-denied-desktop.png` | Filtering by outcome isolates denied events. |
| `18-login-throttled-desktop.png` | After 20 failed sign-ins from one address the 21st gets "Too many failed attempts" (HTTP 429) before any hashing, and the message names no account (finding F04). |
| `19-auditor-throttle-event-desktop.png` | The throttle is visible to the auditor as one `auth.throttle` event, not one event per refused request. |
| `20-mfa-challenge-desktop.png` | After the password an auditor is asked for a 6-digit code and is not signed in yet. |
| `21-mfa-enrollment-desktop.png` | An officer without a second factor is made to set one up (setup key and address for an authenticator app). |
| `22-mfa-recovery-codes-desktop.png` | Eight single-use recovery codes are shown once, after the first code is verified. |
| `23-officer-extend-deadline-desktop.png` | An officer can extend the deadline of an open review. |
| `24-auditor-export-csv-desktop.png` | The audit timeline offers a CSV export of the filtered events. |
| `17-auditor-timeline-grayscale-desktop.png` | Denied events remain distinguishable without colour (bold row, edge bar, filled square badge). |

Note: the screenshots are taken on pristine demo data (before the simulated incident), so proposal #1 still appears as
"Under review". Refresh them with `scripts/db-apply.sh grants --reset && scripts/seed.sh grants && node scripts/screenshots.mjs`
(last run 17 November 2026: 30 screenshots, 23 checks, 0 failed).
