# University Research Grant Management System

**Database Security Engineering — Final Project Report**

| | |
| --- | --- |
| Project | Secure grant-management platform (PHP 8.5 · PostgreSQL 18 · Apache 2.4 · Docker) |
| Report date | 17 November 2026 |
| Evidence date | Penetration campaign of 11 November 2026; **remediation release, retest and drills of 17 November 2026**; screenshots retaken 15 November 2026 |
| Data | All people, e-mail addresses and proposals are fictional |
| Formal report | [Database_Security_Assessment_Report.pdf](Database_Security_Assessment_Report.pdf): the same work in the 22-section structure required by the assignment |
| AI assistance | The interface redesign and parts of the code and documentation were produced with AI assistance (Claude). The author reviewed the result. |

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Project objectives and requirement coverage](#2-project-objectives-and-requirement-coverage)
3. [System description and user roles](#3-system-description-and-user-roles)
4. [Architecture](#4-architecture)
5. [Database design](#5-database-design)
6. [Security design](#6-security-design)
7. [Application walkthrough (screenshots)](#7-application-walkthrough-screenshots)
8. [Verification: automated tests](#8-verification-automated-tests)
9. [Penetration testing](#9-penetration-testing)
10. [SQL injection: controlled before/after demonstration](#10-sql-injection-controlled-beforeafter-demonstration)
11. [Auditing and incident investigation](#11-auditing-and-incident-investigation)
12. [Backup and recovery](#12-backup-and-recovery)
13. [Hardening](#13-hardening)
14. [Final assessment, limitations and recommendations](#14-final-assessment-limitations-and-recommendations)
15. [Reproducing the work](#15-reproducing-the-work)
16. [References](#16-references)

---

## 1. Executive summary

The system supports the full life cycle of a university research grant. The research office publishes a **grant call**; a **researcher** drafts and submits a proposal; an assigned **reviewer** scores it and writes confidential comments; a **grants officer** approves (with an amount) or declines it, and the call budget is reduced atomically; an **auditor** can later reconstruct who did what, when, and with what result.

The project is a *database security engineering* exercise, so the emphasis is on **defence in depth around the data**:

* authorization is enforced twice — in PHP and again inside PostgreSQL with Row-Level Security (RLS), column grants, constraints and triggers;
* the web application connects with a restricted, non-owner database account; the database role is derived inside the database from a transaction-local user id and cannot be asserted by PHP;
* reviewer comments are encrypted with libsodium before they reach the database;
* every sensitive action, including **denied** ones, is written to an audit log on a second connection so it survives a rolled-back business transaction;
* backups are encrypted with OpenPGP public-key encryption and a recovery drill proves they can be restored.

**Headline results**

| Measure | Result |
| --- | --- |
| Integration tests (real PostgreSQL) | **89 tests, 968 assertions, 0 failed**, plus **13 owner-level guard checks** (`tests/owner_guards.sql`) |
| Interface checks (responsive, keyboard focus, long titles, colour-independence, login throttle, two-step sign-in, deadlines, export) | **28 checks, 0 failed**; 33 screenshots |
| Penetration campaign of 11 Nov (isolated lab) | **115 attacks resisted**; 5 findings (F01-F05) + 3 conditional observations (O01-O03) |
| **Remediation and retest of 17 Nov (F01-F05, O02, O03)** | **F01-F05 all remediated and retested** with the same probes (`docs/evidence/pentest-after/`); black-box rerun on the live lab: **122 resisted, 0 findings** |
| Concurrent award test | Two simultaneous awards of 7,000 against a 10,000 budget: exactly one succeeds, 3,000.00 remains (now through the single database function `record_decision()`) |
| Controlled SQL injection lab | The unsafe query leaks **7 accounts**; hashes, audit trail, other users' data and comments stay out of reach; the same 9 payloads return 0 rows after the fix |
| Field-key lifecycle | Key ids, rotation without a flag day, retirement refused while rows depend on the key; backup of the key apart from the dump |
| Backup → loss → restore drill | Restored in **0.8 s**; 8 verification checks (28 assertions) pass, including identity binding, second factor and outbox; field-key backup identical to the live keyring |
| Clean-room install | fresh copy, no secrets: setup + all tests pass in under a minute |
| Continuous integration | every push and pull request: syntax, tests, labs, pentest retest, recovery drill, image build with a patch-status report (`.github/workflows/ci.yml`) |
| Incidents investigated | (1) unauthorized read followed by a legitimate award; (2) **stolen service credential**: before the identity binding the attacker could award and forge an audit event; now they obtain **only the account list**, and the PostgreSQL log reconstructs every attempt |

Residual risks are stated honestly in [section 14](#14-final-assessment-limitations-and-recommendations): observation **O01** (the login helper returns one password hash per e-mail address to the web account) and the compromise of the **whole web process**, which holds the actor key, remain accepted and documented. **O02 (self-asserted identity) and O03 (forged audit events) are closed for the stolen-database-credential threat.**

---

## 2. Project objectives and requirement coverage

The course assignment defines sixteen scenario requirements. The table maps each to the implementation, a repeatable check, and the current status.

| # | Objective | Where it is implemented | Repeatable check | Status |
| --- | --- | --- | --- | --- |
| 1 | Database design | `database/02_schema.sql`, [ERD](ERD.md) | `scripts/test.sh FLOW` | Done |
| 2 | Functional application | `public/`, `src/`, `templates/` | `scripts/test.sh FLOW` | Done |
| 3 | Identification of sensitive information | Section 6.1 | Ownership table review | Done |
| 4 | Threats and vulnerabilities | Section 6.2, section 9 | Threats mapped to routes and controls | Done |
| 5 | Authentication and authorization | `src/Auth`, `src/Http/Kernel.php` | `scripts/test.sh AUTH` | Done; F02-F04 remediated and retested |
| 6 | Role-based access control | `Policy.php`, `01_roles.sql`, `03_rls.sql` | `scripts/test.sh RBAC` | Done |
| 7 | Least privilege | `database/04_grants.sql`, `database/05_remediation.sql` | `scripts/evidence.sh` | Done (F01: the runtime account can no longer move money in pieces); service-compromise limits documented |
| 8 | Controlled vulnerability demonstration | Section 10 | `scripts/sqli-demo.sh` (impact shown, then same payloads replayed) | Done (lab only) |
| 9 | Remediation | `GrantQueries.php`, `Database.php` (bound parameters) | Same exploit replayed | Done |
| 10 | Sensitive data protection | `FieldCipher.php` (keyring), TLS, `backup.sh`, `rotate-field-key.sh`, `backup-key.sh` | `scripts/test.sh DATA`, `scripts/key-rotation-drill.sh` | Done |
| 11 | Logging and auditing | `src/Audit`, `audit_events` | `scripts/test.sh AUDIT` | Done |
| 12 | Backup and recovery | `backup.sh`, `restore.sh`, `restore-field-key.sh` | `scripts/recovery-drill.sh` | Done |
| 13 | Hardening | `docker/`, `compose.yaml` | `scripts/evidence.sh` | Done; package updates are a rebuild away |
| 14 | Final security assessment | Section 14 | Regression + pentest retest | Done: retest of F01-F05 on 17 Nov |
| 15 | Simulated security incident | `scripts/incident-demo.sh`, `scripts/incident-privileged.sh` | Two incidents, evidence files in `docs/evidence/` | Done |
| 16 | Professional report | This document | — | Done |

### 2.1 Where the assignment's ten phases and nine final-assessment questions are answered

| Assignment item | Section here | Evidence |
| --- | --- | --- |
| Phase 1 design and analysis (ERD, schema, classification, CIA, threat model) | 5, 6.1-6.3 | `ERD.md`, `database/02_schema.sql` |
| Phase 2 users, RBAC, least privilege, access-control matrix | 6.5 | `database/01_roles.sql`, `04_grants.sql`, `evidence/privileges.txt` |
| Phase 3 authentication (hashing, sessions, failed attempts) | 6.4 | `scripts/test.sh AUTH`, `evidence/pentest-after/auth-retest.json` |
| Phase 4-5 vulnerability and SQL injection prevention | 10 | `evidence/sqli-demo.txt` |
| Phase 6 sensitive data protection and key management | 6.6, 12 | `evidence/key-rotation.txt`, `evidence/backup-key-custody.txt` |
| Phase 7 auditing and monitoring | 11 | `evidence/incident-timeline.txt`, `evidence/incident-privileged.txt` |
| Phase 8 backup and recovery | 12 | `evidence/recovery-drill.txt` |
| Phase 9 hardening (before/after) | 13 | `evidence/hardening.txt` |
| Phase 10 incident investigation | 11 | two incidents with timelines |
| Final assessment (authentication, authorization, least privilege, SQLi, data protection, auditing, recovery, hardening, investigation) | 14 | all of the above |

---

## 3. System description and user roles

| Role | Can do | Cannot do |
| --- | --- | --- |
| **Researcher** | See open calls; create, edit, submit and delete **own** drafts; view own proposal status and final decision | See other researchers' proposals, any reviews, or audit data |
| **Reviewer** | See **assigned** proposals only; save a draft review; submit one final review (score 1–10) | See unassigned proposals, change a final review, see decisions |
| **Grants officer** | Manage calls; see submitted proposals; assign reviewers; record the decision and award | Edit proposals; read review comments of proposals they did not assign |
| **Auditor** | Read-only audit timeline with filters | Read proposal text or review comments; write anything |

**Business rules enforced**

* A submitted proposal is immutable; draft and submit are separate actions.
* A final review cannot be changed.
* A proposal needs at least one completed review before a decision.
* An award cannot exceed the call's remaining budget; the budget only ever decreases.
* A decision is final: at most one per proposal.

**Workflow**

```mermaid
flowchart LR
    A[Officer publishes call] --> B[Researcher saves draft]
    B --> C[Researcher submits]
    C --> D[Officer assigns reviewer]
    D --> E[Reviewer submits final review]
    E --> F{Officer decision}
    F -->|Approve + amount| G[Budget reduced atomically]
    F -->|Decline| H[Closed, no money moves]
    G --> I[Auditor reconstructs the trail]
    H --> I
```

---

## 4. Architecture

### 4.1 Runtime view

```mermaid
flowchart TB
    U[Browser] -- HTTPS 8443 --> W
    subgraph Docker host
      subgraph W[web container: Apache 2.4 + PHP 8.5]
        K[Kernel: headers → session → route → CSRF → permission]
        C[Controllers]
        D[GrantWorkflow / GrantQueries]
        E[FieldCipher libsodium]
        L[AuditLog second connection]
      end
      subgraph P[db container: PostgreSQL 18]
        R[RLS policies + column grants + triggers]
        T[(grants database)]
      end
    end
    K --> C --> D --> E
    D -- TLS verify-full as grants_app --> R
    L -- separate connection --> R
    R --> T
    H[Host: postgres peer socket for migrations, grants_backup for pg_dump] -.-> P
```

### 4.2 Request pipeline

Every request passes the same ordered checks in `src/Http/Kernel.php`:

`security headers → session → route match → CSRF (POST) → login → role permission → controller → database (RLS)`

A request that fails any step never reaches the next one. The router is an explicit table of 23 routes, each bound to a named permission (e.g. `decision.record`, `audit.read`).

```mermaid
flowchart LR
    R[HTTPS request] --> H[Security headers]
    H --> S[Session + idle/absolute expiry]
    S --> M[Route match, ids are digits only]
    M --> C{POST?}
    C -- yes --> T[CSRF token check]
    C -- no --> L
    T --> L[Signed in?]
    L --> P[Role permission]
    P --> K[Controller]
    K --> W[GrantWorkflow / GrantQueries]
    W --> D[(PostgreSQL: RLS, column grants, triggers)]
    T -. 400 + audit .-> X[Refused]
    L -. redirect .-> X
    P -. 403 + audit .-> X
```

**Defence in depth.** A write passes five independent barriers; any one of them stops a bypass of the others.

```mermaid
flowchart TB
    A[PHP permission per route] --> B[PHP ownership and state checks in the transaction]
    B --> C[RLS policies: who may see or change which row]
    C --> D[Column grants and no direct write on money tables]
    D --> E[Guard triggers and constraints: states, budget, one decision]
    E --> F[Append-only audit, written in the same transaction]
```

### 4.3 Code organisation

| Directory | Responsibility |
| --- | --- |
| `public/` | The **only** directory Apache serves (front controller, CSS, JS, icons) |
| `src/Http` | Kernel, router, response, controllers, view helpers |
| `src/Auth` | Authenticator (Argon2id), session, CSRF, role policy |
| `src/Grants` | Workflow, parameterised queries, money arithmetic, validation |
| `src/Security` | `FieldCipher`: XChaCha20-Poly1305 for review comments, keyring with key ids |
| `src/Audit` | Writer (independent connection) and read-only reader |
| `src/Database` | PDO wrapper: TLS, prepared statements, transaction-local actor |
| `database/` | Roles, schema, RLS, remediation release (`05_remediation.sql`), grants — numbered, applied in the order 00, 02, 03, 05, 04 |
| `scripts/` | Setup, tests, backup/restore, drills, evidence, screenshots, pentest |
| `docker/`, `compose.yaml` | Hardened images and private network |

### 4.4 Key design decisions

| Decision | Reason |
| --- | --- |
| One web root (`public/`) | `/config/config.php`, `/secrets/web.env`, `/.git/config` all return 404 (verified) |
| Web container has **no owner or superuser** credentials | A PHP compromise yields only `grants_app` / `grants_auditor`, no DDL |
| Actor set via transaction-local `app.user_id`; role derived **in the database** | A reused connection cannot leak identity; PHP cannot assert a role |
| Denied events written on a **second connection** | They must survive the business transaction's rollback |
| Comments encrypted in PHP, not `pgcrypto` | The key never reaches SQL, logs or the database host |
| Backup = `pg_dump -Fc` piped to OpenPGP public-key encryption | The backup host holds no decryption key; plaintext never touches disk |
| The award is one `SECURITY DEFINER` function, `record_decision()` | The runtime account cannot insert a decision or edit a balance on its own, so no caller can commit part of an award (finding F01) |
| Login failures counted per (account, source address) in the database | A stranger cannot lock the real owner out (F02); one address cannot guess without limit (F04) |
| Own test runner, native CSS, one icon set | No Composer dependency; works offline; smallest thing to explain |

**The award, step by step** (finding F01 remediated: one database function, so no caller can commit part of it).

```mermaid
sequenceDiagram
    participant B as Officer's browser
    participant K as Kernel (CSRF, role)
    participant W as GrantWorkflow
    participant F as record_decision() in PostgreSQL
    B->>K: POST /officer/proposals/{id}/decision
    K->>W: recordDecision(actor, outcome, amount)
    W->>F: BEGIN; set app.user_id; SELECT record_decision(...)
    F->>F: role = officer? lock the call row (FOR NO KEY UPDATE)
    F->>F: re-read proposal: not decided, under review, review done
    F->>F: amount <= requested and <= remaining balance
    F->>F: INSERT decision, lower balance, set status, INSERT audit event
    F-->>W: decision id, remaining balance
    W-->>B: COMMIT, 303 redirect
    Note over F,W: any refusal raises GR001, the whole transaction rolls back,<br/>and the denial is written on the second connection
```

---

## 5. Database design

```mermaid
erDiagram
    users ||--o{ grant_calls  : "creates (officer)"
    users ||--o{ proposals    : "owns (researcher)"
    users ||--o{ reviews      : "reviews (reviewer)"
    users ||--o{ decisions    : "decides (officer)"
    users |o--o{ audit_events : "acts"
    grant_calls ||--o{ proposals : "receives"
    proposals   ||--o{ reviews   : "is evaluated by"
    proposals   ||--o| decisions : "ends with at most one"
```

The full column-level diagram is in [`ERD.md`](ERD.md). Integrity is enforced by the database, not only by PHP:

* `numeric(14,2)` money, `remaining_budget` constrained to `0 … total_budget`, only ever decreasing;
* a unique constraint gives **at most one decision** per proposal and one assignment per reviewer;
* status columns use `CHECK` constraints; triggers block edits to submitted proposals and final reviews;
* the award is one database function that locks the call row, so concurrent decisions serialise (proved by test `AWARD`), and the same function writes the decision, the balance, the status and the audit event together.

---

## 6. Security design

### 6.1 Sensitive data classification and CIA analysis

| Asset | Owner | Confidentiality | Integrity | Availability | Protection |
| --- | --- | --- | --- | --- | --- |
| Password hashes | Account holder | High | High | Medium: nobody can sign in without them | Argon2id; not readable by the runtime role except through one helper (O01) |
| Review comments | Reviewer | High | High | Medium | XChaCha20-Poly1305 in PHP with a keyring (key ids, rotation); key outside the database; backed up apart from the dump |
| Proposal content | Researcher | Medium/High | High | High before a deadline | RLS: owner, assigned reviewer, officer only; immutable once submitted; backups |
| Funding amounts and budgets | Grants office | Medium | **Critical** | High | Numeric constraints, row lock, single `record_decision()` function, no direct write privilege |
| Audit events | Internal audit | Medium | **Critical** | Medium | Append-only (trigger + grants); auditor read-only; no proposal text stored |
| Login-failure records | Security | Low | Medium | **High**: a wrong design lets an attacker lock people out | Only reachable through three `SECURITY DEFINER` functions; per-address and per-pair counters |
| Backups | System administrator | High | High | **High**: recovery time measured 0.7 s | Public-key encrypted; private key under separate custody; ignored by Git |
| TLS keys, DB passwords, field keyring | System administrator | Critical | Critical | High | `secrets/` (mode 600, never committed); keyring backed up separately |

Availability requirements and how they are met: the application must stay usable during a submission deadline (login is throttled per source address, not by locking accounts); the database must be recoverable (measured restore 0.7 s, verified); the audit trail must not grow without bound under attack (threshold events are written once, throttled requests write nothing).

### 6.2 Threat actors and attack surfaces

| Threat actor | Capability | Main target |
| --- | --- | --- |
| External anonymous visitor | Reaches the HTTPS login form only | Credentials, availability of the login |
| Malicious or curious researcher | Valid account, can craft requests | Other researchers' proposals, reviewer comments, budgets |
| Reviewer | Valid account, sees assigned work | Unassigned proposals, other reviewers' scores |
| Rogue grants officer | Can decide and assign | Awarding without review, editing history |
| Holder of a stolen service credential | Runs SQL as `grants_app` inside the network | Money, identities, audit trail (incident 2) |
| Insider with Docker or host access | Reads files and logs | Secrets, backups, keys |
| Someone who finds a backup file | Offline | Everything in the dump |

| Attack surface | Exposure |
| --- | --- |
| HTTPS application (routes, forms, query parameters) | Host loopback port 8443 only |
| Login form | Public to the network that can reach it; throttled |
| Search and filter parameters | Parameterised queries only |
| PostgreSQL port | Private Docker network; `pg_hba.conf` allows `grants_app` and `grants_auditor` over TLS from that network only |
| Backup files and key backup | Local `backups/`; encrypted; ignored by Git |
| `secrets/` files | Mode 600; outside the web root; never committed |
| Containers and the published image | Least-functionality Apache; image contains no code or secrets |

### 6.3 Threat model

| Threat (STRIDE) | Control | Evidence |
| --- | --- | --- |
| Spoofing: session fixation / theft | ID regenerated at login; Secure, HttpOnly, SameSite, `__Host-` cookie; idle and absolute expiry | Test `AUTH`; pentest SESSION |
| Spoofing: guessing or enumerating accounts | Argon2id; equal hashing work on every failed path; uniform message; per-address throttle | Tests `AUTH` (F03, F04); `pentest-after/auth-retest.json` |
| Tampering: SQL injection | Prepared statements only; restricted account; column grants | Section 10, `sqli-demo.txt` |
| Tampering: partial or double award | One database function under a row lock; no direct privilege | Tests `AWARD`; `pentest-after/deep-db.json` (DB04) |
| Tampering: cross-site request forgery | Per-session token on every POST; SameSite; POST-only logout | Pentest CSRF |
| Repudiation: denied or forged history | Append-only audit; denials on a second connection; function writes its own audit event | Tests `AUDIT`; incident 2 |
| Information disclosure: IDOR, reading review comments | PHP ownership check **and** RLS; encrypted comments | Tests `RLS`, `DATA`; pentest IDOR |
| Denial of service: lockout abuse | Failures counted per (account, address), no account-wide lock | Test `AUTH` (F02) |
| Elevation of privilege | Permission per route; role derived in the database; runtime account has no owner rights | Tests `RBAC`, `RLS` |
| Loss of data | Encrypted backups, separate key backup, recovery drill | Section 12 |

### 6.4 Authentication

* Individual accounts; passwords hashed with **Argon2id**; generic failure message for every failure; session ID regenerated at login; idle (20 min) and absolute (8 h) expiry; logout is POST-only with CSRF.
* **Failed attempts (remediated findings F02-F04).** Failures are counted in the database **per (account, source address)** and **per source address**: five failures lock that pair for the 15-minute window; 20 failures from one address within 10 minutes make that address answer `429 Too Many Requests` with `Retry-After`, **before any password hashing**. Every other failed path (unknown account, disabled, locked pair, wrong password) pays exactly one Argon2id verification, so timing does not reveal account state (medians 139.9 / 143.1 / 142.1 ms for unknown / unlocked / locked, previously 251.8 / 254.4 / 28.0 ms). `users.locked_until` remains as an *administrative* lock for incident response.
```mermaid
flowchart TD
    A[POST /login] --> B{Source address throttled?<br/>20 failures / 10 min}
    B -- yes --> Z[429 + Retry-After<br/>no hashing]
    B -- no --> C[Look up credentials by e-mail]
    C --> D{Unknown, disabled,<br/>administratively locked,<br/>or pair locked?}
    D -- yes --> E[Argon2id verify of a DUMMY hash<br/>same cost as a real check]
    E --> F[Record failure, audit, generic 401]
    D -- no --> G{password_verify with the real hash}
    G -- wrong --> F
    G -- correct --> H[Clear the pair's failures, new session ID, audit success]
```

* **Trade-offs, stated openly.** People who share a network address (a university NAT) share the per-address limit; the threshold is a configuration value. A distributed attack from many addresses against one account is slowed, not stopped: the application raises an `auth.suspicious_volume` audit alert at 20 failures per hour, and multi-factor authentication for officers and auditors is the recommended next control.

**Plaintext, encryption, hashing and secure password hashing: what is the difference?**

| Method | Reversible? | What the database holds | Why it is (not) acceptable for passwords |
| --- | --- | --- | --- |
| Plaintext storage | Not applicable | The password itself | Any leak (backup, SQL injection, DBA) exposes every password; reused passwords fall elsewhere too |
| Encryption (e.g. AES) | **Yes**, with the key | Ciphertext | Whoever gets the key (the application must hold it) recovers every password; encryption suits data that must be read back, such as review comments |
| Hashing (e.g. SHA-256) | No | A fast digest | One-way, but built to be fast: billions of guesses per second, precomputed tables, identical passwords give identical digests |
| **Secure password hashing (Argon2id)** | No | `$argon2id$...` with salt and cost parameters | Per-password random salt; deliberately slow and **memory-hard** (64 MiB, 4 passes here) so GPUs gain little; cost can be raised over time; verification with `password_verify` |

Review comments need the opposite property: they must be read back by authorised people, so they are **encrypted** (section 6.6), never hashed.

### 6.5 Authorization, least privilege and the access-control matrix

Two independent layers: **PHP** (each route names a permission; `Policy.php` maps role to permissions) and **PostgreSQL** (`grants_runtime` is subject to RLS policies; column-level `GRANT`s limit what can be written; the owner role is `NOLOGIN`). The tests attack the second layer directly with raw SQL under the restricted account, so a PHP bug cannot silently remove protection.

**Access-control matrix, application layer** (`src/Auth/Policy.php`; ✔ = permitted)

| Permission | Researcher | Reviewer | Officer | Auditor |
| --- | :---: | :---: | :---: | :---: |
| `call.read` (open calls) | ✔ | | ✔ | |
| `call.manage` (create, edit, close calls) | | | ✔ | |
| `proposal.read_own` | ✔ | | | |
| `proposal.write_own_draft` (create, edit, delete drafts) | ✔ | | | |
| `proposal.submit` | ✔ | | | |
| `proposal.read_submitted` (all submitted proposals) | | | ✔ | |
| `review.assign` | | | ✔ | |
| `review.read_assigned` | | ✔ | | |
| `review.write_assigned` (save, submit own review) | | ✔ | | |
| `decision.record` (approve with amount, decline) | | | ✔ | |
| `audit.read` (timeline) | | | | ✔ |

**Access-control matrix, database layer** (`database/04_grants.sql`, `03_rls.sql`; evidence `evidence/privileges.txt`)

| Object | `grants_runtime` (web service, via `grants_app`) | `grants_audit_read` (via `grants_auditor`) | `grants_backup_read` (via `grants_backup`) | `grants_owner` |
| --- | --- | --- | --- | --- |
| `users` | SELECT of 9 columns (no `password_hash`); UPDATE `last_login_at` only | none | SELECT | all (NOLOGIN) |
| `grant_calls` | SELECT, INSERT; UPDATE of title, description, closes_at, status; **no** budget write; RLS: officers manage, workflow roles read | none | SELECT | all |
| `proposals` | SELECT, INSERT, DELETE; UPDATE of title, abstract, requested_amount, status; RLS by owner / assigned reviewer / officer | none | SELECT | all |
| `reviews` | SELECT, INSERT; UPDATE of score, comments_enc, status; **no DELETE**; RLS: reviewer own rows, officer all | none | SELECT | all |
| `decisions` | **SELECT only** (rows appear only through `record_decision()`); RLS: officer all, researcher own | none | SELECT | all |
| `audit_events` | **INSERT only** | none | SELECT | all, but a trigger forbids UPDATE, DELETE, TRUNCATE |
| `audit_timeline` (view) | none | **SELECT** | SELECT | all |
| `login_failures` | none (three `SECURITY DEFINER` functions only) | none | SELECT | all |
| Functions | EXECUTE on `current_actor_*`, `is_assigned_reviewer`, `owns_proposal`, `auth_*`, `record_decision` | none | none | all |

| Account | Attributes | Connects |
| --- | --- | --- |
| `grants_owner` | NOLOGIN, owns every object | Never; used through `SET ROLE` by an administrator for migrations |
| `grants_runtime`, `grants_audit_read`, `grants_backup_read` | NOLOGIN privilege groups | Never; privileges are granted to groups, not to accounts |
| `grants_app` | member of `grants_runtime`; 30 connections; statement timeout 15 s | TLS + SCRAM from the Docker network |
| `grants_auditor` | member of `grants_audit_read`; sessions read-only by default | TLS + SCRAM from the Docker network |
| `grants_backup` | member of `grants_backup_read`; BYPASSRLS (needed by `pg_dump`); 2 connections | Local socket only |

The commands the assignment names are all in the repository and run by `scripts/evidence.sh`: `CREATE ROLE` and role membership (`database/01_roles.sql`), `GRANT` / `REVOKE` (`04_grants.sql`, with a rolled-back `REVOKE` demonstration), `\du` and `\dp` as the `SHOW GRANTS` equivalent, and privilege testing under the real accounts (`evidence/privileges.txt`, tests `RBAC`).

### 6.5b Release 2 controls: identity binding, audit separation, two-step sign-in, deadlines, export, notifications

| Control | What it does | Where | Verified by |
| --- | --- | --- | --- |
| **Actor token (O02)** | The web process signs `v1.<user>.<expiry>.<nonce>.<HMAC-SHA256>` with `secrets/actor.key`; PostgreSQL verifies it (`actor_verify_token`, HMAC written in SQL and checked against RFC 4231 vectors). No valid token, no identity, and every policy answers "no rows". The old `app.user_id` is ignored. | `database/06_identity_and_audit.sql`, `src/Security/ActorToken.php` | tests `IDENT`, `owner_guards.sql`, retest DB03 |
| **Audit separation (O03)** | The web account has **no privilege** on `audit_events`. `audit_append()` accepts an event naming an actor only with that actor's token, and looks the role up itself. Events with no authenticated actor are written by a **different account** (`grants_audit_write`, no table privilege) and flagged `actor_verified = false`; the auditor sees "(unverified)". | `database/06_...`, `src/Audit/AuditLog.php` | tests `IDENT`, retest DB05 |
| **Two-step sign-in** | TOTP (RFC 6238) required for officers and auditors: password, then a 6-digit code. First sign-in enrols an authenticator app and shows 8 single-use recovery codes once. The secret is stored **encrypted** (field keyring); a code is accepted once (last step in the database); wrong codes count toward the lock and throttle; 5 wrong codes abandon the pending sign-in; every `mfa_*` function needs the user's token. Operator reset: `scripts/mfa-reset.sh` (audited). | `database/08_mfa.sql`, `src/Auth/Totp.php`, `Authenticator.php` | tests `MFA` (RFC 6238 vectors, enrolment, recovery code once, replay, stolen DB password) |
| **Review deadlines** | A trigger refuses saving or submitting a review after `due_at`; only an officer can move a deadline, only forwards, and nothing else changes in the same statement; new assignments cannot start in the past. Overdue is visible to both sides; the officer extends from the proposal page. | `database/07_review_deadlines.sql` (policy `reviews_officer_extend`, 18 policies now) | tests `DEADLINE` |
| **CSV export** | `GET /audit/export.csv`, auditors only, same filters as the screen, at most 5,000 rows, spreadsheet formulas neutralised, server-chosen file name, itself audited (`audit.export`), never any proposal text. | `AuditController::export` | tests `EXPORT` |
| **E-mail notifications** | Queued in the **same transaction** as the change through `notify_enqueue()`: a user can only queue a message about their own action, the **database** chooses the recipient and renders a fixed text with no title, amount, score or outcome, and each message is unique per (kind, subject, recipient). A separate account `grants_notifier` (service `notifier`) delivers every minute: `.eml` files by default, or SMTP with verified TLS; header injection refused; retries up to 5; reminders 48 hours before a deadline and once overdue. | `database/09_notifications.sql`, `src/Mail/` | tests `MAIL` (incl. a fake SMTP server) |
| **CI** | Syntax, the full test suite, the SQL-injection lab, the black-box pentest, the retest of F01-F05/O02/O03, incident 2, the recovery drill and an image build with a patch-status report on every push and pull request; Dependabot for actions and the base image. | `.github/` | the workflow itself |

```mermaid
flowchart LR
    W[Web process<br/>holds secrets/actor.key] -- "signed actor token<br/>(120 s, per transaction)" --> D[(PostgreSQL<br/>verifies the HMAC itself)]
    X[Attacker with only<br/>the grants_app password] -. "no key, no valid token" .-> D
    D --> R[RLS policies see an identity<br/>only for a valid token]
    W -- "audit_append(token)" --> A[audit_events]
    AW[grants_audit_write<br/>separate account] -- "unauthenticated events only<br/>flagged unverified" --> A
    N[grants_notifier<br/>separate service] -- "reads outbox, sends .eml/SMTP" --> O[(notifications outbox)]
    W -- "notify_enqueue(token)<br/>same transaction" --> O
```

### 6.5c Release 3 controls: identity service, security keys, pgaudit and log shipping, manual-test script

**Identity service (closes O01).** The web process is split in two. The *front end* serves pages and runs the business logic. The *identity service* (`src/Identity/`, an HTTP wrapper around the unchanged `Authenticator`, on an internal network that is never published) is the only process that holds the actor key, the audit-writer credential and the database account that can read password hashes. Requests are signed (HMAC-SHA256 over a timestamp and the body, 30-second skew, method whitelist). Sessions are opaque 64-hex handles; the database stores only `sha256(handle)` and an encrypted, row-bound payload (`identity_sessions`). A front end can obtain an actor token only for the user of a live session whose handle it holds, and a verified audit event needs a live session of that very user. Evidence: `docs/evidence/isolation.txt` (37 checks: environment variables, files, and the web account refused `auth_find_credentials` and `password_hash` with `42501`), tests `SPLIT` (6), and incident 3 (`docs/evidence/incident-frontend.txt`).

**Security keys (WebAuthn).** Officers and auditors can register FIDO2 keys on the *Security* page and use one instead of a TOTP code. The server side is written in PHP (`src/Auth/WebAuthn.php`, `Cbor.php`: strict CBOR subset, attestation "none", ES256 and RS256, signatures verified with OpenSSL). Checked on every ceremony: type, single-use challenge (two minutes, kept server-side), origin, relying-party id hash, user presence and user verification; for sign-in also the signature and a signature counter that must move forward (a cloned key is refused and audited as `auth.webauthn_clone_suspected`). Only the public key is stored (`webauthn_credentials`, reachable through functions that need the owner's actor token). The credential is bound to the site's origin, so a look-alike page cannot capture it: this is what TOTP cannot do. Tests `WEBAUTHN` (5, 52 assertions, with a software authenticator, including a response signed for a look-alike origin), and screenshots 31 to 33 made with Chrome's virtual authenticator. WebAuthn is a tool beyond the list the instructor approved; it is implemented with PHP and OpenSSL only, no library.

**pgaudit and log shipping.** The database image adds `pgaudit` (flags on the server command line, so they cannot drift): DDL, role changes and writes are logged for everybody, and **everything** (reads included) for the superuser and the schema owner, the two accounts that bypass the application audit trail. PostgreSQL writes a JSON log; a `logship` container with no network, no secrets, a read-only root file system and read-only views of the sources copies the database log and the application error log into `archive.ndjson` on a volume nothing else can write. Every record carries the SHA-256 of the previous one: an edited, removed or swapped record is found by `logship.php verify` (checked in `docs/evidence/logship.txt`, 20 checks). A cut-off tail is invisible to the chain alone, so the newest `seq:hash` is anchored outside the shipper (`docs/evidence/logship-anchor.txt`); `verify <anchor>` then detects it. In production the shipper runs on another host. Incident 2 now reads the PostgreSQL log from the shipped archive. pgaudit is a tool beyond the instructor-approved list.

**Database audit.** `scripts/check-db-security.sh` queries the PostgreSQL catalogs directly (29 checks, `docs/evidence/db-security.txt`): a single superuser reachable only by local peer authentication; SCRAM-SHA-256 verifiers only; `pg_hba.conf` with `hostssl` rules and a final reject; no privilege or function execution for PUBLIC; one object owner that cannot log in; the web account without access to audit, identity, credential or key tables and without `password_hash`; row-level security on the business tables and deny-by-default RLS on the tables reached through functions only; every `SECURITY DEFINER` function with a pinned `search_path`; primary keys everywhere, no floating-point money; data checksums, TLS 1.2+, connection logging and pgaudit. The audit led to one small change (deny-by-default RLS on `actor_key`, `login_failures`, `mfa_recovery_codes`, `webauthn_credentials`; `FORCE` is not used because the definer functions run as the owner) and exposed a real defect on 17 November: key rotation re-encrypted review comments only, so retiring a key left TOTP secrets unreadable. Rotation now covers both and `retire` is refused while any value still uses the key.

**Manual testing.** `scripts/manual-test.sh` starts the stack if needed, prints every demo account with its password and the current two-step code, opens the browser and lists a checklist of scenarios (it can rebuild the demo data with `--reset`, show live codes with `codes`, and stop the stack).

### 6.6 Sensitive data protection and key management

| Data | Mechanism | At rest / in transit | Why it needs this |
| --- | --- | --- | --- |
| Passwords | Argon2id hash | At rest | Must never be recoverable |
| Review comments | XChaCha20-Poly1305, key in PHP, row context authenticated | At rest in the table and in every backup | Confidential judgements; the database host, a DBA and a stolen dump must not read them |
| All traffic | TLS 1.2+ browser to Apache; TLS `verify-full` Apache to PostgreSQL | In transit | Credentials and personal data |
| Backups | OpenPGP public-key encryption | At rest | The backup host needs no decryption key |

**Key management principles applied**

| Principle | How it is done |
| --- | --- |
| Separation of keys from data | The keyring `secrets/field.key` lives outside the database and the repository; the dump holds only ciphertext |
| Identify keys | Every value is `v2:<key id>:<payload>`; the header and the row context are authenticated, so a value cannot be relabelled or moved to another row |
| Rotation without downtime | `scripts/rotate-field-key.sh add` makes a new active key (first line); old keys remain for decryption; `reencrypt` rewrites all rows in one audited transaction (`admin.rotate_field_key`) |
| Safe retirement | `retire <id>` is refused while any row still uses the key (drill: k2 refused, then retired after re-encryption) |
| Backup of keys | `scripts/backup.sh` also writes `backups/<db>-<time>.fieldkey.gpg`, a separate file to be stored apart from the dump |
| Custody of the decryption capability | The backup **private** key can be passphrase-protected, exported, and removed from the host (`scripts/backup-key.sh`): the host can still encrypt backups with the public key but cannot read them; a restore happens on a clean workstation |
| Backward compatibility | Values written in the original `v1:` format remain readable |

```mermaid
flowchart LR
    A[add: new active key first line] --> B[old keys stay: decrypt only]
    B --> C[reencrypt: one audited transaction]
    C --> D{rows still on the old key?}
    D -- yes --> X[retire refused]
    D -- no --> E[retire old key]
    A --> K[backup.sh: keyring backed up as a separate file]
    E --> K
```

Evidence: `evidence/key-rotation.txt`, `evidence/backup-key-custody.txt`, tests `DATA`. Limitation: in this lab the keyring, the passphrase file and the private key still start on one host; in production they belong with different custodians (the scripts support this).

---

## 7. Application walkthrough (screenshots)

All screenshots below were captured from the running application (headless Chrome, 1280×800 desktop and 390×844 mobile) after the interface redesign.

### 7.1 Sign-in

![Login](evidence/screenshots/01-login-desktop.png)

Keyboard focus is always visible (WCAG-oriented focus ring):

![Login keyboard focus](evidence/screenshots/02-login-keyboard-focus-desktop.png)

### 7.2 Researcher

Open calls with deadline and budget, and the researcher's own proposals with a clear *next action*:

![Researcher inbox](evidence/screenshots/03-researcher-inbox-desktop.png)

Server-side validation with specific, accessible error messages:

![Validation](evidence/screenshots/05-researcher-form-validation-desktop.png)

**Allowed vs denied.** Opening another researcher's proposal by changing the URL returns "not found" (no information leak) and is recorded in the audit log:

![Denied access](evidence/screenshots/04-researcher-denied-other-proposal-desktop.png)

A final decision is visible to its owner:

![Decision view](evidence/screenshots/07-researcher-decision-view-desktop.png)

### 7.3 Reviewer

Only assigned work is listed:

![Reviewer list](evidence/screenshots/08-reviewer-list-desktop.png)

Workspace: draft saving, score 1–10, comments (stored encrypted):

![Reviewer workspace](evidence/screenshots/09-reviewer-workspace-desktop.png)

After final submission the review is locked:

![Locked review](evidence/screenshots/10-reviewer-final-review-locked-desktop.png)

### 7.4 Grants officer

Decision queue:

![Officer queue](evidence/screenshots/11-officer-queue-desktop.png)

The decision screen previews the resulting balance and rechecks the money on the server:

![Officer decision](evidence/screenshots/12-officer-decision-desktop.png)

When a decision is not yet possible, the interface explains why instead of silently hiding the control:

![Decision unavailable](evidence/screenshots/13-officer-decision-unavailable-explained-desktop.png)

Grant call management:

![Calls](evidence/screenshots/14-officer-calls-desktop.png)

### 7.5 Auditor

Read-only timeline: who, when, what, result. No proposal text or review comments appear. A denied event is distinguished by weight, edge marker and badge **shape**, not only colour:

![Audit timeline](evidence/screenshots/15-auditor-timeline-desktop.png)

Filtering by outcome *denied*:

![Denied filter](evidence/screenshots/16-auditor-filter-denied-desktop.png)

Grayscale rendering proves the distinction does not depend on colour:

![Grayscale](evidence/screenshots/17-auditor-timeline-grayscale-desktop.png)

### 7.6 Security controls visible in the interface (remediation release)

Twenty failed sign-ins from one address are all processed (HTTP 401); the 21st is refused with **429** *before any password hashing*, and the message names no account (finding F04). The operator clears the throttle, and the auditor then sees it as **one** `auth.throttle` event, not one event per refused request.

| Throttled sign-in (HTTP 429) | Auditor: one throttle event |
| --- | --- |
| ![](evidence/screenshots/18-login-throttled-desktop.png) | ![](evidence/screenshots/19-auditor-throttle-event-desktop.png) |

### 7.7 Responsive layout

On narrow screens the navigation becomes a top bar and tables become stacked records, with no horizontal scrolling (verified by automated checks).

| Researcher | Reviewer | Officer |
| --- | --- | --- |
| ![](evidence/screenshots/03-researcher-inbox-mobile.png) | ![](evidence/screenshots/09-reviewer-workspace-mobile.png) | ![](evidence/screenshots/12-officer-decision-mobile.png) |

---

## 8. Verification: automated tests

`scripts/test.sh` rebuilds a separate `grants_test` database and runs six suites against **real PostgreSQL** with the restricted account.

| Suite | Focus |
| --- | --- |
| `AUTH` | Login, per-address throttle and pair lock, equal timing, headers, session regeneration, CSRF, logout, expiry |
| `RBAC` | Each role reaches only its routes and actions |
| `RLS` | Raw SQL under `grants_runtime`: cross-user reads/writes are blocked |
| `FLOW` | Draft → submit → assign → review → decision; constraint violations; the database refuses illegal changes |
| `DATA` | Field encryption, key ids, rotation, legacy values, tampered headers |
| `AWARD` | Two OS processes race for the same budget; exactly one wins; no partial award; the function refuses non-officers |
| `AUDIT` | Denied events survive rollback; metadata contains no proposal text |

**Result: 78 tests, 851 assertions, 0 failed**, plus **13 owner-level checks** (`tests/owner_guards.sql`, run as the schema owner) that exercise the guard triggers and constraints that the restricted account can no longer even attempt to violate (`docs/evidence/test-results.txt`).

---

## 9. Penetration testing

### 9.1 Scope and rules of engagement

* **Target:** the group's own fictional application, run as a separate disposable Docker stack (own network, volume, keys and passwords) created by `scripts/pentest/prepare-lab.py`.
* **Network:** localhost ports 9180/9543 only; database checks from inside the isolated web container.
* **Excluded:** production university systems, third-party hosts, real accounts, mass password lists, denial-of-service, credential exfiltration.
* **Distinction kept explicit:** administrative access was used to *prepare* the lab; the *attack step* of the database tests used the restricted `grants_app` account.

### 9.2 Methodology

1. Read the source, route table, SQL grants and existing evidence.
2. Baseline HTTP script: authorization violations, injection, XSS, CSRF, session and exposure checks.
3. Deeper HTTP script: certificate verification, positive-control reads, bounded timing (60 requests) and throttling (30 attempts) probes.
4. Restricted SQL script against `grants_test`.
5. Fresh regression run; confirmation that the original demo data was untouched.

### 9.3 What was resisted

The baseline of 11 November recorded **115 resisted checks**, including:

| Area | Examples of attempts that failed |
| --- | --- |
| Authorization | Horizontal (other user's proposal), vertical (researcher → officer routes), reviewer reading unassigned work |
| Injection | SQL metacharacters in search and form fields |
| CSRF | POST without a token → 400; POST with another user's valid token → 400 |
| Session | Fixation, cookie flags (Secure/HttpOnly/SameSite), reuse after logout |
| Exposure | `/config/config.php`, `/secrets/web.env`, `/.git/config`, directory listings → 404 |
| Headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and HSTS present (Permissions-Policy was absent: F05, now added) |

### 9.4 Findings

| ID | Finding | Prerequisite | Impact | Status |
| --- | --- | --- | --- | --- |
| **F01** | Restricted SQL access could commit a decision row **without** the matching budget deduction and status change (a committed 1.00 award while the balance stayed 600,000.00 and the proposal stayed *under review*) | Runtime SQL access | Financial integrity | **Remediated 17 Nov**: `record_decision()`; runtime lost `INSERT` on `decisions` and `UPDATE(remaining_budget)`; original probe now `42501` |
| **F02** | Anonymous lockout abuse: anyone could lock a known account by failed attempts | Knowing an e-mail | Availability for one user | **Remediated**: failures counted per (account, address); no account-wide lock; the owner from another address is unaffected |
| **F03** | Locked-account timing gap: locked median **28.0 ms** vs unlocked **254.4 ms** (20 samples each) | Network access | Account-state disclosure | **Remediated**: locked / unlocked / unknown medians **142.1 / 143.1 / 139.9 ms** (ratio 1.02) |
| **F04** | No source-based throttling observed over 30 attempts | Network access | Weak brute-force friction | **Remediated**: 20 processed, then `429` + `Retry-After: 600`, even with the correct password |
| **F05** | Missing `Permissions-Policy` header | - | Defence in depth | **Remediated** (plus COOP and CORP headers) |

Original timing samples (before remediation):

![Authentication timing samples](evidence/pentest/timing.svg)

**Conditional observations (assume SQL/service compromise, not HTTP entry points). O02 and O03 were closed on 17 November (release 2); O01 stays open by design.**

| ID | Observation |
| --- | --- |
| O01 | The credential helper exposes password hashes to a compromised runtime account |
| O02 | ~~The actor identity is self-asserted per transaction~~ **Closed**: the database verifies an HMAC-signed actor token (`database/06_identity_and_audit.sql`); a database password alone yields no identity. Residual: whoever holds `secrets/actor.key` (the web process) |
| O03 | ~~A compromised service can insert fabricated audit rows~~ **Closed**: the web account has no privilege on `audit_events`; `audit_append()` needs a valid actor token, and unauthenticated events are written by a separate account and flagged *unverified* |

### 9.4.1 What was **not** proven

No cross-user HTTP disclosure, XSS execution, login bypass or successful SQL injection against the delivered application's tested routes was demonstrated. The controlled vulnerable query in section 10 is a teaching comparison, not a live endpoint. No denial-of-service, password cracking or third-party scanning was performed. The counts above do **not** certify the system as free of vulnerabilities.

### 9.5 Retest after remediation (17 November 2026)

The same probes were replayed after the fixes, each with a separate "after" file (nothing is marked passed without having been executed):

| Finding | Original probe | Result after remediation | Evidence |
| --- | --- | --- | --- |
| F01 | Insert only the decision row as the runtime account | `42501 permission denied`; balance-only update also `42501`; a researcher calling the function `42501`; the single door still awards atomically (invariant difference 0) | `pentest-after/deep-db.json` (DB04) |
| F02 | Five anonymous failures against one account | account-wide lock **not** set; attacker's address `pair_locked`; the owner's address `open` | `pentest-after/auth-retest.json` |
| F03 | 60 randomized timing samples | medians 139.9 / 143.1 / 142.1 ms, spread ratio 1.02 | `pentest-after/auth-retest.json`, `timing.csv` |
| F04 | 30 rapid attempts on different accounts | 20 × `401`, 10 × `429`, `Retry-After: 600`, correct password also refused while throttled | `pentest-after/auth-retest.json` |
| F05 | Header check | `Permissions-Policy`, COOP, CORP present | `pentest-after/auth-retest.json` |
| All | Black-box script against the live lab (`scripts/pentest.sh`) | **122 resisted, 0 findings** | `evidence/pentest-<date>.txt` (local) |

Full write-up of the original campaign: [`pentest/WRITEUP.md`](pentest/WRITEUP.md), with the retest addendum.

---

## 10. SQL injection: controlled vulnerability, impact, fix and verification

The assignment asks for the chain **vulnerability → security impact → root cause → mitigation → verification**, with the *same* test before and after. The delivered application has no injectable route, so a deliberately unsafe query lives only in a guarded CLI lab (`scripts/sqli-demo.php`, run by `scripts/sqli-demo.sh`) and runs only on the disposable `grants_test` database, **with the real restricted account, acting as a researcher**, so the impact shown is the impact the real privilege model allows.

The vulnerable code: `SELECT id, title FROM proposals WHERE owner_id = <actor> AND title ILIKE '%<INPUT>%'`, with `<INPUT>` pasted into the statement.

| Payload | Intent | Result before the fix |
| --- | --- | --- |
| A1 `' OR TRUE -- ` | Bypass the filter | 11 rows, **all owned by the actor**: RLS still applies |
| **A2** `... UNION SELECT id, email \|\| ' \| ' \|\| full_name \|\| ' \| ' \|\| role FROM users --` | Read every account | **7 accounts leaked** (2 researchers, 3 reviewers, 1 officer, 1 auditor): **confidentiality breach** and a map for targeted attacks |
| A3 `UNION ... password_hash FROM users` | Steal hashes | **Refused** (`42501`): column grant |
| A4 `UNION ... FROM audit_events` | Read the audit trail | **Refused** (`42501`): no SELECT |
| A5 `UNION ... other researchers' proposals` | Cross-user read | 0 rows: RLS |
| A6 `UNION ... comments_enc FROM reviews` | Read reviewer comments | 0 rows: no policy for researchers |
| A7-A9 stacked `; UPDATE users ... ; DELETE FROM decisions ; UPDATE grant_calls ...` | Tamper | **Refused twice**: server-side prepared statements reject stacking (`42601`), and even if they did not, the account has no privilege (`42501`, shown separately) |

**Root cause.** The statement text is built from input, so input can change the *grammar* of the statement (a quote, `UNION`, a comment). Escaping lists and blacklists do not remove the cause.

**Mitigation.** Fixed statement text with the value bound as a parameter (as in `GrantQueries.php`), server-side validation, `PDO::ATTR_EMULATE_PREPARES=false`, and a least-privileged account.

**Verification (same test).** The **same nine payloads** through the parameterised query return **0 rows and no error**: they are treated as harmless search text. A legitimate title with an apostrophe still returns 1 row; an empty search returns only the actor's own rows. The regression test `RLS ... apostrophe` keeps this permanent.

**What this shows about the design.** Even while the code was vulnerable, column privileges, RLS and the missing UPDATE/DELETE grants capped the damage; the worst outcome was the disclosure of account names. Evidence: `docs/evidence/sqli-demo.txt`.

---

## 11. Auditing and incident investigation

**What is logged:** authentication events, proposal create/submit/delete/view, review assignment/view/submit, decision recording, call management, audit viewing. Each event stores actor, role, action, resource, outcome, time, request correlation id and small metadata — never proposal text or review comments.

**Key property:** denied attempts are written on a **second database connection**, so they persist even when the business transaction rolls back.

**Detecting and investigating suspicious activity.** The audit trail answers *who* (actor and role), *what* (action), *when* (UTC, wall-clock), *which resource*, and *was it successful*. The auditor account reads it through a view that carries no proposal text. For the privileged case the PostgreSQL server log adds *from where* (connection host and application name) and *what the server refused* (every `permission denied` with the statement text); `log_connections`, `log_disconnections`, `log_statement = 'ddl'` and `log_lock_waits` are on.

**Incident 1: unauthorized read, then a legitimate award** (`scripts/incident-demo.sh`, `docs/evidence/incident-timeline.txt`). A reviewer who is **not** assigned requests another reviewer's review (HTTP 404, denied and logged), then an officer awards 150,000.00 through the web form, which now calls `record_decision()`. From the audit view alone the investigator reconstructs the sequence, the actors, the resources and the final balance (600,000.00 to 450,000.00); the decision event carries the request id, which proves it came through the web application.

**Incident 2: stolen service credential** (`scripts/incident-privileged.sh`, `docs/evidence/incident-privileged.txt`, disposable `grants_test`). An attacker holding the `grants_app` password (but not `secrets/actor.key`, which lives only in the web process) opens a session from inside the Docker network, outside any HTTP request. The same attack was run **before** the identity binding (`docs/evidence/incident-privileged-before-binding.txt`):

| Step | Before the fix (release 1) | After the fix (release 2) |
| --- | --- | --- |
| A: read audit trail, hashes, login failures, actor key | `42501` each; account list readable | `42501` each; account list readable (the web account needs it) |
| B: claim an officer identity | **allowed**: all submitted proposals readable (O02) | `app.user_id` ignored, self-signed token ignored: **0 rows** |
| C: lone decision row / lone balance edit | `42501` (F01 control held) | `42501` |
| D: award 1.00 through `record_decision()` as the claimed officer | **allowed**, event `decision.record` without request id | **refused** (`42501`): no proved identity |
| E: edit / delete / truncate audit events | `42501` each | `42501` each |
| E: forge an event framing a researcher | **allowed** (O03) | **refused** three ways: direct `INSERT`, `audit_append()` with a forged token, `audit_append()` with no token |

```mermaid
sequenceDiagram
    participant A as Attacker (stolen grants_app password)
    participant DB as PostgreSQL
    participant L as PostgreSQL log
    participant T as Audit trail (auditor view)
    participant I as Investigator
    A->>DB: connect (application_name=stolen-credential)
    DB->>L: connection authorized, host 172.18.0.x, TLS
    A->>DB: read audit_events / password_hash / login_failures / actor_key
    DB-->>A: 42501 (x4)
    A->>DB: claim officer via app.user_id, then via a self-signed actor token
    DB-->>A: 0 rows (no proved identity)
    A->>DB: lone decision / lone balance edit / record_decision()
    DB-->>A: 42501 (x3)
    A->>DB: UPDATE / DELETE / TRUNCATE audit_events, forge an event (3 ways)
    DB-->>A: 42501 (x6)
    DB->>L: every ERROR with the exact STATEMENT
    I->>T: anomaly query: nothing (the attempt never reached the trail)
    I->>L: the connection of interest and every refused statement
```

**Investigation (evidence only).** (2a) the application audit trail contains **no event** from the session; (2b) the anomaly query (events without request id or source address) returns none; (2c) the **PostgreSQL log** is the only witness: the connection (pid, `host=172.18.0.3`, `application_name=stolen-credential`, TLS) and every refused statement with its text. **Controls that held:** identity proved not asserted (O02), no audit forgery (O03), no partial award (F01), no hash or audit read, audit immutable, every refusal logged. **What remains:** the account list is readable, the credential helper still returns one hash per e-mail (O01), nothing in the *application* trail shows the attempt (alert on `permission denied` for `grants_app`), and an attacker who also takes `secrets/actor.key` (a full compromise of the web process) can act as any user again. **Corrective actions:** rotate `grants_app` (and the actor key if the web host is suspect), alert on the log, tighten `pg_hba.conf`, add `pgaudit`, ship the log off the host, and split the web process so that no single process holds every key.

---

## 12. Backup and recovery

```mermaid
flowchart LR
    A[pg_dump -Fc as grants_backup] --> B[OpenPGP public-key encrypt] --> C[backups/grants-UTC.dump.gpg]
    K[secrets/field.key] --> L[OpenPGP encrypt] --> M[backups/grants-UTC.fieldkey.gpg]
    C --> D[Restore to a separate database]
    D --> E[Verify: values, funds, privileges, RLS, comments, login]
```

**Strategy.** A logical encrypted backup of the database plus a *separate* backup of the field keyring, because the dump holds ciphertext comments that are unreadable without the keys, and the keys must not travel with the data they protect. Roles are cluster-wide and not inside the archive, so a restore re-applies `01_roles.sql` and `00_database.sql` first.

**Procedure** (`scripts/backup.sh`, `scripts/restore.sh`, `scripts/restore-field-key.sh`):

1. `backup.sh grants` writes `backups/grants-<UTC>.dump.gpg` + `.sha256` and `...fieldkey.gpg` + `.sha256` (the plaintext dump never touches the disk; encryption needs only the **public** key).
2. `restore.sh <file> grants_restore` verifies the checksum, restores into a **separate** database (never over `grants`), and re-applies roles and database ACLs.
3. `restore-field-key.sh <file>` decrypts the keyring next to the live one, never over it.

**Controlled data loss and recovery.** `scripts/recovery-drill.sh` backs up the live database, restores it into `grants_drill`, **destroys the schema there** (`DROP SCHEMA grants CASCADE`: 1 schema + 22 objects), restores again from the encrypted archive (**0.7 s**), then verifies: per-table row counts and md5 over all rows match the source for the six tables; table privileges, column privileges and the RLS policies are identical; and 7 behavioural checks (23 assertions) pass under the restricted accounts: RLS fails closed, researchers see only their own proposals, privileges and triggers came back, funds and the awarded decision have the expected values, **encrypted comments decrypt with the separately stored key**, and a user can sign in against the restored database. The key backup decrypts and is identical to the live keyring (`docs/evidence/recovery-drill.txt`).

**Protection of the backups.** Files are mode 600 and ignored by Git; the private key can be passphrase-protected, exported and removed from the backup host (`scripts/backup-key.sh`); `docs/evidence/backup-key-custody.txt` shows the host still encrypting but no longer able to read, and a clean workstation restoring after the custodians supply the key and the passphrase.

---

## 13. Hardening

| Security issue | Before hardening | After hardening | Justification |
| --- | --- | --- | --- |
| Default accounts | One superuser `postgres`, `trust` authentication for local and loopback | Superuser only through the local `peer` socket inside the container; no other default accounts; owner role `NOLOGIN` | The owner must not be a network-reachable credential |
| Unnecessary users | PUBLIC may connect to a new database | `REVOKE ALL ON DATABASE ... FROM PUBLIC`; three login accounts, each in one privilege group | Least privilege |
| Excessive privileges | (design alternative: one account with full rights) | Column-level grants; **no INSERT on `decisions`, no UPDATE of budgets**; no DELETE on reviews; `audit_events` INSERT only | F01 and the least-privilege requirement |
| Weak application accounts | (default) | 48-hex-digit generated passwords, SCRAM, connection limits, statement and lock timeouts | Online guessing and runaway queries |
| Database network exposure | `listen_addresses = *`, SSL off, `host all all all scram` | No host port published; `hostssl ... samenet` for two accounts; `host all all all reject`; TLS 1.2+; `verify-full` from the application | Only the web container reaches the database, encrypted |
| Logging configuration | `log_statement = none`, no connection logs | Connections, disconnections, DDL, lock waits logged; denied statements logged with text | Investigation (incident 2) |
| Configuration files | Image defaults | `pg_hba.conf` and `hardening.conf` versioned and mounted read-only | Reviewable, reproducible |
| Unnecessary features | 28 Apache modules incl. autoindex and status; `display_errors` on; `allow_url_fopen` on | `autoindex`, `status`, default site, CGI disabled; production `php.ini`, errors to a private log | Least functionality |
| File permissions | Defaults | `secrets/` mode 600, outside the web root, ignored by Git; code mounted read-only | Secrets and integrity of code |
| Authentication abuse | Account-wide lockout, no throttle, timing gap | Per-(account, address) lock, per-address throttle, equal hashing work | F02-F04 |
| Browser hardening | Five headers | + `Permissions-Policy`, COOP, CORP | F05 |
| Backup protection | (none) | Public-key encrypted, checksummed, key backed up separately, private-key custody scripts | Phase 8, key management |
| Patch/update status | 8 pending package upgrades in the web image, 5 in the db image (measured 17 Nov) | Rebuilt with `docker compose build --pull` and a pulled `postgres:18` (now 18.7): 0 and 0 pending; data volume kept, fresh backup taken first, tests and recovery drill rerun | Rebuild on a schedule; not automated |

Before/after listings: `docs/evidence/hardening.txt`, `docs/evidence/privileges.txt` (regenerated 17 November).

---

## 14. Final assessment, limitations and recommendations

### 14.1 Assessment (the nine questions of the assignment)

| Question | Answer | Evidence |
| --- | --- | --- |
| Authentication: are users properly authenticated? | Yes: individual accounts, Argon2id, session hygiene, per-address throttle, equal timing (F02-F04 remediated and retested) | tests `AUTH`, `pentest-after/auth-retest.json` |
| Authorization: only the resources required? | Yes, enforced twice (PHP and RLS); 2 matrices in 6.5; cross-user access refused in tests and pentest | tests `RBAC`, `RLS`; pentest IDOR/PRIVESC |
| Least privilege: unnecessary privileges removed? | Yes, including the F01 privileges (`INSERT` on `decisions`, `UPDATE` of budgets) | `privileges.txt`, test `AWARD`, DB04 |
| Application security: SQL injection mitigated? | Yes: bound parameters; impact shown before, none after | section 10 |
| Data protection: sensitive information protected? | Yes: Argon2id, field encryption with a managed keyring, TLS, encrypted backups with separate key backup | tests `DATA`, `key-rotation.txt` |
| Auditing and monitoring: identified and traced? | Yes, including denials; the anomaly query and the server log expose activity outside the application | tests `AUDIT`, incident 2 |
| Backup and recovery: recoverable after data loss? | Yes: 0.7 s restore, all comparisons match, 7 checks pass | `recovery-drill.txt` |
| Hardening: attack surface reduced? | Yes: table in section 13 | `hardening.txt` |
| Incident investigation: can the evidence support it? | Yes, for two scenarios; incident 2 also shows what the evidence cannot prove | two timelines |

### 14.2 Limitations (stated honestly)

* The penetration test is a **bounded lab campaign**, not a certification. The retest replays the same probes; it does not prove the absence of other flaws.
* **A fully compromised web front end** no longer holds the actor key or any identity credential (release 3, section 6.5c). It can still act as the users who are signed in at that moment, because it sees their opaque session handles, and it sees passwords as they are typed at the sign-in form. Incident 3 shows what it can and cannot do. The client address is reported by the front end, so per-address throttling can be evaded by a compromised front end; an account-level slow-down is still to add.
* **O01 is closed**: password hashes are readable only by the identity service's database account; the web account is refused (`42501`).
* TOTP is not phishing-resistant; officers and auditors can therefore also register a **WebAuthn security key**, which is bound to this site's origin (section 6.5c). Keys are optional, TOTP stays the fallback, and the factor is required for officers and auditors only, and enrolment is by manual key entry (no QR code, to avoid a library). A distributed guessing attack against a researcher or reviewer account is slowed and alerted, not stopped. People behind one address share the per-address limit.
* E-mail uses the **file transport** in the lab (nothing leaves the machine); the SMTP client is tested against a fake server, not a real mail provider. Messages deliberately contain no proposal details.
* Docker and host administrators remain highly trusted; the lab TLS certificates are self-signed; single node; timing measured locally.
* In this lab the keyring, the actor key, the key passphrase and the backup private key start on one host; the scripts support separate custody but the demonstration is on a copy.
* CI is configured and runs on every push and pull request; image updates are applied by rebuilding (done on 17 November: 0 pending), and Dependabot proposes base-image and action updates.

### 14.3 Recommendations (priority order)

1. Split the web process into a front end and an **identity/audit service**, so that no single process holds the actor key and every credential.
2. **WebAuthn / hardware keys** instead of, or besides, TOTP; extend the second factor to every role that can read confidential data.
3. Move password verification to a place that never hands hashes to the web account (closes O01).
4. Ship PostgreSQL and application logs to a separate host, add `pgaudit`, and alert on `permission denied` for `grants_app` and on `auth.suspicious_volume`.
5. Move the backup private key, its passphrase and the actor key to separate custodians; define the key-rotation calendar.
6. Real SMTP with a provider, per-user notification preferences, and a rate limit per recipient.

---

## 15. Reproducing the work

```bash
scripts/setup.sh                    # secrets, build, roles, schema, remediation release, seed
scripts/test.sh                     # 78 tests / 851 assertions + 13 owner-level guard checks
scripts/sqli-demo.sh                # controlled SQL injection: impact, fix, same payloads replayed
node scripts/screenshots.mjs        # 30 screenshots + 23 interface checks
scripts/incident-demo.sh            # incident 1: unauthorized read, legitimate award
scripts/incident-privileged.sh      # incident 2: stolen service credential, investigated from logs
scripts/recovery-drill.sh           # backup + key backup -> loss -> restore -> verify
scripts/key-rotation-drill.sh       # add key -> re-encrypt -> retire, audited
scripts/backup-key-custody-demo.sh  # backup private key: export, remove, import elsewhere
scripts/pentest.sh                  # black-box checks against the live lab
python3 scripts/pentest/retest-auth.py   # replay of F02-F05 with the original probes
scripts/evidence.sh                 # privilege and hardening listings
scripts/totp.py <e-mail>            # current 6-digit code of a demo officer/auditor
scripts/mfa-reset.sh <e-mail>       # operator: reset one person's second factor (audited)
php scripts/send-notifications.php  # deliver the e-mail outbox (the notifier service does it every minute)
```

To bring an **existing** database to this release without losing data: `scripts/db-apply.sh grants` (applies `05_remediation.sql`, then re-applies the grants).

Demo credentials are generated locally in `secrets/demo-credentials.txt` and are never committed.

---

## 16. References

1. OWASP Application Security Verification Standard (ASVS)
2. OWASP Top 10 and Cheat Sheet Series (SQL injection, CSRF, session management, password storage)
3. PostgreSQL 18 documentation: Row Security Policies, `GRANT`, `pg_hba.conf`, SSL
4. libsodium documentation: authenticated secret-key encryption
5. NIST SP 800-63B: Digital Identity Guidelines (authentication)
6. WCAG 2.2 (focus visibility, colour independence)
7. Tabler Icons v3.51.0 (MIT)
