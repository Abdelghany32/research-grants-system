# Entity-relationship diagram and data ownership

```mermaid
erDiagram
    users ||--o{ grant_calls  : "creates (officer)"
    users ||--o{ proposals    : "owns (researcher)"
    users ||--o{ reviews      : "reviews (reviewer)"
    users ||--o{ reviews      : "assigns (officer)"
    users ||--o{ decisions    : "decides (officer)"
    users |o--o{ audit_events : "acts"
    users |o--o{ login_failures : "failed attempts (functions only)"
    users ||--o{ mfa_recovery_codes : "has (functions only)"
    users ||--o{ notifications : "is addressed by"
    users ||--o{ webauthn_credentials : "registers (functions only)"
    users |o--o{ identity_sessions : "signed in (identity account only)"
    grant_calls ||--o{ proposals : "receives"
    proposals   ||--o{ reviews   : "is evaluated by"
    proposals   ||--o| decisions : "ends with at most one"

    users {
        bigint id PK
        text email UK "lower-case"
        text full_name
        text department
        text role "researcher | reviewer | officer | auditor"
        text password_hash "Argon2id"
        boolean is_active
        timestamptz locked_until "administrative lock only"
        text totp_secret_enc "second factor, encrypted, never in clear"
        timestamptz totp_enrolled_at
        bigint totp_last_step "replay protection"
        timestamptz last_login_at
        timestamptz created_at
    }
    grant_calls {
        bigint id PK
        text title
        text description
        text currency "ISO 4217, UK with id"
        numeric total_budget "numeric(14,2), fixed"
        numeric remaining_budget "0..total, only decreases"
        timestamptz opens_at
        timestamptz closes_at
        text status "open | closed"
        bigint created_by FK
    }
    proposals {
        bigint id PK
        bigint call_id FK "with currency -> grant_calls(id, currency)"
        bigint owner_id FK
        text title
        text abstract
        numeric requested_amount "numeric(14,2)"
        text currency
        text status "draft | submitted | under_review | approved | declined"
        timestamptz submitted_at
        timestamptz created_at
        timestamptz updated_at
    }
    reviews {
        bigint id PK
        bigint proposal_id FK "UK with reviewer_id"
        bigint reviewer_id FK
        bigint assigned_by FK
        timestamptz due_at
        text status "assigned | submitted"
        smallint score "1..10"
        text comments_enc "XChaCha20-Poly1305 ciphertext"
        timestamptz submitted_at
    }
    decisions {
        bigint id PK
        bigint proposal_id FK "UNIQUE; with currency -> proposals(id, currency)"
        text outcome "approved | declined"
        numeric awarded_amount "numeric(14,2)"
        text currency
        text rationale
        bigint decided_by FK
        timestamptz decided_at
    }
    login_failures {
        bigint id PK
        timestamptz occurred_at
        bigint user_id FK "NULL = unknown e-mail"
        inet source_ip
    }
    audit_events {
        bigint id PK
        timestamptz occurred_at "clock_timestamp(), UTC"
        bigint actor_id FK "NULL = not signed in"
        text actor_role
        text action
        text resource_type
        bigint resource_id
        text outcome "success | denied | failure"
        uuid correlation_id
        inet source_ip
        jsonb details "metadata only"
        boolean actor_verified "true = proved by an actor token"
    }
    mfa_recovery_codes {
        bigint id PK
        bigint user_id FK
        text code_hash "Argon2id"
        timestamptz used_at
    }
    webauthn_credentials {
        bigint id PK
        bigint user_id FK
        bytea credential_id UK
        text public_key_pem "public key only"
        smallint alg "-7 ES256, -257 RS256"
        bigint sign_count "must move forward"
        text name
    }
    identity_sessions {
        bytea handle_hash PK "sha256 of the opaque handle"
        bigint user_id
        text data_enc "encrypted, bound to the row"
        timestamptz expires_at
    }
    notifications {
        bigint id PK
        bigint to_user_id FK "chosen by the database"
        text kind "5 fixed kinds"
        text ref_type
        bigint ref_id "UNIQUE with kind and recipient"
        text subject "fixed template"
        text body "no confidential content"
        timestamptz sent_at
        int attempts
    }
    actor_key {
        smallint id PK "always 1"
        bytea secret "owner-only; verifies actor tokens"
    }
```

Cardinalities: a call receives many proposals; a proposal belongs to exactly one call and one owner;
a proposal has zero or more reviews, at most one per reviewer (`UNIQUE (proposal_id, reviewer_id)`);
a proposal has at most one decision (`UNIQUE (proposal_id)`) and decision rows are created only by the database function `record_decision()`. All timestamps are `timestamptz`
with the database and both login roles pinned to UTC.

The two composite foreign keys make a currency mismatch impossible: a proposal can only carry its
call's currency, and a decision can only carry its proposal's currency.

## Ownership of sensitive fields (data classification with availability needs)

| Field | Classification | Data owner | May read | May write | Availability need |
| --- | --- | --- | --- | --- | --- |
| `users.password_hash` | Secret | The account holder | Nobody through SQL grants; `auth_find_credentials()` returns one row for one e-mail | Schema owner only (seed) | Medium: no sign-in without it |
| `users.email`, `full_name`, `department` | Personal (internal) | The person | Runtime account | Schema owner only | Medium |
| `users.role`, `is_active` | Internal, integrity-critical | Research office | Runtime account | Schema owner only | Medium |
| `users.locked_until` | Internal | Security | Runtime account (read) | Administrator only (incident response) | Low |
| `proposals.title`, `abstract` | Confidential (unpublished research) | The researcher | Owner; assigned reviewers and officers once submitted | Owner while draft | **High** before a deadline |
| `proposals.requested_amount` | Confidential | The researcher | Same as abstract | Owner while draft | High |
| `reviews.score` | Confidential | The reviewer | The reviewer, officers | The reviewer until final | Medium |
| `reviews.comments_enc` | Restricted (private notes) | The reviewer | The reviewer, officers; ciphertext to everyone else including DBAs and backups | The reviewer until final | Medium; unreadable if the key is lost |
| `decisions.outcome`, `awarded_amount`, `rationale` | Confidential, integrity-critical | Grants office | Officers; the proposal owner | **Only `record_decision()`**, once per proposal | High |
| `grant_calls.remaining_budget` | Internal, integrity-critical | Grants office | Workflow roles | **Only `record_decision()`** (lowers it) | High |
| `login_failures.*` | Internal (security) | Security | Nobody directly; three `SECURITY DEFINER` functions | The same functions | **High**: a flawed design lets an attacker lock people out |
| `audit_events.*` | Restricted (security record) | Internal audit | Auditor account through `audit_timeline` | Append-only by the runtime account (observation O03) | Medium |
| Field keyring, backup private key, DB passwords | Secret | System administrator | Files under `secrets/`, mode 0600 | Generated by `scripts/setup.sh` / `backup.sh`; keyring changed by `rotate-field-key.sh` | High |
| `users.totp_secret_enc` | Secret | The account holder | Nobody through SQL; `mfa_state()` with the user's own token | `mfa_enroll()` once, with the user's own token (operator reset: `scripts/mfa-reset.sh`) | Medium |
| `mfa_recovery_codes.code_hash` | Secret (Argon2id) | The account holder | Nobody (functions only) | `mfa_enroll()`, `mfa_consume_recovery()` | Low |
| `webauthn_credentials.*` | Internal (public key, counter) | The account holder | Identity account through `webauthn_list()` with the owner's actor token | `webauthn_register()`, `webauthn_use()`, `webauthn_delete()` (own token; the last second factor cannot be removed) | Low |
| `identity_sessions.*` | Secret (session state) | Security | Identity account only; the web account has no privilege | Identity service; handles are stored as SHA-256, payload encrypted | High |
| `notifications.*` | Internal | Security | The notifier account | `notify_enqueue()` (actor token, own action, fixed template); the notifier marks them sent | Medium |
| `actor_key.secret` | Secret (verifies identity) | System administrator | Schema owner only | `database/06_identity_and_audit.sql` from `secrets/actor.key` | High |
| `audit_events.actor_verified` | Restricted | Internal audit | Auditor account | Set by `audit_append()` / `record_decision()`: true only for a proved actor | Medium |
| `reviews.due_at` | Internal | Grants office | Reviewer (own), officers | Set at assignment; moved forward only by an officer (trigger) | Medium |
