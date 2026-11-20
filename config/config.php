<?php
// All environment-specific values come from environment variables or files
// mounted outside the web root. Nothing secret is stored in this file.
return [
    'db' => [
        'host'             => getenv('DB_HOST') ?: 'db',
        'port'             => getenv('DB_PORT') ?: '5432',
        'name'             => getenv('DB_NAME') ?: 'grants',
        'sslrootcert'      => getenv('DB_SSLROOTCERT') ?: '',
        'app_user'         => 'grants_app',
        'app_password'     => getenv('APP_DB_PASSWORD') ?: '',
        'auditor_user'     => 'grants_auditor',
        'auditor_password' => getenv('AUDITOR_DB_PASSWORD') ?: '',
        'audit_writer_user'     => 'grants_audit_write',
        'audit_writer_password' => getenv('AUDIT_WRITER_DB_PASSWORD') ?: '',
        'identity_user'         => 'grants_identity',
        'identity_password'     => getenv('IDENTITY_DB_PASSWORD') ?: '',
        'notifier_user'         => 'grants_notifier',
        'notifier_password'     => getenv('NOTIFIER_DB_PASSWORD') ?: '',
    ],
    'session' => [
        'idle_seconds'     => (int) (getenv('SESSION_IDLE_SECONDS') ?: 20 * 60),   // inactivity expiry
        'absolute_seconds' => 8 * 60 * 60,  // forced re-login after a working day
    ],
    'auth' => [
        // Failures are counted per (account, source address), not per account:
        // a stranger cannot lock the real owner out (finding F02).
        'pair_max_failures'   => 5,    // failures for one account from one address ...
        'pair_window_minutes' => 15,   // ... within this window lock that pair for the rest of the window
        // A source address that keeps failing is refused before any password hashing (finding F04).
        'ip_max_failures'     => 20,   // failures against ANY account from one address ...
        'ip_window_minutes'   => 10,   // ... within this window
        'alert_account_failures' => 20, // failures against one account from all addresses in an hour -> audit alert
        // Second factor (TOTP, RFC 6238). Required for these roles; anyone who enrolled is asked for it too.
        'mfa' => [
            'required_roles'  => ['officer', 'auditor'],
            'issuer'          => 'Research Grants',
            'window'          => 1,            // accept the previous and next 30-second step (clock drift)
            'pending_seconds' => 300,          // time allowed between the password and the code
            'max_attempts'    => 5,            // wrong codes before the pending sign-in is abandoned
            // A code is accepted once (the database records the last step). Switched off ONLY by the automated
            // tests, which sign the same user in many times within one 30-second step.
            'replay_protection' => getenv('MFA_REPLAY_PROTECTION') !== '0',
        ],
        // Security keys (WebAuthn). The relying-party id is the site's host name and the origin its public address: a
        // credential made for one cannot be used on a look-alike site, which is what makes this factor phishing-resistant.
        'webauthn' => [
            'origin'     => $origin = rtrim(getenv('WEBAUTHN_ORIGIN') ?: (getenv('PUBLIC_URL') ?: 'https://localhost:8443'), '/'),
            'rp_id'      => getenv('WEBAUTHN_RP_ID') ?: (parse_url($origin, PHP_URL_HOST) ?: 'localhost'),
            'require_uv' => getenv('WEBAUTHN_REQUIRE_UV') !== '0',   // the key must check the person (PIN or fingerprint)
            'ttl'        => 120,                                       // seconds a challenge stays valid
        ],
    ],
    // 'local': this process holds the identity secrets itself (the identity service, the tests, the operator tools).
    // 'remote': this process is the web front end and calls the identity service instead.
    'identity' => [
        'mode'    => getenv('IDENTITY_MODE') ?: 'local',
        'url'     => getenv('IDENTITY_URL') ?: 'http://identity:8081',
        'api_key' => getenv('IDENTITY_API_KEY') ?: '',
    ],
    'mail' => [
        'transport'     => getenv('MAIL_TRANSPORT') ?: 'file',
        'from'          => getenv('MAIL_FROM') ?: 'research-grants@uni.example',
        'public_url'    => rtrim(getenv('PUBLIC_URL') ?: 'https://localhost:8443', '/'),
        'smtp_host'     => getenv('SMTP_HOST') ?: '',
        'smtp_port'     => (int) (getenv('SMTP_PORT') ?: 587),
        'smtp_security' => getenv('SMTP_SECURITY') ?: 'starttls',
        'smtp_user'     => getenv('SMTP_USER') ?: '',
        'smtp_password' => getenv('SMTP_PASSWORD') ?: '',
    ],
    'field_key_file' => getenv('FIELD_KEY_FILE') ?: '',
    'actor_key_file' => getenv('ACTOR_KEY_FILE') ?: '',
    'log_dir'        => getenv('LOG_DIR') ?: __DIR__ . '/../logs',
];
