-- Commit Quarantine Gateway schema.
--
-- Holds identity (users, tokens) and the held-push queue. Scan findings and
-- verdicts live in the audit log and SARIF reports, not here: those must
-- remain append-only files that an auditor can verify independently of the
-- database.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    subject       TEXT NOT NULL DEFAULT '',  -- OIDC subject, when federated
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    -- SHA-256 of the token secret; the secret itself is never stored.
    digest     TEXT NOT NULL UNIQUE,
    scopes     TEXT NOT NULL,              -- comma-separated
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used  TEXT
);

CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);

-- Pushes parked by a `hold` verdict, awaiting a reviewer with the approve
-- scope. The quarantine repo is kept on disk until the push is resolved.
CREATE TABLE IF NOT EXISTS held_pushes (
    id              TEXT PRIMARY KEY,       -- the quarantine push id
    repo            TEXT NOT NULL,
    ref             TEXT NOT NULL,
    old_rev         TEXT NOT NULL,
    new_rev         TEXT NOT NULL,
    actor_user_id   TEXT NOT NULL REFERENCES users(id),
    quarantine_path TEXT NOT NULL,
    findings_json   TEXT NOT NULL DEFAULT '[]',
    reasons_json    TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    -- pending | approved | rejected | expired
    state           TEXT NOT NULL DEFAULT 'pending',
    resolved_at     TEXT,
    resolved_by     TEXT REFERENCES users(id),
    resolution_note TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_held_state ON held_pushes(state, created_at);
