PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS organizations (
    org_id     INTEGER PRIMARY KEY,
    org_name   TEXT NOT NULL,
    segment    TEXT,
    region     TEXT,
    created_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    user_id       INTEGER PRIMARY KEY,
    org_id        INTEGER REFERENCES organizations(org_id),
    role          TEXT,
    is_privileged BOOLEAN,
    country       TEXT,
    created_at    TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id        INTEGER PRIMARY KEY,
    user_id           INTEGER REFERENCES users(user_id),
    org_id            INTEGER REFERENCES organizations(org_id),
    started_at        TIMESTAMP,
    device_type       TEXT,
    ip_address        TEXT,
    ip_country        TEXT,
    ip_risk_level     TEXT,
    previous_country  TEXT,
    previous_device   TEXT,
    previous_login_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_events (
    event_id      INTEGER PRIMARY KEY,
    session_id    INTEGER REFERENCES sessions(session_id),
    event_type    TEXT,
    created_at    TIMESTAMP,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS policies (
    policy_id          INTEGER PRIMARY KEY,
    policy_name        TEXT,
    risk_threshold     REAL,
    block_high_risk    BOOLEAN,
    mfa_for_admins     BOOLEAN,
    mfa_for_new_device BOOLEAN,
    mfa_for_geo_change BOOLEAN
);

CREATE TABLE IF NOT EXISTS session_risk_factors (
    session_id           INTEGER PRIMARY KEY REFERENCES sessions(session_id),
    risk_score           REAL,
    is_new_country       BOOLEAN,
    is_new_device        BOOLEAN,
    geo_distance_km      REAL,
    impossible_travel    BOOLEAN,
    recent_failed_logins INTEGER,
    odd_login_hour       BOOLEAN,
    ip_reputation_score  REAL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    policy_id      INTEGER REFERENCES policies(policy_id),
    session_id     INTEGER REFERENCES sessions(session_id),
    decision       TEXT,
    effective_risk REAL,
    PRIMARY KEY (policy_id, session_id)
);

CREATE TABLE IF NOT EXISTS session_explanations (
    session_id        INTEGER PRIMARY KEY REFERENCES sessions(session_id),
    explanations_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_org ON sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_auth_events_session ON auth_events(session_id);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_policy ON policy_decisions(policy_id);
