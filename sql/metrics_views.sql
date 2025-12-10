CREATE VIEW IF NOT EXISTS v_sessions_with_policy AS
SELECT
    s.session_id,
    s.org_id,
    s.user_id,
    s.started_at,
    s.device_type,
    s.ip_risk_level,
    rf.risk_score,
    u.role,
    u.is_privileged,
    o.segment,
    o.region,
    pd.policy_id,
    p.policy_name,
    pd.decision
FROM sessions s
JOIN session_risk_factors rf ON rf.session_id = s.session_id
JOIN users u ON u.user_id = s.user_id
JOIN organizations o ON o.org_id = s.org_id
JOIN policy_decisions pd ON pd.session_id = s.session_id
JOIN policies p ON p.policy_id = pd.policy_id;

CREATE VIEW IF NOT EXISTS v_policy_security_metrics AS
SELECT
    policy_name,
    DATE(started_at) AS date,
    COUNT(*) FILTER (WHERE risk_score >= 0.8) AS high_risk_sessions,
    COUNT(*) FILTER (
        WHERE risk_score >= 0.8 AND decision IN ('mfa', 'block')
    ) AS covered_high_risk_sessions,
    COUNT(*) FILTER (
        WHERE risk_score >= 0.8 AND decision = 'block'
    ) AS blocked_high_risk_sessions,
    COUNT(*) FILTER (
        WHERE risk_score >= 0.8 AND decision = 'allow'
    ) AS residual_high_risk_sessions
FROM v_sessions_with_policy
GROUP BY policy_name, DATE(started_at);

CREATE VIEW IF NOT EXISTS v_events_with_policy AS
SELECT
  e.*,
  v.policy_name,
  v.org_id,
  v.user_id,
  v.segment,
  v.region,
  v.role,
  v.device_type
FROM auth_events e
JOIN v_sessions_with_policy v ON v.session_id = e.session_id;

CREATE VIEW IF NOT EXISTS v_policy_friction_metrics AS
SELECT
    policy_name,
    DATE(created_at) AS date,
    COUNT(*) FILTER (WHERE event_type = 'mfa_challenge') AS mfa_challenges,
    COUNT(*) FILTER (WHERE event_type = 'mfa_failed') AS mfa_failures,
    COUNT(*) FILTER (WHERE event_type = 'login_started') AS logins_started,
    COUNT(*) FILTER (WHERE event_type = 'login_success') AS logins_success
FROM v_events_with_policy
GROUP BY policy_name, DATE(created_at);

CREATE VIEW IF NOT EXISTS v_org_policy_summary AS
SELECT
    o.org_id,
    o.org_name,
    o.segment,
    o.region,
    v.policy_name,
    COUNT(*) FILTER (WHERE v.risk_score >= 0.8) AS high_risk_sessions,
    COUNT(*) FILTER (
        WHERE v.risk_score >= 0.8 AND v.decision IN ('mfa', 'block')
    ) AS covered_high_risk_sessions,
    COUNT(*) FILTER (
        WHERE v.risk_score >= 0.8 AND v.decision = 'allow'
    ) AS residual_high_risk_sessions,
    COUNT(*) FILTER (WHERE v.decision = 'mfa') AS mfa_sessions,
    COUNT(*) AS total_sessions
FROM v_sessions_with_policy v
JOIN organizations o ON o.org_id = v.org_id
GROUP BY o.org_id, o.org_name, o.segment, o.region, v.policy_name;
