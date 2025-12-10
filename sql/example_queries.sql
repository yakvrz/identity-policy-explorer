-- Security coverage by policy for last 30 days
SELECT
  policy_name,
  SUM(high_risk_sessions) AS high_risk_sessions,
  SUM(covered_high_risk_sessions) AS covered_high_risk_sessions,
  SUM(residual_high_risk_sessions) AS residual_high_risk_sessions,
  ROUND(
    100.0 * SUM(covered_high_risk_sessions) / NULLIF(SUM(high_risk_sessions),0), 2
  ) AS coverage_pct
FROM v_policy_security_metrics
WHERE date >= DATE('now', '-30 days')
GROUP BY policy_name;

-- MFA prompts per active user per policy
SELECT
  policy_name,
  ROUND(
    CAST(mfa_challenges AS REAL) / NULLIF(active_users, 0), 3
  ) AS mfa_prompts_per_user
FROM (
  SELECT
    policy_name,
    SUM(mfa_challenges) AS mfa_challenges,
    COUNT(DISTINCT user_id) AS active_users
  FROM v_events_with_policy
  WHERE date(created_at) >= DATE('now', '-30 days')
  GROUP BY policy_name
);

-- Tradeoff curve reference: risk threshold grid evaluated in Python,
-- see src/metrics.py:compute_threshold_grid for a reusable helper.
