# Identity Security Policy Tradeoff Explorer

**End-to-end Specification Document**

---

## 0. Overview

**Working title:** Identity Security Policy Tradeoff Explorer

**Purpose:**
A small analytics web app that lets product and security stakeholders explore the tradeoff between **risk reduction** and **user friction** for adaptive authentication policies. It operates on synthetic authentication telemetry, applies multiple policy variants, and exposes intuitive metrics, visualizations, and explanations.

**Primary users:**

* Identity / security product managers
* Security architects / analysts
* UX / product designers working on authentication flows

**Key questions:**

1. How much **risk** is reduced by a given authentication policy?
2. How much **friction** (MFA prompts, failures, decreased login success) is introduced?
3. How does this tradeoff vary across segments (org size, region, role, device)?
4. For any given login, **why** was it considered risky and what happened to it?

---

## 1. System Architecture

### 1.1 Tech Stack

* **Backend / Data:**

  * Synthetic data generation in Python
  * SQLite or DuckDB database file for portability
  * SQL as the metrics/query layer

* **Analytics & Logic:**

  * Python (Pandas, NumPy)
  * Optional: scikit-learn for simple anomaly scoring (if desired)

* **Frontend / UI:**

  * Streamlit web app (single-page or multipage)
  * Plotly charts for interactive visualizations

* **Packaging:**

  * `requirements.txt` for dependencies
  * `README.md` with setup instructions

### 1.2 Repository Structure

```text
identity-policy-explorer/
├─ README.md
├─ requirements.txt
├─ data/
│  ├─ seed_config.yaml        # parameters for synthetic data generation
│  └─ auth_demo.db            # generated SQLite or DuckDB database
├─ sql/
│  ├─ schema.sql              # CREATE TABLE statements
│  ├─ metrics_views.sql       # CREATE VIEW statements
│  └─ example_queries.sql     # reference queries for development
├─ src/
│  ├─ generate_data.py        # synthetic data generation script
│  ├─ policy_engine.py        # policy definition and evaluation logic
│  ├─ explanations.py         # session-level explanation generation
│  └─ metrics.py              # helpers that query metrics from DB
├─ app/
│  └─ app.py                  # Streamlit application entrypoint
├─ report/
│  ├─ demo_report.md          # 2–4 page product-style writeup
│  └─ figures/                # exported charts from the app
└─ tests/
   └─ test_metrics.py         # basic unit tests
```

---

## 2. Data Model

The demo simulates an identity/authentication environment with the following entities:

* **Organizations** – tenant accounts
* **Users** – people or service identities
* **Sessions** – login attempts (context)
* **Auth events** – stepwise actions in a session
* **Risk factors** – features characterizing session risk
* **Policies** – adaptive authentication policy configurations
* **Policy decisions** – what each policy does with each session

### 2.1 Tables

#### 2.1.1 `organizations`

Represents customer organizations.

```sql
CREATE TABLE organizations (
    org_id           INTEGER PRIMARY KEY,
    org_name         TEXT,
    segment          TEXT,   -- 'SMB', 'Mid', 'Enterprise'
    region           TEXT,   -- 'NA', 'EU', 'APAC', 'LATAM', etc.
    created_at       TIMESTAMP
);
```

#### 2.1.2 `users`

Represents identities within organizations.

```sql
CREATE TABLE users (
    user_id          INTEGER PRIMARY KEY,
    org_id           INTEGER REFERENCES organizations(org_id),
    role             TEXT,    -- 'admin', 'developer', 'employee', 'service'
    is_privileged    BOOLEAN, -- derived from role (e.g., admin/service)
    country          TEXT,
    created_at       TIMESTAMP
);
```

#### 2.1.3 `sessions`

Represents login attempts with contextual attributes.

```sql
CREATE TABLE sessions (
    session_id        INTEGER PRIMARY KEY,
    user_id           INTEGER REFERENCES users(user_id),
    org_id            INTEGER REFERENCES organizations(org_id),
    started_at        TIMESTAMP,
    device_type       TEXT,    -- 'desktop', 'mobile', 'unknown'
    ip_address        TEXT,
    ip_country        TEXT,
    ip_risk_level     TEXT,    -- 'low', 'medium', 'high'
    previous_country  TEXT,
    previous_device   TEXT,
    previous_login_at TIMESTAMP
);
```

#### 2.1.4 `auth_events`

Represents stepwise events within a session.

```sql
CREATE TABLE auth_events (
    event_id     INTEGER PRIMARY KEY,
    session_id   INTEGER REFERENCES sessions(session_id),
    event_type   TEXT,        -- 'login_started','login_success','login_failed',
                              -- 'mfa_challenge','mfa_success','mfa_failed',
                              -- 'policy_blocked'
    created_at   TIMESTAMP,
    metadata_json TEXT        -- optional JSON payload
);
```

#### 2.1.5 `policies`

Represents predefined policy variants.

```sql
CREATE TABLE policies (
    policy_id          INTEGER PRIMARY KEY,
    policy_name        TEXT,  -- 'lenient', 'balanced', 'strict'
    risk_threshold     REAL,  -- >= threshold => challenge/block
    block_high_risk    BOOLEAN,
    mfa_for_admins     BOOLEAN,
    mfa_for_new_device BOOLEAN,
    mfa_for_geo_change BOOLEAN
);
```

#### 2.1.6 `session_risk_factors`

Stores derived risk-related features for each session.

```sql
CREATE TABLE session_risk_factors (
    session_id           INTEGER PRIMARY KEY REFERENCES sessions(session_id),
    risk_score           REAL,   -- continuous 0-1
    is_new_country       BOOLEAN,
    is_new_device        BOOLEAN,
    geo_distance_km      REAL,
    impossible_travel    BOOLEAN,
    recent_failed_logins INTEGER, -- last 24h
    odd_login_hour       BOOLEAN,
    ip_reputation_score  REAL    -- 0-1
);
```

#### 2.1.7 `policy_decisions`

Stores the outcome of each policy for each session.

```sql
CREATE TABLE policy_decisions (
    policy_id      INTEGER REFERENCES policies(policy_id),
    session_id     INTEGER REFERENCES sessions(session_id),
    decision       TEXT,   -- 'allow', 'mfa', 'block'
    effective_risk REAL,   -- risk_score used by the policy
    PRIMARY KEY (policy_id, session_id)
);
```

#### 2.1.8 `session_explanations` (optional materialization)

Stores explanation text for each session.

```sql
CREATE TABLE session_explanations (
    session_id        INTEGER PRIMARY KEY REFERENCES sessions(session_id),
    explanations_json TEXT  -- JSON array of short explanation strings
);
```

Alternatively, explanations can be computed on the fly from `session_risk_factors`.

---

## 3. Synthetic Data Generation

Implemented in `src/generate_data.py`.

### 3.1 Volume Targets

* Organizations: ~50
* Users: 5k–20k
* Sessions (last 90 days): 100k–300k
* Events: dependent on sessions (~2–5 events per session)

### 3.2 Organization Generation

* **Segments**:

  * SMB: 50%
  * Mid: 30%
  * Enterprise: 20%
* **Regions**: NA, EU, APAC, etc., distributed across orgs.
* **Created_at**: uniformly or normally distributed over the last ~12 months.

### 3.3 User Generation

For each organization:

* Number of users:

  * SMB: 20–100
  * Mid: 100–500
  * Enterprise: 500–5000
* Roles and privilege:

  * `admin`: 2–5% (privileged)
  * `developer`: 10–20%
  * `employee`: 70–80%
  * `service`: 2–5% (privileged, may behave more anomalously)
* Country:

  * Mostly aligned with org region, with some noise (remote workers, global teams).
* `created_at` distributed over last year.

### 3.4 Session Generation

For each user, simulate sessions over the last 90 days:

* Session counts:

  * Employees: 1–5 logins/day (Poisson per day).
  * Admins: 1–3 logins/day, higher probability on weekdays.
  * Service accounts: machine-like patterns (consistent or bursty depending on design).
* For each session:

  * `started_at`: realistic daily time distribution (peaks at working hours).
  * `device_type`: ~70% desktop, 30% mobile.
  * `ip_country`: usually user’s country, occasionally foreign (travel, VPN).
  * `ip_risk_level`: sample from:

    * low: 80–90%
    * medium: 8–15%
    * high: 2–5%
  * `previous_country`, `previous_device`, `previous_login_at`:

    * from prior successful sessions, if available; otherwise use defaults.

Select a subset of organizations and users to have elevated suspicious activity to create interesting patterns.

### 3.5 Risk Factors and Risk Score

In Python, derive `session_risk_factors`:

* `is_new_country`:

  * `ip_country != previous_country` (with null-safe handling).
* `is_new_device`:

  * `device_type != previous_device` or random “new fingerprint” event.
* `geo_distance_km`:

  * approximate based on country centroids.
* `impossible_travel`:

  * flag if time difference to previous login is too short for travel over `geo_distance_km`.
* `recent_failed_logins`:

  * count of `login_failed` in the last 24 hours for that user.
* `odd_login_hour`:

  * 1 if `started_at` is outside role-specific working hours.
* `ip_reputation_score`:

  * derived from `ip_risk_level` + small noise.

Define a raw risk function (example):

```text
risk_raw =
  1.2 * (ip_risk_level = 'high') +
  0.7 * (ip_risk_level = 'medium') +
  0.8 * is_new_country +
  0.6 * is_new_device +
  1.0 * impossible_travel +
  0.05 * recent_failed_logins +
  0.4 * odd_login_hour +
  1.0 * is_privileged_user
```

Normalize to `[0,1]` via logistic or min-max normalization:

```text
risk_score = 1 / (1 + exp(-normalized_risk_raw))
```

Persist these into `session_risk_factors`.

### 3.6 Policy Definitions

Seed `policies` with 3 variants:

* **Lenient:**

  * `risk_threshold = 0.9`
  * `block_high_risk = FALSE`
  * `mfa_for_admins = TRUE`
  * `mfa_for_new_device = FALSE`
  * `mfa_for_geo_change = FALSE`
* **Balanced:**

  * `risk_threshold = 0.7`
  * `block_high_risk = TRUE`
  * `mfa_for_admins = TRUE`
  * `mfa_for_new_device = TRUE`
  * `mfa_for_geo_change = TRUE`
* **Strict:**

  * `risk_threshold = 0.5`
  * `block_high_risk = TRUE`
  * `mfa_for_admins = TRUE`
  * `mfa_for_new_device = TRUE`
  * `mfa_for_geo_change = TRUE`

Can adjust in `seed_config.yaml`.

### 3.7 Policy Decisions and Events

For each session & policy, apply logic in `policy_engine.py`:

Pseudo-code:

```python
def evaluate_policy(session, risk_factors, policy, user):
    risk = risk_factors.risk_score

    if policy.block_high_risk and risk >= 0.9:
        return "block"

    if risk >= policy.risk_threshold:
        return "mfa"

    if policy.mfa_for_admins and user.is_privileged:
        return "mfa"

    if policy.mfa_for_new_device and risk_factors.is_new_device:
        return "mfa"

    if policy.mfa_for_geo_change and risk_factors.is_new_country:
        return "mfa"

    return "allow"
```

Insert result into `policy_decisions`.

Generate `auth_events` accordingly:

* Always: `login_started`.
* If decision = `"block"`:

  * Add `policy_blocked`.
* If decision = `"mfa"`:

  * Add `mfa_challenge`.
  * With probability `p_success` (e.g., 80–95% depending on risk), add `mfa_success` and `login_success`.
  * Otherwise add `mfa_failed` (and possibly `login_failed`).
* If decision = `"allow"`:

  * Possibly a small chance of `login_failed`, otherwise `login_success`.

---

## 4. Metrics Definitions

Metrics are defined clearly and implemented via SQL views and/or Python helpers.

### 4.1 Time Windows

* Default analysis window: **last 30 days**.
* Options: last 7 days, last 30 days, last 90 days, and custom date range.
* All metrics are computed within the selected window unless stated otherwise.

### 4.2 Security Metrics

**1. High-Risk Session Coverage**

> Fraction of high-risk sessions that were challenged or blocked.

Definitions:

* `high_risk_session = risk_score >= 0.8`

Metric:

```text
coverage =
  (# high-risk sessions with decision in ('mfa', 'block'))
  /
  (# high-risk sessions)
```

**2. Blocked High-Risk Rate**

```text
blocked_high_risk_rate =
  (# high-risk sessions with decision = 'block')
  /
  (# high-risk sessions)
```

**3. Residual Risk Rate**

> High-risk sessions allowed without MFA.

```text
residual_risk_rate =
  (# high-risk sessions with decision = 'allow')
  /
  (# high-risk sessions)
```

**4. Risk Reduction vs Baseline**

Choose a baseline policy (e.g., lenient).

For any other policy:

```text
risk_reduction =
  residual_risk_rate_baseline - residual_risk_rate_current
```

Optionally expressed as percentage of baseline.

### 4.3 Friction Metrics

**1. MFA Prompts per Active User**

```text
mfa_prompts_per_user =
  (# mfa_challenge events)
  /
  (# distinct users with at least one session in the window)
```

**2. MFA Failure Rate**

```text
mfa_failure_rate =
  (# mfa_failed events)
  /
  (# mfa_challenge events)
```

**3. Login Conversion**

```text
login_conversion =
  (# sessions with login_success)
  /
  (# sessions with login_started)
```

Compute the above:

* Globally
* By segment: `segment`, `region`, `role`, `device_type`, etc.

### 4.4 Tradeoff Curves

Define a hypothetical risk threshold grid, e.g. `0.4` to `0.95` in increments of `0.05`.

For each threshold:

* Recompute decisions in memory (Python) using the same logic but with varying `risk_threshold`.
* Compute:

  * `risk_reduction`
  * `mfa_prompts_per_user`

Plot `risk_reduction` vs `mfa_prompts_per_user`. This yields the tradeoff curve.

---

## 5. SQL Metrics Layer

Implemented in `sql/metrics_views.sql`.

### 5.1 Session + Policy View

```sql
CREATE VIEW v_sessions_with_policy AS
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
```

### 5.2 Security Metrics per Policy and Day

```sql
CREATE VIEW v_policy_security_metrics AS
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
```

### 5.3 Events + Policy View

```sql
CREATE VIEW v_events_with_policy AS
SELECT
  e.*,
  v.policy_name,
  v.org_id,
  v.user_id,
  v.segment,
  v.region,
  v.role
FROM auth_events e
JOIN v_sessions_with_policy v ON v.session_id = e.session_id;
```

### 5.4 Friction Metrics per Policy and Day

```sql
CREATE VIEW v_policy_friction_metrics AS
SELECT
  policy_name,
  DATE(created_at) AS date,
  COUNT(*) FILTER (WHERE event_type = 'mfa_challenge') AS mfa_challenges,
  COUNT(*) FILTER (WHERE event_type = 'mfa_failed') AS mfa_failures,
  COUNT(*) FILTER (WHERE event_type = 'login_started') AS logins_started,
  COUNT(*) FILTER (WHERE event_type = 'login_success') AS logins_success
FROM v_events_with_policy
GROUP BY policy_name, DATE(created_at);
```

Further segmented views can be created, e.g. per region or segment, as needed.

---

## 6. Explanation Logic

Implemented in `src/explanations.py`.

### 6.1 Explanation Rules

Given a row with risk factors and user attributes, generate a list of short, human-readable explanations.

Example:

```python
def explain_session(row):
    reasons = []

    if row["ip_risk_level"] == "high":
        reasons.append("IP address from a high-risk network range")
    elif row["ip_risk_level"] == "medium":
        reasons.append("IP address from a moderately risky network range")

    if row["is_new_country"]:
        reasons.append("Login from a new country compared to the last successful login")

    if row["is_new_device"]:
        reasons.append("Login from a new device or browser")

    if row["impossible_travel"]:
        reasons.append("Geographic distance and timing indicate impossible travel")

    if row["recent_failed_logins"] >= 3:
        reasons.append("Multiple failed login attempts in the last 24 hours")

    if row["odd_login_hour"]:
        reasons.append("Login at an unusual time for this role")

    if row["is_privileged"]:
        reasons.append("Privileged account with elevated access")

    if not reasons:
        reasons.append("No major anomalies; risk driven by baseline factors")

    return reasons
```

These can either be:

* Stored in `session_explanations` as JSON, or
* Computed on demand when a session is inspected in the UI.

---

## 7. UI / UX Specification (Streamlit App)

Implemented in `app/app.py`.

### 7.1 Global UI Elements (Sidebar)

Sidebar elements:

* **Policy selector**:

  * Dropdown: `policy_name` values (`lenient`, `balanced`, `strict`).
* **Time window**:

  * Radio: `Last 7 days`, `Last 30 days`, `Last 90 days`, `Custom`.
  * If `Custom`, date range selector.
* **Filter controls**:

  * Segments: multiselect from `segment`.
  * Regions: multiselect from `region`.
  * Roles: multiselect from `role`.
  * Device types: multiselect from `device_type`.

These filters apply across all pages.

### 7.2 Page 1 – Overview (“Security vs Friction”)

Content:

1. **KPI Cards** (top row):

   * Risk Coverage (% of high-risk sessions challenged/blocked)
   * Residual Risk (% of high-risk sessions allowed)
   * MFA Prompts per Active User
   * Login Conversion

2. **Policy Comparison Chart**:

   * Scatter or bubble chart with:

     * X-axis: `mfa_prompts_per_user`
     * Y-axis: `risk_reduction` vs baseline
     * One point per policy (`lenient`, `balanced`, `strict`), labeled.
   * Highlight the currently selected policy.

3. **Time Series Charts**:

   * Chart 1: Risk coverage over time (daily).
   * Chart 2: Login conversion and MFA failure rate over time (dual-axis or separate small charts).

4. **Insight text box**:

   * One panel showing simple textual summaries derived from metrics (e.g., “Strict policy reduces residual risk by X% vs lenient but doubles MFA prompts per user.”).

### 7.3 Page 2 – Policy Threshold Explorer

This page explores hypothetical thresholds beyond the three predefined policies.

Controls:

* Risk threshold slider: range `[0.3, 0.95]` with step `0.05`.
* Toggles:

  * “Always MFA privileged accounts”
  * “MFA for new devices”
  * “MFA for geo changes”
  * “Block sessions with risk >= 0.95”

For each configuration:

* Recompute decisions in memory using all relevant sessions from the DB.
* Compute:

  * High-risk coverage
  * Residual risk
  * MFA prompts per user
  * Login conversion

Visuals:

1. **KPI Cards** for the current slider setting.
2. **Tradeoff Curve**:

   * Precomputed or dynamically computed for a grid of thresholds.
   * X-axis: MFA prompts per user.
   * Y-axis: risk reduction vs baseline.
   * Current slider position highlighted.
3. **Threshold vs Metrics Chart**:

   * Line chart with risk threshold on X-axis and:

     * Risk reduction (%)
     * MFA prompts per user
     * Possibly MFA failure rate

This page demonstrates the continuous tradeoff space.

### 7.4 Page 3 – Session Explorer (“Why was this flagged?”)

Controls:

* Minimum risk score (slider, e.g., 0–1).
* Decision type filter (multiselect: `allow`, `mfa`, `block`).
* Policy selector reused from sidebar or local override.

Main components:

1. **Table of sessions**:

   * Columns:

     * `started_at`
     * `org_name`
     * `segment`
     * `region`
     * `role`
     * `device_type`
     * `risk_score`
     * `decision`
     * `top_explanation` (first explanation joined into a summary string)

2. **Session detail panel** (via expanders or when a row is selected):

   * All risk factor values.
   * Full list of explanations.
   * Underlying events timeline:

     * List of `auth_events` with timestamps and event types.

This page focuses on interpretability and narrative, not just aggregates.

### 7.5 Page 4 – Organization Comparison (Optional but Recommended)

Controls:

* Same global filters (segment, region, etc.).
* Additional threshold for “high friction” indicator (e.g., MFA prompts/user).

Components:

1. **Org summary table**:

   * Columns:

     * `org_name`
     * `segment`
     * `region`
     * `high_risk_coverage`
     * `residual_risk_rate`
     * `mfa_prompts_per_user`
     * `login_conversion`
   * Sortable by any metric.

2. **Scatter plot**:

   * X-axis: MFA prompts per user.
   * Y-axis: residual risk.
   * Points: organizations.
   * Highlight “problematic” orgs:

     * high friction & high residual risk.

3. **Filter presets**:

   * Buttons like:

     * “Show orgs with high friction and low coverage”
     * “Show orgs with low friction and high coverage”

This page supports tenant-level prioritization (who needs onboarding, configuration help, or policy tweaks).

---

## 8. Testing

Basic tests in `tests/test_metrics.py`:

* Unit tests for:

  * Risk score computation (sanity checks on ranges and monotonicity).
  * Policy decision logic:

    * High risk with `block_high_risk = TRUE` leads to `"block"`.
    * Very low risk below threshold leads to `"allow"` when no secondary rules apply.
  * Metrics calculations for small sample data:

    * high-risk coverage,
    * MFA prompts per user,
    * conversion rates.

* Smoke tests for:

  * Data generation (non-empty tables, reasonable distributions).
  * SQL views creation.

---

## 9. Documentation & Report

### 9.1 README

Contents:

* Project description

* Architecture overview

* Setup:

  ```bash
  pip install -r requirements.txt
  python src/generate_data.py      # generates auth_demo.db
  streamlit run app/app.py
  ```

* Screenshots of key UI pages.

* Notes on extensibility.

### 9.2 Product-Style Report (`report/demo_report.md`)

Suggested structure:

1. **Context & Objective**

   * Problem: balancing security and user friction in identity policies.
   * What the tool does and for whom.

2. **Data & Metrics**

   * Short description of synthetic auth data model.
   * Clear definitions of key metrics (coverage, residual risk, friction, conversion).

3. **Key Findings (with charts)**

   * Example charts exported from the app (tradeoff curve, time series).
   * Bullet-point insights derived from these charts.

4. **Recommendations**

   * How a product team might use such a tool:

     * Policy templates per segment.
     * Role-based thresholds.
     * UX improvements for high-friction pockets.
     * Better communication of risk explanations to admins/users.

---

## 10. Future Extensions (Optional)

Potential enhancements:

* Incorporate simple anomaly detection models (e.g., Isolation Forest) on top of risk factors.
* Add simulation of configuration change rollouts over time (policy change “deployments” and pre/post comparisons).
* Introduce separate views for human vs service identities.
* Add experiment/AB-style analysis where different policies are assigned to subsets of orgs and their metrics are compared statistically.