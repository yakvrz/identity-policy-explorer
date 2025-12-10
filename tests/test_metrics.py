import sqlite3
import sys
from datetime import date, datetime
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from metrics import TimeWindow, compute_kpis, policy_comparison
from policy_engine import Policy, evaluate_policy


def setup_memory_db():
    conn = sqlite3.connect(":memory:")
    schema = (BASE_DIR / "sql" / "schema.sql").read_text()
    views = (BASE_DIR / "sql" / "metrics_views.sql").read_text()
    conn.executescript(schema)

    # Seed minimal org/user/policies
    conn.execute(
        "INSERT INTO organizations (org_id, org_name, segment, region, created_at) VALUES (1,'Acme','SMB','NA',?)",
        (datetime.utcnow().isoformat(),),
    )
    conn.execute(
        "INSERT INTO users (user_id, org_id, role, is_privileged, country, created_at) VALUES (1,1,'admin',1,'US',?)",
        (datetime.utcnow().isoformat(),),
    )
    policies = [
        ("lenient", 0.9, 0, 1, 0, 0),
        ("strict", 0.5, 1, 1, 1, 1),
    ]
    for idx, p in enumerate(policies, start=1):
        conn.execute(
            """
            INSERT INTO policies (policy_id, policy_name, risk_threshold, block_high_risk, mfa_for_admins,
                                  mfa_for_new_device, mfa_for_geo_change)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (idx, *p),
        )

    today = datetime.utcnow().date().isoformat()
    sessions = [
        (1, 1, 1, f"{today}T10:00:00", "desktop", "1.1.1.1", "US", "low", "US", "desktop", None),
        (2, 1, 1, f"{today}T12:00:00", "desktop", "2.2.2.2", "US", "high", "US", "desktop", f"{today}T10:00:00"),
    ]
    conn.executemany(
        """
        INSERT INTO sessions (
            session_id, user_id, org_id, started_at, device_type, ip_address,
            ip_country, ip_risk_level, previous_country, previous_device, previous_login_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        sessions,
    )
    risk_rows = [
        (1, 0.1, 0, 0, 0.0, 0, 0, 0, 0.2),
        (2, 0.95, 0, 0, 0.0, 0, 0, 0, 0.95),
    ]
    conn.executemany(
        """
        INSERT INTO session_risk_factors (
            session_id, risk_score, is_new_country, is_new_device, geo_distance_km,
            impossible_travel, recent_failed_logins, odd_login_hour, ip_reputation_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        risk_rows,
    )
    # Decisions: lenient allows both, strict blocks high risk
    conn.executemany(
        "INSERT INTO policy_decisions (policy_id, session_id, decision, effective_risk) VALUES (1, ?, 'allow', ?)",
        [(1, 0.1), (2, 0.95)],
    )
    conn.executemany(
        "INSERT INTO policy_decisions (policy_id, session_id, decision, effective_risk) VALUES (2, ?, ?, ?)",
        [(1, "allow", 0.1), (2, "block", 0.95)],
    )
    # Shared events (canonical timeline)
    events = [
        (1, 1, "login_started", f"{today}T10:00:00"),
        (2, 1, "login_success", f"{today}T10:00:02"),
        (3, 2, "login_started", f"{today}T12:00:00"),
        (4, 2, "login_success", f"{today}T12:00:02"),
    ]
    conn.executemany(
        "INSERT INTO auth_events (event_id, session_id, event_type, created_at) VALUES (?, ?, ?, ?)", events
    )
    conn.executescript(views)
    return conn


def test_policy_logic_blocking():
    policy = Policy(
        policy_id=1,
        policy_name="strict",
        risk_threshold=0.5,
        block_high_risk=True,
        mfa_for_admins=True,
        mfa_for_new_device=True,
        mfa_for_geo_change=True,
    )
    decision = evaluate_policy(
        {"session_id": 2},
        {"risk_score": 0.95, "is_new_device": False, "is_new_country": False},
        policy,
        {"is_privileged": True},
    )
    assert decision == "block"


def test_compute_kpis_and_comparison():
    conn = setup_memory_db()
    window = TimeWindow.last_n_days(1)

    comparison = policy_comparison(conn, window, baseline="lenient")
    lenient_row = comparison[comparison["policy_name"] == "lenient"].iloc[0]
    strict_row = comparison[comparison["policy_name"] == "strict"].iloc[0]

    assert lenient_row["coverage"] == 0.0
    assert strict_row["coverage"] == 1.0
    assert strict_row["risk_reduction_vs_baseline"] > 0

    sessions_df = pd.read_sql_query(
        "SELECT * FROM v_sessions_with_policy WHERE policy_name = 'lenient'", conn, parse_dates=["started_at"]
    )
    events_df = pd.read_sql_query(
        "SELECT * FROM v_events_with_policy WHERE policy_name = 'lenient'", conn, parse_dates=["created_at"]
    )
    kpis = compute_kpis(sessions_df, events_df)
    assert kpis["residual_risk"] == 1.0  # high-risk session allowed
    assert kpis["login_conversion"] == 1.0
