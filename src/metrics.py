from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd

from policy_engine import Policy, evaluate_dataframe

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "auth_demo.db"


@dataclass
class TimeWindow:
    start: date
    end: date

    @classmethod
    def last_n_days(cls, days: int) -> "TimeWindow":
        today = date.today()
        return cls(start=today - timedelta(days=days), end=today)


def _build_filter_clauses(filters: Dict[str, List[str]], alias: Dict[str, str]) -> Tuple[str, List[str]]:
    clauses = []
    params: List[str] = []
    for key, column in alias.items():
        values = filters.get(key)
        if values:
            placeholders = ",".join(["?"] * len(values))
            clauses.append(f"{column} IN ({placeholders})")
            params.extend(values)
    clause_sql = ""
    if clauses:
        clause_sql = " AND " + " AND ".join(clauses)
    return clause_sql, params


def fetch_sessions_for_policy(
    conn,
    policy_name: str,
    window: TimeWindow,
    filters: Optional[Dict[str, List[str]]] = None,
) -> pd.DataFrame:
    filters = filters or {}
    base_query = """
    SELECT v.*, o.org_name
    FROM v_sessions_with_policy v
    JOIN organizations o ON o.org_id = v.org_id
    WHERE v.policy_name = ?
      AND DATE(v.started_at) BETWEEN DATE(?) AND DATE(?)
    """
    params: List = [policy_name, window.start, window.end]
    clause, extra = _build_filter_clauses(
        filters, {"segment": "v.segment", "region": "v.region", "role": "v.role", "device_type": "v.device_type"}
    )
    query = base_query + clause
    params += extra
    return pd.read_sql_query(query, conn, params=params, parse_dates=["started_at"])


def fetch_events_for_policy(
    conn,
    policy_name: str,
    window: TimeWindow,
    filters: Optional[Dict[str, List[str]]] = None,
) -> pd.DataFrame:
    filters = filters or {}
    base_query = """
    SELECT *
    FROM v_events_with_policy
    WHERE policy_name = ?
      AND DATE(created_at) BETWEEN DATE(?) AND DATE(?)
    """
    params: List = [policy_name, window.start, window.end]
    clause, extra = _build_filter_clauses(
        filters, {"segment": "segment", "region": "region", "role": "role", "device_type": "device_type"}
    )
    query = base_query + clause
    params += extra
    return pd.read_sql_query(query, conn, params=params, parse_dates=["created_at"])


def compute_kpis(sessions_df: pd.DataFrame, events_df: pd.DataFrame) -> Dict[str, float]:
    high_risk = sessions_df[sessions_df["risk_score"] >= 0.8]
    high_risk_count = len(high_risk)
    covered = len(high_risk[high_risk["decision"].isin(["mfa", "block"])])
    residual = len(high_risk[high_risk["decision"] == "allow"])

    coverage = covered / high_risk_count if high_risk_count else 0.0
    residual_rate = residual / high_risk_count if high_risk_count else 0.0

    mfa_challenges = events_df[events_df["event_type"] == "mfa_challenge"]
    mfa_failed = events_df[events_df["event_type"] == "mfa_failed"]
    logins_started = events_df[events_df["event_type"] == "login_started"]
    logins_success = events_df[events_df["event_type"] == "login_success"]

    active_users = sessions_df["user_id"].nunique() or 1
    mfa_prompts_per_user = len(mfa_challenges) / active_users
    mfa_failure_rate = len(mfa_failed) / len(mfa_challenges) if len(mfa_challenges) else 0.0
    login_conversion = len(logins_success) / len(logins_started) if len(logins_started) else 0.0

    return {
        "coverage": coverage,
        "residual_risk": residual_rate,
        "mfa_prompts_per_user": mfa_prompts_per_user,
        "mfa_failure_rate": mfa_failure_rate,
        "login_conversion": login_conversion,
    }


def policy_comparison(
    conn, window: TimeWindow, filters: Optional[Dict[str, List[str]]] = None, baseline: str = "lenient"
) -> pd.DataFrame:
    policies = pd.read_sql_query("SELECT policy_name FROM policies", conn)["policy_name"].tolist()
    rows = []
    baseline_metrics = None
    for policy_name in policies:
        sessions_df = fetch_sessions_for_policy(conn, policy_name, window, filters)
        events_df = fetch_events_for_policy(conn, policy_name, window, filters)
        kpis = compute_kpis(sessions_df, events_df)
        if policy_name == baseline:
            baseline_metrics = kpis
        rows.append({"policy_name": policy_name, **kpis})

    df = pd.DataFrame(rows)
    if baseline_metrics:
        df["risk_reduction_vs_baseline"] = baseline_metrics["residual_risk"] - df["residual_risk"]
    else:
        df["risk_reduction_vs_baseline"] = 0.0
    return df


def _load_components(conn, window: TimeWindow, filters: Optional[Dict[str, List[str]]] = None) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    filters = filters or {}
    base_query = """
    SELECT
        s.session_id, s.user_id, s.org_id, s.started_at, s.device_type, s.ip_risk_level,
        rf.risk_score, rf.is_new_device, rf.is_new_country,
        rf.geo_distance_km, rf.impossible_travel, rf.recent_failed_logins, rf.odd_login_hour, rf.ip_reputation_score,
        u.role, u.is_privileged,
        o.segment, o.region, o.org_name
    FROM sessions s
    JOIN session_risk_factors rf ON rf.session_id = s.session_id
    JOIN users u ON u.user_id = s.user_id
    JOIN organizations o ON o.org_id = s.org_id
    WHERE DATE(s.started_at) BETWEEN DATE(?) AND DATE(?)
    """
    params: List = [window.start, window.end]
    clause, extra = _build_filter_clauses(
        filters, {"segment": "o.segment", "region": "o.region", "role": "u.role", "device_type": "s.device_type"}
    )
    query = base_query + clause
    params += extra
    df = pd.read_sql_query(query, conn, params=params, parse_dates=["started_at"])
    sessions_df = df[
        [
            "session_id",
            "user_id",
            "org_id",
            "started_at",
            "device_type",
            "ip_risk_level",
            "segment",
            "region",
            "role",
            "org_name",
        ]
    ]
    risk_df = df[
        [
            "session_id",
            "risk_score",
            "is_new_device",
            "is_new_country",
            "geo_distance_km",
            "impossible_travel",
            "recent_failed_logins",
            "odd_login_hour",
            "ip_reputation_score",
        ]
    ]
    users_df = df[["user_id", "is_privileged"]].drop_duplicates()
    return sessions_df, risk_df, users_df


def summarize_decisions(
    sessions: pd.DataFrame, risk: pd.DataFrame, decisions: pd.DataFrame
) -> Dict[str, float]:
    merged = (
        sessions[["session_id", "user_id", "started_at"]]
        .merge(risk, on="session_id")
        .merge(decisions, on="session_id")
    )

    high_risk = merged[merged["risk_score"] >= 0.8]
    high_risk_count = len(high_risk)
    covered = len(high_risk[high_risk["decision"].isin(["mfa", "block"])])
    residual = len(high_risk[high_risk["decision"] == "allow"])
    coverage = covered / high_risk_count if high_risk_count else 0.0
    residual_rate = residual / high_risk_count if high_risk_count else 0.0

    active_users = merged["user_id"].nunique() or 1
    mfa_count = len(merged[merged["decision"] == "mfa"])
    mfa_prompts_per_user = mfa_count / active_users

    # Simulate expected success probabilities.
    success_probs = []
    mfa_fail_probs = []
    for row in merged.itertuples():
        if row.decision == "block":
            success_probs.append(0.0)
            continue
        if row.decision == "mfa":
            success_prob = max(0.55, 0.95 - row.risk_score * 0.4)
            success_probs.append(success_prob)
            mfa_fail_probs.append(1 - success_prob)
        else:
            success_probs.append(max(0.75, 0.97 - row.risk_score * 0.15))
    login_conversion = sum(success_probs) / len(merged) if len(merged) else 0.0
    mfa_failure_rate = np.mean(mfa_fail_probs) if mfa_fail_probs else 0.0

    return {
        "coverage": coverage,
        "residual_risk": residual_rate,
        "mfa_prompts_per_user": mfa_prompts_per_user,
        "mfa_failure_rate": mfa_failure_rate,
        "login_conversion": login_conversion,
    }


def threshold_metrics(
    conn,
    threshold: float,
    window: TimeWindow,
    filters: Optional[Dict[str, List[str]]] = None,
    toggles: Optional[Dict[str, bool]] = None,
) -> Dict[str, float]:
    toggles = toggles or {}
    sessions, risk_df, users_df = _load_components(conn, window, filters)
    base_policy = Policy(
        policy_id=None,
        policy_name="custom",
        risk_threshold=threshold,
        block_high_risk=toggles.get("block_high_risk", True),
        mfa_for_admins=toggles.get("mfa_for_admins", True),
        mfa_for_new_device=toggles.get("mfa_for_new_device", True),
        mfa_for_geo_change=toggles.get("mfa_for_geo_change", True),
    )
    decisions = evaluate_dataframe(sessions, risk_df, users_df, base_policy)
    return summarize_decisions(sessions, risk_df, decisions)


def tradeoff_curve(
    conn,
    thresholds: Iterable[float],
    window: TimeWindow,
    filters: Optional[Dict[str, List[str]]] = None,
    base_toggles: Optional[Dict[str, bool]] = None,
) -> pd.DataFrame:
    base_toggles = base_toggles or {}
    sessions, risk_df, users_df = _load_components(conn, window, filters)
    rows = []
    for t in thresholds:
        policy = Policy(
            policy_id=None,
            policy_name=f"threshold_{t:.2f}",
            risk_threshold=t,
            block_high_risk=base_toggles.get("block_high_risk", True),
            mfa_for_admins=base_toggles.get("mfa_for_admins", True),
            mfa_for_new_device=base_toggles.get("mfa_for_new_device", True),
            mfa_for_geo_change=base_toggles.get("mfa_for_geo_change", True),
        )
        decisions = evaluate_dataframe(sessions, risk_df, users_df, policy)
        metrics = summarize_decisions(sessions, risk_df, decisions)
        rows.append({"threshold": t, **metrics})
    return pd.DataFrame(rows)


def sessions_table(
    conn,
    policy_name: str,
    window: TimeWindow,
    min_risk: float = 0.0,
    decisions: Optional[List[str]] = None,
    filters: Optional[Dict[str, List[str]]] = None,
    limit: int = 200,
) -> pd.DataFrame:
    filters = filters or {}
    decision_clause = ""
    params: List = [policy_name, window.start, window.end, min_risk]
    if decisions:
        placeholders = ",".join(["?"] * len(decisions))
        decision_clause = f" AND pd.decision IN ({placeholders})"
        params.extend(decisions)

    base_query = f"""
    SELECT
        s.session_id, s.started_at, o.org_name, o.segment, o.region, u.role, s.device_type,
        rf.risk_score, pd.decision, rf.is_new_country, rf.is_new_device, rf.impossible_travel,
        rf.recent_failed_logins, rf.odd_login_hour,
        COALESCE(se.explanations_json, '[]') AS explanations_json
    FROM policy_decisions pd
    JOIN policies p ON p.policy_id = pd.policy_id
    JOIN sessions s ON s.session_id = pd.session_id
    JOIN session_risk_factors rf ON rf.session_id = s.session_id
    JOIN users u ON u.user_id = s.user_id
    JOIN organizations o ON o.org_id = s.org_id
    LEFT JOIN session_explanations se ON se.session_id = s.session_id
    WHERE p.policy_name = ?
      AND DATE(s.started_at) BETWEEN DATE(?) AND DATE(?)
      AND rf.risk_score >= ?
    {decision_clause}
    """
    clause, extra = _build_filter_clauses(
        filters, {"segment": "o.segment", "region": "o.region", "role": "u.role", "device_type": "s.device_type"}
    )
    query = base_query + clause + " ORDER BY s.started_at DESC LIMIT ?"
    params += extra
    params.append(limit)
    return pd.read_sql_query(query, conn, params=params, parse_dates=["started_at"])


def org_summary(
    conn,
    policy_name: str,
    window: TimeWindow,
    filters: Optional[Dict[str, List[str]]] = None,
) -> pd.DataFrame:
    filters = filters or {}
    sessions_df = fetch_sessions_for_policy(conn, policy_name, window, filters)
    events_df = fetch_events_for_policy(conn, policy_name, window, filters)
    events_df["date"] = events_df["created_at"].dt.date

    # Aggregate per org
    summary_rows = []
    for org_id, org_sessions in sessions_df.groupby("org_id"):
        org_events = events_df[events_df["org_id"] == org_id]
        metrics = compute_kpis(org_sessions, org_events)
        summary_rows.append(
            {
                "org_id": org_id,
                "org_name": org_sessions["org_name"].iloc[0],
                "segment": org_sessions["segment"].iloc[0],
                "region": org_sessions["region"].iloc[0],
                **metrics,
            }
        )

    df = pd.DataFrame(summary_rows)
    return df.sort_values("residual_risk", ascending=True)
