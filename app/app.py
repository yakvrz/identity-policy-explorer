import json
import io
import sqlite3
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import sys

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

from metrics import (
    TimeWindow,
    compute_kpis,
    fetch_events_for_policy,
    fetch_sessions_for_policy,
    org_summary,
    policy_comparison,
    sessions_table,
    threshold_metrics,
    tradeoff_curve,
)
from generate_data import generate_dataset, create_views

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "auth_demo.db"
CONFIG_PATH = Path(__file__).resolve().parent.parent / "data" / "seed_config.yaml"


st.set_page_config(
    page_title="Identity Policy Explorer",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_resource
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    # Ensure views exist (idempotent).
    try:
        create_views(conn)
    except Exception as exc:
        st.warning(f"Failed to refresh views: {exc}")
    return conn


@st.cache_data
def load_policy_names(_conn) -> List[str]:
    df = pd.read_sql_query("SELECT policy_name FROM policies", _conn)
    return df["policy_name"].tolist()


@st.cache_data
def load_filter_options(_conn) -> Dict[str, List[str]]:
    segments = pd.read_sql_query("SELECT DISTINCT segment FROM organizations", _conn)["segment"].dropna().tolist()
    regions = pd.read_sql_query("SELECT DISTINCT region FROM organizations", _conn)["region"].dropna().tolist()
    roles = pd.read_sql_query("SELECT DISTINCT role FROM users", _conn)["role"].dropna().tolist()
    device_types = pd.read_sql_query("SELECT DISTINCT device_type FROM sessions", _conn)["device_type"].dropna().tolist()
    return {"segment": segments, "region": regions, "role": roles, "device_type": device_types}


def ensure_db():
    regenerate = False
    if not DB_PATH.exists():
        regenerate = True
    else:
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM sessions")
            count = cur.fetchone()[0]
            conn.close()
            if count == 0:
                regenerate = True
        except Exception:
            regenerate = True

    if regenerate:
        st.info("Generating synthetic authentication dataset...")
        generate_dataset(CONFIG_PATH, DB_PATH, force=True)
        st.cache_data.clear()
        st.cache_resource.clear()


def get_time_window(selection: str, custom_range: Optional[List[date]] = None) -> TimeWindow:
    today = date.today()
    if selection == "Last 7 days":
        return TimeWindow(today - timedelta(days=7), today)
    if selection == "Last 30 days":
        return TimeWindow(today - timedelta(days=30), today)
    if selection == "Last 90 days":
        return TimeWindow(today - timedelta(days=90), today)
    if custom_range and len(custom_range) == 2:
        return TimeWindow(custom_range[0], custom_range[1])
    return TimeWindow(today - timedelta(days=30), today)


def render_data_health(conn):
    try:
        cur = conn.cursor()
        sessions = cur.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        users = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        orgs = cur.execute("SELECT COUNT(*) FROM organizations").fetchone()[0]
        generated_at = date.fromtimestamp(DB_PATH.stat().st_mtime)
        st.caption(f"Data: {sessions:,} sessions • {users:,} users • {orgs} orgs • generated {generated_at}")
    except Exception:
        st.caption("Data status unavailable.")


def sidebar_filters(conn):
    st.sidebar.title("Controls")
    policies = load_policy_names(conn)
    policy = st.sidebar.selectbox("Policy", policies, index=1 if "balanced" in policies else 0)

    window_choice = st.sidebar.radio("Time window", ["Last 7 days", "Last 30 days", "Last 90 days", "Custom"], index=1)
    custom_range = None
    if window_choice == "Custom":
        custom_range = st.sidebar.date_input("Custom range", [date.today() - timedelta(days=30), date.today()])
    window = get_time_window(window_choice, custom_range)

    options = load_filter_options(conn)
    filters = {}
    filters["segment"] = st.sidebar.multiselect("Segments", options["segment"])
    filters["region"] = st.sidebar.multiselect("Regions", options["region"])
    filters["role"] = st.sidebar.multiselect("Roles", options["role"])
    filters["device_type"] = st.sidebar.multiselect("Device types", options["device_type"])

    st.sidebar.markdown("**Quick cohorts**")
    if st.sidebar.checkbox("Privileged accounts (admin/service)"):
        filters["role"] = ["admin", "service"]
    if st.sidebar.checkbox("Enterprise only"):
        filters["segment"] = ["Enterprise"]
    if st.sidebar.checkbox("Higher-risk regions (LATAM/MEA)"):
        filters["region"] = ["LATAM", "MEA"]
    if st.sidebar.checkbox("Mobile devices"):
        filters["device_type"] = ["mobile"]

    filters = {k: v for k, v in filters.items() if v}

    if st.sidebar.button("Regenerate dataset"):
        generate_dataset(CONFIG_PATH, DB_PATH, force=True)
        st.cache_resource.clear()
        st.cache_data.clear()
        st.experimental_rerun()

    page = st.sidebar.radio("Page", ["Overview", "Threshold Explorer", "Session Explorer", "Org Comparison"])
    return policy, window, filters, page


def render_kpi_cards(kpis: Dict[str, float], cols=None, deltas: Optional[Dict[str, float]] = None):
    labels = {
        "coverage": "Risk Coverage",
        "residual_risk": "Residual Risk",
        "mfa_prompts_per_user": "MFA Prompts / User",
        "login_conversion": "Login Conversion",
    }
    fmt = {
        "coverage": "{:.1%}",
        "residual_risk": "{:.1%}",
        "mfa_prompts_per_user": "{:.2f}",
        "login_conversion": "{:.1%}",
    }
    columns = cols or st.columns(4)
    keys = ["coverage", "residual_risk", "mfa_prompts_per_user", "login_conversion"]
    for col, key in zip(columns, keys):
        delta_val = None
        if deltas and key in deltas:
            delta_val = deltas[key]
            delta_val = f"{delta_val:+.1%}" if key != "mfa_prompts_per_user" else f"{delta_val:+.2f}"
        col.metric(labels[key], fmt[key].format(kpis.get(key, 0.0)), delta=delta_val)


def summarize_segments(sessions_df: pd.DataFrame, events_df: pd.DataFrame) -> List[str]:
    if sessions_df.empty or "segment" not in sessions_df.columns:
        return []
    rows = []
    for seg, seg_sessions in sessions_df.groupby("segment"):
        seg_events = events_df[events_df["segment"] == seg] if "segment" in events_df.columns else events_df
        k = compute_kpis(seg_sessions, seg_events)
        rows.append((seg, k))
    if not rows:
        return []
    top_residual = max(rows, key=lambda r: r[1]["residual_risk"])
    top_friction = max(rows, key=lambda r: r[1]["mfa_prompts_per_user"])
    insights = [
        f"Highest residual risk in {top_residual[0]} ({top_residual[1]['residual_risk']:.0%}); consider tighter thresholds there.",
        f"Most friction in {top_friction[0]} ({top_friction[1]['mfa_prompts_per_user']:.2f} MFA/user); check false positives.",
    ]
    return insights


def insight_banner(policy_name: str, selected_row: pd.Series, baseline_row: Optional[pd.Series]) -> None:
    bullets = []
    if baseline_row is not None:
        coverage_delta = selected_row["coverage"] - baseline_row["coverage"]
        risk_delta = baseline_row["residual_risk"] - selected_row["residual_risk"]
        mfa_delta = selected_row["mfa_prompts_per_user"] - baseline_row["mfa_prompts_per_user"]
        bullets.append(
            f"{policy_name.title()} covers {selected_row['coverage']:.0%} of high-risk sessions ({coverage_delta:+.0%} vs lenient)."
        )
        bullets.append(
            f"Residual risk {selected_row['residual_risk']:.0%} (improvement {risk_delta:+.0%} vs lenient); MFA load {selected_row['mfa_prompts_per_user']:.2f} ({mfa_delta:+.2f})."
        )
        bullets.append(f"Conversion holds at {selected_row['login_conversion']:.0%}.")
    else:
        bullets.append(f"{policy_name.title()} coverage {selected_row['coverage']:.0%}, residual {selected_row['residual_risk']:.0%}.")
    st.info(" • ".join(bullets))


def build_timeseries(sessions_df: pd.DataFrame, events_df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    sessions_df["date"] = sessions_df["started_at"].dt.date
    events_df["date"] = events_df["created_at"].dt.date

    sec_rows = []
    for day, group in sessions_df.groupby("date"):
        kpis = compute_kpis(group, events_df[events_df["date"] == day])
        sec_rows.append({"date": day, **kpis})
    sec_df = pd.DataFrame(sec_rows).sort_values("date")

    # Friction metrics time series
    return {"security": sec_df}


def risk_band(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.8:
        return "high"
    if score >= 0.6:
        return "elevated"
    if score >= 0.4:
        return "medium"
    return "low"


def concise_summary(row: pd.Series) -> str:
    reasons = json.loads(row["explanations_json"]) if row.get("explanations_json") else []
    key_reasons = "; ".join(reasons[:2]) if reasons else "No major anomalies"
    return f"{risk_band(row['risk_score']).title()} risk; {row['decision']} → {key_reasons}"


def verdict_sentence(row: pd.Series) -> str:
    reasons = json.loads(row["explanations_json"]) if row.get("explanations_json") else []
    top_reason = "; ".join(reasons[:3]) if reasons else "Baseline factors"
    if row["decision"] == "block":
        return f"Blocked due to {top_reason} (risk {row['risk_score']:.2f})."
    if row["decision"] == "mfa":
        return f"MFA challenged because {top_reason} (risk {row['risk_score']:.2f})."
    return f"Allowed with monitoring; {top_reason} (risk {row['risk_score']:.2f})."


def factor_bullets(detail: pd.Series) -> List[str]:
    bullets = []
    if detail.get("is_new_country"):
        bullets.append("New country vs last login")
    if detail.get("is_new_device"):
        bullets.append("New device/browser fingerprint")
    if detail.get("impossible_travel"):
        bullets.append("Impossible travel flagged")
    if detail.get("recent_failed_logins", 0) >= 3:
        bullets.append(f"{detail['recent_failed_logins']} failed logins in last 24h")
    if detail.get("odd_login_hour"):
        bullets.append("Unusual login hour for this role")
    if "ip_reputation_score" in detail:
        bullets.append(f"IP reputation score {detail['ip_reputation_score']:.2f}")
    else:
        bullets.append(f"Overall risk score {detail.get('risk_score', 0):.2f}")
    return bullets


def overview_page(conn, policy: str, window: TimeWindow, filters: Dict):
    sessions_df = fetch_sessions_for_policy(conn, policy, window, filters)
    events_df = fetch_events_for_policy(conn, policy, window, filters)
    if sessions_df.empty:
        st.warning("No sessions match the selected filters/time window.")
        return

    comparison_df = policy_comparison(conn, window, filters)
    baseline_row_df = comparison_df[comparison_df["policy_name"] == "lenient"]
    baseline_row = baseline_row_df.iloc[0] if not baseline_row_df.empty else None
    selected_row = comparison_df[comparison_df["policy_name"] == policy].iloc[0]

    kpis = compute_kpis(sessions_df, events_df)
    deltas = {}
    if baseline_row is not None:
        deltas = {
            "coverage": selected_row["coverage"] - baseline_row["coverage"],
            "residual_risk": selected_row["residual_risk"] - baseline_row["residual_risk"],
            "mfa_prompts_per_user": selected_row["mfa_prompts_per_user"] - baseline_row["mfa_prompts_per_user"],
            "login_conversion": selected_row["login_conversion"] - baseline_row["login_conversion"],
        }

    st.subheader("Key Metrics vs Lenient Baseline")
    render_kpi_cards(kpis, deltas=deltas)
    insight_banner(policy, selected_row, baseline_row)

    st.subheader("Policy Tradeoff")
    fig = px.scatter(
        comparison_df,
        x="mfa_prompts_per_user",
        y="risk_reduction_vs_baseline",
        color="policy_name",
        size="coverage",
        hover_data={"residual_risk": ":.2%", "coverage": ":.2%"},
        labels={"mfa_prompts_per_user": "MFA prompts per user", "risk_reduction_vs_baseline": "Risk reduction vs baseline"},
    )
    fig.update_traces(marker=dict(size=14, line=dict(width=1, color="DarkSlateGrey")))
    st.plotly_chart(fig, use_container_width=True)

    ts = build_timeseries(sessions_df, events_df)
    st.subheader("Time Series")
    coverage_fig = px.line(
        ts["security"],
        x="date",
        y=["coverage", "residual_risk"],
        labels={"value": "Rate", "date": "Date", "variable": "Metric"},
    )
    st.plotly_chart(coverage_fig, use_container_width=True)

    friction_fig = px.line(
        ts["security"],
        x="date",
        y=["login_conversion", "mfa_failure_rate"],
        labels={"value": "Rate", "variable": "Metric", "date": "Date"},
    )
    st.plotly_chart(friction_fig, use_container_width=True)

    segment_notes = summarize_segments(sessions_df, events_df)
    if segment_notes:
        st.subheader("Highlights")
        for note in segment_notes:
            st.write(f"• {note}")


def threshold_page(conn, window: TimeWindow, filters: Dict):
    st.header("Policy Threshold Explorer")
    col1, col2 = st.columns([2, 3])
    with col1:
        threshold = st.slider("Risk threshold", 0.3, 0.95, 0.7, 0.05)
        mfa_admins = st.checkbox("Always MFA privileged accounts", value=True)
        mfa_new_device = st.checkbox("MFA for new devices", value=True)
        mfa_geo = st.checkbox("MFA for geo changes", value=True)
        block_high = st.checkbox("Block risk >= 0.95", value=True)
    toggles = {
        "mfa_for_admins": mfa_admins,
        "mfa_for_new_device": mfa_new_device,
        "mfa_for_geo_change": mfa_geo,
        "block_high_risk": block_high,
    }

    metrics = threshold_metrics(conn, threshold, window, filters, toggles)

    st.subheader("Current Configuration")
    st.markdown(
        f"Threshold **{threshold:.2f}** | Block ≥0.95: **{block_high}** | MFA privileged: **{mfa_admins}** | "
        f"MFA new device: **{mfa_new_device}** | MFA geo change: **{mfa_geo}**"
    )
    render_kpi_cards(metrics)

    baseline_df = policy_comparison(conn, window, filters)
    baseline_row_df = baseline_df[baseline_df["policy_name"] == "lenient"]
    baseline_residual = baseline_row_df["residual_risk"].iloc[0] if not baseline_row_df.empty else 0.0
    baseline_row = baseline_row_df.iloc[0] if not baseline_row_df.empty else None
    tradeoff_df = tradeoff_curve(conn, np.arange(0.4, 0.96, 0.05), window, filters, toggles)
    tradeoff_df["risk_reduction_vs_baseline"] = baseline_residual - tradeoff_df["residual_risk"]
    tradeoff_df["score"] = tradeoff_df["risk_reduction_vs_baseline"] - tradeoff_df["mfa_prompts_per_user"] * 0.3
    knee_row = tradeoff_df.loc[tradeoff_df["score"].idxmax()]

    st.subheader("Tradeoff Curve")
    trade_fig = px.scatter(
        tradeoff_df,
        x="mfa_prompts_per_user",
        y="risk_reduction_vs_baseline",
        color="threshold",
        color_continuous_scale="Blues",
        labels={"mfa_prompts_per_user": "MFA prompts per user", "risk_reduction_vs_baseline": "Risk reduction vs baseline"},
    )
    trade_fig.add_annotation(
        x=knee_row["mfa_prompts_per_user"],
        y=knee_row["risk_reduction_vs_baseline"],
        text=f"Knee ~{knee_row['threshold']:.2f}",
        showarrow=True,
        arrowhead=2,
    )
    st.plotly_chart(trade_fig, use_container_width=True)

    lines_df = tradeoff_df.sort_values("threshold")
    line_fig = px.line(
        lines_df,
        x="threshold",
        y=["coverage", "residual_risk", "mfa_prompts_per_user"],
        labels={"value": "Value", "variable": "Metric", "threshold": "Risk threshold"},
    )
    st.plotly_chart(line_fig, use_container_width=True)

    snapshot = (
        f"Threshold {threshold:.2f} → coverage {metrics['coverage']:.0%}, residual {metrics['residual_risk']:.0%}, "
        f"MFA/user {metrics['mfa_prompts_per_user']:.2f}, conversion {metrics['login_conversion']:.0%}."
        f" Suggested knee: {knee_row['threshold']:.2f}."
    )
    st.info(snapshot)

    csv_buf = io.StringIO()
    tradeoff_df.to_csv(csv_buf, index=False)
    st.download_button("Download tradeoff data (CSV)", data=csv_buf.getvalue(), file_name="tradeoff_curve.csv")


def session_page(conn, policy: str, window: TimeWindow, filters: Dict):
    st.header("Session Explorer")
    min_risk = st.slider("Minimum risk score", 0.0, 1.0, 0.6, 0.05)
    decision_filter = st.multiselect("Decision type", ["allow", "mfa", "block"], default=["mfa", "block", "allow"])
    df = sessions_table(conn, policy, window, min_risk, decision_filter, filters, limit=300)
    if df.empty:
        st.info("No sessions match the selected filters.")
        return
    df["summary"] = df.apply(concise_summary, axis=1)
    df["risk_band"] = df["risk_score"].apply(risk_band)

    st.markdown("**Quick filters**")
    col_a, col_b = st.columns(2)
    with col_a:
        high_risk_only = st.checkbox("Only high-risk (≥0.8)")
    with col_b:
        residual_only = st.checkbox("Residual risk (high-risk allowed)")
    if high_risk_only:
        df = df[df["risk_score"] >= 0.8]
    if residual_only:
        df = df[(df["risk_score"] >= 0.8) & (df["decision"] == "allow")]
    if df.empty:
        st.info("No sessions match the selected filters.")
        return

    display_cols = [
        "started_at",
        "org_name",
        "segment",
        "region",
        "role",
        "device_type",
        "risk_band",
        "decision",
        "summary",
    ]
    st.dataframe(df[display_cols], use_container_width=True, hide_index=True)

    selected_session = st.selectbox("Inspect session", df["session_id"].tolist())
    detail = df[df["session_id"] == selected_session].iloc[0]

    st.subheader(f"Decision: {detail['decision'].upper()} • Risk {detail['risk_score']:.2f} ({risk_band(detail['risk_score'])})")
    st.write(verdict_sentence(detail))

    cols = st.columns(2)
    with cols[0]:
        st.markdown("**Why it was flagged**")
        for bullet in factor_bullets(detail):
            st.write(f"• {bullet}")
    with cols[1]:
        st.markdown("**Context**")
        st.write(f"Org: {detail['org_name']} ({detail['segment']}, {detail['region']})")
        st.write(f"Role: {detail['role']} • Device: {detail['device_type']}")

    events = pd.read_sql_query(
        """
        SELECT event_type, created_at
        FROM v_events_with_policy
        WHERE session_id = ? AND policy_name = ?
        ORDER BY created_at
        """,
        conn,
        params=[selected_session, policy],
        parse_dates=["created_at"],
    )
    if not events.empty:
        events["delta_s"] = (events["created_at"] - events["created_at"].min()).dt.total_seconds().astype(int)
        label_map = {
            "login_started": "Login started",
            "mfa_challenge": "MFA challenge",
            "mfa_success": "MFA success",
            "mfa_failed": "MFA failed",
            "login_success": "Login success",
            "login_failed": "Login failed",
            "policy_blocked": "Policy blocked",
        }
        events["label"] = events["event_type"].map(label_map).fillna(events["event_type"])
        st.subheader("Events Timeline")
        st.dataframe(events[["created_at", "delta_s", "label"]], hide_index=True, use_container_width=True)
    else:
        st.info("No events recorded for this session/policy (possible if filtered out or blocked before events).")


def org_page(conn, policy: str, window: TimeWindow, filters: Dict):
    st.header("Organization Comparison")
    df = org_summary(conn, policy, window, filters)
    if df.empty:
        st.warning("No org-level data available for the selected filters.")
        return

    friction_cut = df["mfa_prompts_per_user"].median()
    residual_cut = df["residual_risk"].median()

    def quadrant(row):
        high_friction = row["mfa_prompts_per_user"] >= friction_cut
        high_resid = row["residual_risk"] >= residual_cut
        if high_friction and high_resid:
            return "High friction & residual"
        if high_resid:
            return "Risky but low friction"
        if high_friction:
            return "High friction but safer"
        return "Optimized"

    df["quadrant"] = df.apply(quadrant, axis=1)

    st.subheader("Org table")
    st.dataframe(df, use_container_width=True, hide_index=True)

    scatter = px.scatter(
        df,
        x="mfa_prompts_per_user",
        y="residual_risk",
        color="quadrant",
        hover_name="org_name",
        labels={"mfa_prompts_per_user": "MFA prompts per user", "residual_risk": "Residual risk"},
    )
    scatter.add_hline(y=residual_cut, line_dash="dot", line_color="gray")
    scatter.add_vline(x=friction_cut, line_dash="dot", line_color="gray")
    st.plotly_chart(scatter, use_container_width=True)

    problem_orgs = df[df["quadrant"] == "High friction & residual"].sort_values(
        ["residual_risk", "mfa_prompts_per_user"], ascending=False
    )
    if not problem_orgs.empty:
        st.subheader("Playbook targets")
        names = problem_orgs.head(5)["org_name"].tolist()
        st.write(
            "High friction and high residual risk: "
            + ", ".join(names)
            + ". Playbook: lower threshold slightly, enforce privileged MFA, simplify MFA UX."
        )
    else:
        st.success("No orgs in high-friction/high-residual quadrant for this view.")


def main():
    ensure_db()
    conn = get_conn()
    policy, window, filters, page = sidebar_filters(conn)

    st.title("Identity Security Policy Tradeoff Explorer")
    st.caption("Explore the balance between risk reduction and user friction across adaptive auth policies.")
    render_data_health(conn)

    if page == "Overview":
        overview_page(conn, policy, window, filters)
    elif page == "Threshold Explorer":
        threshold_page(conn, window, filters)
    elif page == "Session Explorer":
        session_page(conn, policy, window, filters)
    else:
        org_page(conn, policy, window, filters)


if __name__ == "__main__":
    main()
