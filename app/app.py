import json
import io
import sqlite3
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import sys

# Ensure src is in path
ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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

# --- CONFIGURATION & STYLING ---
st.set_page_config(
    page_title="Identity Policy Explorer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for KPI cards and layout tightness
st.markdown("""
<style>
    .stMetric {
        background-color: #f9f9f9;
        border: 1px solid #e0e0e0;
        padding: 15px;
        border-radius: 8px;
    }
    [data-testid="stMetricDelta"] > svg {
        display: none;
    }
    .block-container {
        padding-top: 2rem;
    }
</style>
""", unsafe_allow_html=True)


# --- DATA LOADING & CACHING ---

@st.cache_resource
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        create_views(conn)
    except Exception as exc:
        st.warning(f"View refresh warning: {exc}")
    return conn

@st.cache_data
def load_metadata(_conn) -> Dict:
    policies = pd.read_sql_query("SELECT policy_name FROM policies", _conn)["policy_name"].tolist()
    segments = pd.read_sql_query("SELECT DISTINCT segment FROM organizations", _conn)["segment"].dropna().tolist()
    regions = pd.read_sql_query("SELECT DISTINCT region FROM organizations", _conn)["region"].dropna().tolist()
    roles = pd.read_sql_query("SELECT DISTINCT role FROM users", _conn)["role"].dropna().tolist()
    device_types = pd.read_sql_query("SELECT DISTINCT device_type FROM sessions", _conn)["device_type"].dropna().tolist()
    return {
        "policies": policies,
        "segments": segments,
        "regions": regions,
        "roles": roles,
        "device_types": device_types
    }

def ensure_db():
    if not DB_PATH.exists():
        st.info("⚡ Generating synthetic authentication dataset... (this happens once)")
        generate_dataset(CONFIG_PATH, DB_PATH, force=True)
        st.cache_data.clear()
        st.experimental_rerun()

# --- HELPER FUNCTIONS ---

def get_time_window(selection: str, custom_range: Optional[List[date]] = None) -> TimeWindow:
    today = date.today()
    if selection == "Last 7 days":
        return TimeWindow(today - timedelta(days=7), today)
    if selection == "Last 90 days":
        return TimeWindow(today - timedelta(days=90), today)
    return TimeWindow(today - timedelta(days=30), today) # Default 30

def render_kpi_row(kpis: Dict[str, float], deltas: Optional[Dict[str, float]] = None):
    cols = st.columns(4)
    
    # 1. Coverage
    delta_cov = f"{deltas['coverage']:+.1%}" if deltas else None
    cols[0].metric(
        "Risk Coverage", 
        f"{kpis['coverage']:.1%}", 
        delta=delta_cov, 
        help="% of high-risk sessions challenged or blocked"
    )

    # 2. Residual Risk
    delta_res = f"{deltas['residual_risk']:+.1%}" if deltas else None
    # Invert color for risk (red is bad, so +increase should be red)
    cols[1].metric(
        "Residual Risk", 
        f"{kpis['residual_risk']:.1%}", 
        delta=delta_res,
        delta_color="inverse",
        help="% of high-risk sessions allowed through"
    )

    # 3. Friction
    delta_mfa = f"{deltas['mfa_prompts_per_user']:+.2f}" if deltas else None
    cols[2].metric(
        "MFA Prompts / User", 
        f"{kpis['mfa_prompts_per_user']:.2f}", 
        delta=delta_mfa,
        delta_color="inverse",
        help="Average MFA challenges per active user"
    )

    # 4. Conversion
    delta_conv = f"{deltas['login_conversion']:+.1%}" if deltas else None
    cols[3].metric(
        "Login Success Rate", 
        f"{kpis['login_conversion']:.1%}", 
        delta=delta_conv,
        help="Successful logins / Total attempts"
    )

def risk_band(score: float) -> str:
    if score >= 0.9: return "Critical"
    if score >= 0.8: return "High"
    if score >= 0.6: return "Elevated"
    if score >= 0.4: return "Medium"
    return "Low"

# --- PAGE: OVERVIEW ---
def page_overview(conn, policy: str, window: TimeWindow, filters: Dict):
    st.title(f"📊 Executive Dashboard: {policy.title()}")
    
    # Fetch Data
    with st.spinner("Crunching numbers..."):
        sessions_df = fetch_sessions_for_policy(conn, policy, window, filters)
        events_df = fetch_events_for_policy(conn, policy, window, filters)
        
    if sessions_df.empty:
        st.warning("No data found for these filters.")
        return

    # Comparative Metrics
    comparison_df = policy_comparison(conn, window, filters)
    current_metrics = compute_kpis(sessions_df, events_df)
    baseline_policy = "lenient"
    baseline_row_df = comparison_df[comparison_df["policy_name"] == baseline_policy]
    baseline_row = baseline_row_df.iloc[0] if not baseline_row_df.empty else None
    
    deltas = None
    if baseline_row is not None:
        deltas = {
            "coverage": current_metrics["coverage"] - baseline_row["coverage"],
            "residual_risk": current_metrics["residual_risk"] - baseline_row["residual_risk"],
            "mfa_prompts_per_user": current_metrics["mfa_prompts_per_user"] - baseline_row["mfa_prompts_per_user"],
            "login_conversion": current_metrics["login_conversion"] - baseline_row["login_conversion"],
        }

    render_kpi_row(current_metrics, deltas)
    if baseline_row is not None:
        st.caption(f"Deltas compared to baseline '{baseline_policy}' policy.")
    else:
        st.caption("Baseline policy not available; showing absolute values.")
    
    tab_main, tab_friction, tab_details = st.tabs(["🛡️ Security Posture", "🚦 User Friction", "📈 Detailed Trends"])

    with tab_main:
        col1, col2 = st.columns([2, 1])
        with col1:
            st.subheader("Policy Performance vs. Industry Baseline")
            fig = px.scatter(
                comparison_df,
                x="mfa_prompts_per_user",
                y="risk_reduction_vs_baseline",
                color="policy_name",
                size="coverage",
                text="policy_name",
                hover_data={"residual_risk": ":.2%", "coverage": ":.2%"},
                labels={
                    "mfa_prompts_per_user": "User Friction (MFA/User)", 
                    "risk_reduction_vs_baseline": "Security Gain (Risk Reduction)"
                },
                height=400
            )
            fig.update_traces(textposition='top center', marker=dict(size=25, line=dict(width=2, color='DarkSlateGrey')))
            # Add "Ideal Quadrant" background
            fig.add_shape(type="rect",
                x0=0, y0=0.5, x1=1.0, y1=1.0,
                fillcolor="Green", opacity=0.1, layer="below", line_width=0,
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Risk Distribution")
            risk_counts = sessions_df['ip_risk_level'].value_counts().reset_index()
            fig_donut = px.pie(risk_counts, values='count', names='ip_risk_level', hole=0.4, 
                               color='ip_risk_level', 
                               color_discrete_map={'high':'red', 'medium':'orange', 'low':'green'})
            st.plotly_chart(fig_donut, use_container_width=True)

    with tab_friction:
        # Time series for friction
        events_df["date"] = events_df["created_at"].dt.date
        daily_stats = events_df.groupby(["date", "event_type"]).size().unstack(fill_value=0).reset_index()
        
        if "mfa_challenge" in daily_stats.columns:
            st.subheader("MFA Volume Over Time")
            fig_area = px.area(daily_stats, x="date", y="mfa_challenge", title="Daily MFA Challenges")
            st.plotly_chart(fig_area, use_container_width=True)
        else:
            st.info("No MFA events in this period.")

    with tab_details:
        st.dataframe(comparison_df.style.format({
            "coverage": "{:.1%}",
            "residual_risk": "{:.1%}",
            "mfa_prompts_per_user": "{:.2f}"
        }), use_container_width=True)

# --- PAGE: THRESHOLD EXPLORER ---
def page_thresholds(conn, window: TimeWindow, filters: Dict):
    st.title("🎚️ Policy Tradeoff Simulator")
    st.markdown("Use this tool to find the 'sweet spot' between blocking bad actors and annoying legitimate users.")
    
    col_controls, col_viz = st.columns([1, 3])
    
    with col_controls:
        with st.container(border=True):
            st.subheader("Configuration")
            threshold = st.slider("Risk Threshold", 0.3, 0.95, 0.7, 0.05, 
                                  help="Sessions with risk score above this will be challenged.")
            
            st.markdown("**Triggers**")
            toggles = {
                "mfa_for_admins": st.checkbox("Admin MFA", value=True),
                "mfa_for_new_device": st.checkbox("New Device MFA", value=True),
                "mfa_for_geo_change": st.checkbox("Geo Change MFA", value=True),
                "block_high_risk": st.checkbox("Block Critical (>0.95)", value=True),
            }
            
            # Real-time computation
            metrics = threshold_metrics(conn, threshold, window, filters, toggles)
            
            st.divider()
            st.markdown(f"### Predicted Outcome")
            st.metric("Coverage", f"{metrics['coverage']:.1%}")
            st.metric("MFA/User", f"{metrics['mfa_prompts_per_user']:.2f}")

    with col_viz:
        st.subheader("The Efficient Frontier")
        
        # Calculate curve
        thresholds = np.arange(0.4, 0.96, 0.05)
        curve_df = tradeoff_curve(conn, thresholds, window, filters, toggles)
        
        # Baseline for relative comparison
        baseline_df = policy_comparison(conn, window, filters)
        lenient_rows = baseline_df[baseline_df["policy_name"]=="lenient"]
        lenient_resid = lenient_rows["residual_risk"].iloc[0] if not lenient_rows.empty else metrics["residual_risk"]
        curve_df["risk_reduction"] = lenient_resid - curve_df["residual_risk"]
        
        # Current point
        current_pt = pd.DataFrame([{
            "mfa_prompts_per_user": metrics["mfa_prompts_per_user"],
            "risk_reduction": lenient_resid - metrics["residual_risk"],
            "threshold": threshold
        }])

        fig = px.scatter(
            curve_df, 
            x="mfa_prompts_per_user", 
            y="risk_reduction",
            color="threshold",
            color_continuous_scale="Blues",
            labels={"mfa_prompts_per_user": "Friction (MFA Prompts/User)", "risk_reduction": "Security (Risk Reduction)"}
        )
        
        # Add Current Selection Marker
        fig.add_traces(
            px.scatter(current_pt, x="mfa_prompts_per_user", y="risk_reduction").update_traces(
                marker=dict(size=20, color="red", symbol="x"), name="Current Config"
            ).data
        )

        # Add "Safe Zone" annotations
        fig.add_shape(type="rect",
            x0=0, y0=0.6, x1=1.5, y1=1.0,
            fillcolor="green", opacity=0.05, layer="below", line_width=0,
        )
        fig.add_annotation(x=0.2, y=0.9, text="High Security / Low Friction", showarrow=False, font=dict(color="green"))

        st.plotly_chart(fig, use_container_width=True)
        
        with st.expander("View Simulation Data"):
            st.dataframe(curve_df)


# --- PAGE: SESSION EXPLORER ---
def page_sessions(conn, policy: str, window: TimeWindow, filters: Dict):
    st.title("🔎 Session Forensics")
    
    col1, col2, col3 = st.columns(3)
    min_risk = col1.slider("Min Risk Score", 0.0, 1.0, 0.6, 0.05)
    decision_filter = col2.multiselect("Decision", ["allow", "mfa", "block"], default=["mfa", "block"])
    limit = col3.number_input("Max Rows", 100, 1000, 200)

    # Fetch
    df = sessions_table(conn, policy, window, min_risk, decision_filter, filters, limit=limit)
    
    if df.empty:
        st.info("No sessions match your criteria.")
        return

    # Data Processing for Display
    df["risk_band"] = df["risk_score"].apply(risk_band)
    # Parse explanations JSON to list for the column config
    df["reasons"] = df["explanations_json"].apply(lambda x: json.loads(x) if x else [])
    
    # Advanced Dataframe
    st.dataframe(
        df[[
            "session_id", "started_at", "org_name", "role", 
            "risk_score", "decision", "reasons", "device_type", "region"
        ]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "session_id": st.column_config.NumberColumn("ID", format="%d"),
            "started_at": st.column_config.DatetimeColumn("Time", format="D MMM HH:mm"),
            "risk_score": st.column_config.ProgressColumn(
                "Risk", 
                help="0=Safe, 1=Risky", 
                format="%.2f", 
                min_value=0, 
                max_value=1
            ),
            "decision": st.column_config.TextColumn("Outcome"),
            "reasons": st.column_config.ListColumn("Risk Factors"),
            "org_name": "Organization",
        }
    )

    # Detail view with policy-specific synthetic timeline
    selected_session = st.selectbox("Inspect session", df["session_id"].tolist())
    detail = df[df["session_id"] == selected_session].iloc[0]
    st.subheader(f"Decision: {detail['decision'].upper()} • Risk {detail['risk_score']:.2f} ({risk_band(detail['risk_score'])})")
    st.caption("Timeline reconstructed based on the selected policy's decision.")

    start_ts = pd.to_datetime(detail["started_at"])
    events = [{"event_type": "login_started", "created_at": start_ts}]
    if detail["decision"] == "block":
        events.append({"event_type": "policy_blocked", "created_at": start_ts + timedelta(seconds=2)})
    elif detail["decision"] == "mfa":
        events.append({"event_type": "mfa_challenge", "created_at": start_ts + timedelta(seconds=5)})
        events.append({"event_type": "mfa_success", "created_at": start_ts + timedelta(seconds=20)})
        events.append({"event_type": "login_success", "created_at": start_ts + timedelta(seconds=22)})
    else:  # allow
        events.append({"event_type": "login_success", "created_at": start_ts + timedelta(seconds=5)})

    ev_df = pd.DataFrame(events)
    ev_df["delta_s"] = (ev_df["created_at"] - ev_df["created_at"].min()).dt.total_seconds().astype(int)
    label_map = {
        "login_started": "Login started",
        "mfa_challenge": "MFA challenge",
        "mfa_success": "MFA success",
        "login_success": "Login success",
        "policy_blocked": "Policy blocked",
    }
    ev_df["label"] = ev_df["event_type"].map(label_map).fillna(ev_df["event_type"])
    st.dataframe(ev_df[["created_at", "delta_s", "label"]], hide_index=True, use_container_width=True)

# --- PAGE: ORG COMPARISON ---
def page_orgs(conn, policy: str, window: TimeWindow, filters: Dict):
    st.title("🏢 Organization Health Check")
    
    df = org_summary(conn, policy, window, filters)
    
    # Calculate Benchmarks
    avg_friction = df["mfa_prompts_per_user"].median()
    avg_risk = df["residual_risk"].median()
    
    # Logic for "Playbook"
    def get_playbook(row):
        if row["mfa_prompts_per_user"] > avg_friction * 1.5 and row["residual_risk"] > avg_risk:
            return "🚨 Review Policy: High friction & high risk. Consider tailored thresholds."
        if row["mfa_prompts_per_user"] > avg_friction * 1.5:
            return "⚠️ Tune UX: Users are getting hammered with MFA. Check for false positives."
        if row["residual_risk"] > avg_risk * 1.5:
            return "🛡️ Tighten Security: Too much risk allowed. Enforce stricter rules."
        return "✅ Healthy"

    df["Action Plan"] = df.apply(get_playbook, axis=1)

    # Quadrant Chart
    fig = px.scatter(
        df,
        x="mfa_prompts_per_user",
        y="residual_risk",
        color="Action Plan",
        hover_name="org_name",
        size="total_sessions",
        title="Risk vs. Friction Landscape",
        color_discrete_map={
            "✅ Healthy": "green",
            "🚨 Review Policy: High friction & high risk. Consider tailored thresholds.": "red",
            "⚠️ Tune UX: Users are getting hammered with MFA. Check for false positives.": "orange",
            "🛡️ Tighten Security: Too much risk allowed. Enforce stricter rules.": "purple"
        }
    )
    # Add quadrants
    fig.add_vline(x=avg_friction, line_dash="dash", line_color="gray", annotation_text="Avg Friction")
    fig.add_hline(y=avg_risk, line_dash="dash", line_color="gray", annotation_text="Avg Risk")
    
    st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("Detailed Org Metrics")
    st.dataframe(
        df[["org_name", "segment", "region", "mfa_prompts_per_user", "residual_risk", "Action Plan"]],
        use_container_width=True,
        column_config={
            "residual_risk": st.column_config.NumberColumn("Residual Risk", format="%.1f%%"),
            "mfa_prompts_per_user": st.column_config.NumberColumn("MFA/User", format="%.2f"),
        }
    )

# --- MAIN APP LAYOUT ---

def main():
    ensure_db()
    conn = get_conn()
    meta = load_metadata(conn)

    # Sidebar Controls
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/shield.png", width=60)
        st.title("PolicyExplorer")
        
        page = st.radio("Navigation", ["Dashboard", "Simulation", "Forensics", "Org Health"], label_visibility="collapsed")
        st.divider()
        
        # Primary Filters
        policy = st.selectbox("Active Policy", meta["policies"], index=1)
        time_selection = st.selectbox("Timeframe", ["Last 7 days", "Last 30 days", "Last 90 days"])
        window = get_time_window(time_selection)
        
        # Advanced Filters (Collapsed)
        with st.expander("🕵️‍♀️ Filter Traffic"):
            sel_seg = st.multiselect("Segment", meta["segments"])
            sel_reg = st.multiselect("Region", meta["regions"])
            sel_role = st.multiselect("Role", meta["roles"])
            sel_dev = st.multiselect("Device", meta["device_types"])
            
            # Construct filter dict
            filters = {}
            if sel_seg: filters["segment"] = sel_seg
            if sel_reg: filters["region"] = sel_reg
            if sel_role: filters["role"] = sel_role
            if sel_dev: filters["device_type"] = sel_dev
            
        st.markdown("---")
        st.caption(f"Connected to: `auth_demo.db`")
        if st.button("Reset Data"):
            generate_dataset(CONFIG_PATH, DB_PATH, force=True)
            st.cache_resource.clear()
            st.experimental_rerun()

    # Router
    if page == "Dashboard":
        page_overview(conn, policy, window, filters)
    elif page == "Simulation":
        page_thresholds(conn, window, filters)
    elif page == "Forensics":
        page_sessions(conn, policy, window, filters)
    elif page == "Org Health":
        page_orgs(conn, policy, window, filters)

if __name__ == "__main__":
    main()
