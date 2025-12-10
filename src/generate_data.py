"""
Synthetic identity authentication dataset generator.
Creates SQLite DB with organizations, users, sessions, events, risk factors,
policy decisions, and optional explanations.
"""

from __future__ import annotations

import argparse
import json
import random
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import yaml
from faker import Faker

from explanations import explain_session
from policy_engine import Policy, evaluate_policy

BASE_DIR = Path(__file__).resolve().parent.parent
SQL_DIR = BASE_DIR / "sql"
DATA_DIR = BASE_DIR / "data"

REGION_COUNTRIES: Dict[str, List[str]] = {
    "NA": ["US", "CA", "MX"],
    "EU": ["GB", "DE", "FR", "NL", "SE", "ES", "IT"],
    "APAC": ["JP", "SG", "AU", "IN", "NZ", "PH"],
    "LATAM": ["BR", "CL", "AR", "CO", "PE", "CR"],
    "MEA": ["AE", "ZA", "IL", "TR", "SA"],
}

COUNTRY_COORDS: Dict[str, Tuple[float, float]] = {
    "US": (37.1, -95.7),
    "CA": (56.1, -106.3),
    "MX": (23.6, -102.5),
    "GB": (55.4, -3.4),
    "DE": (51.2, 10.4),
    "FR": (46.2, 2.2),
    "NL": (52.1, 5.3),
    "SE": (60.1, 18.6),
    "ES": (40.5, -3.7),
    "IT": (41.9, 12.6),
    "JP": (36.2, 138.3),
    "SG": (1.35, 103.8),
    "AU": (-25.3, 133.8),
    "IN": (20.6, 78.9),
    "NZ": (-40.9, 174.9),
    "PH": (12.9, 121.8),
    "BR": (-14.2, -51.9),
    "CL": (-35.7, -71.5),
    "AR": (-38.4, -63.6),
    "CO": (4.6, -74.1),
    "PE": (-9.2, -75.0),
    "CR": (9.7, -83.7),
    "AE": (23.4, 53.8),
    "ZA": (-30.6, 22.9),
    "IL": (31.0, 35.0),
    "TR": (38.9, 35.2),
    "SA": (23.9, 45.1),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate synthetic identity dataset.")
    parser.add_argument(
        "--config",
        type=Path,
        default=DATA_DIR / "seed_config.yaml",
        help="Path to seed_config.yaml",
    )
    parser.add_argument(
        "--output-db",
        type=Path,
        default=DATA_DIR / "auth_demo.db",
        help="Where to write the SQLite database",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing database file",
    )
    return parser.parse_args()


def load_config(path: Path) -> Dict:
    with path.open() as f:
        return yaml.safe_load(f)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2) ** 2
    c = 2 * np.arcsin(np.sqrt(a))
    return float(r * c)


def sample_country(region: str, noise: float) -> str:
    countries = REGION_COUNTRIES.get(region, ["US"])
    if np.random.rand() < noise:
        all_countries = [c for values in REGION_COUNTRIES.values() for c in values]
        return random.choice(all_countries)
    return random.choice(countries)


def sample_timestamp(now: datetime, days: int, role: str) -> datetime:
    day_offset = random.random() * days
    base = now - timedelta(days=day_offset)
    # Bias working hours; service roles are flatter
    if role == "service":
        hour = np.random.choice(range(0, 24), p=_service_hour_distribution())
    else:
        hour = int(np.clip(np.random.normal(loc=13, scale=4), 0, 23))
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base.replace(hour=hour, minute=minute, second=second, microsecond=0)


def _service_hour_distribution() -> List[float]:
    baseline = np.ones(24) * 1.0
    baseline[[6, 7, 8, 18, 19, 20]] = 1.5
    baseline /= baseline.sum()
    return baseline.tolist()


def odd_login_hour(ts: datetime, role: str) -> bool:
    hour = ts.hour
    if role in {"admin", "employee"}:
        return hour < 7 or hour > 20
    if role == "developer":
        return hour < 6 or hour > 22
    return False


def read_sql_file(path: Path) -> str:
    return path.read_text()


def run_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(read_sql_file(SQL_DIR / "schema.sql"))


def create_views(conn: sqlite3.Connection) -> None:
    conn.executescript(read_sql_file(SQL_DIR / "metrics_views.sql"))


def generate_organizations(cfg: Dict, faker: Faker) -> pd.DataFrame:
    org_cfg = cfg["organizations"]
    num_orgs = org_cfg["count"]
    segments = list(org_cfg["segments"].keys())
    segment_weights = list(org_cfg["segments"].values())
    regions = list(org_cfg["regions"].keys())
    region_weights = list(org_cfg["regions"].values())

    records = []
    now = datetime.utcnow()
    for i in range(num_orgs):
        segment = np.random.choice(segments, p=segment_weights)
        region = np.random.choice(regions, p=region_weights)
        created_at = now - timedelta(days=random.random() * org_cfg.get("created_months", 12) * 30)
        records.append(
            {
                "org_id": i + 1,
                "org_name": f"{faker.company()}",
                "segment": segment,
                "region": region,
                "created_at": created_at.isoformat(),
            }
        )
    return pd.DataFrame.from_records(records)


def generate_users(orgs: pd.DataFrame, cfg: Dict, faker: Faker) -> pd.DataFrame:
    user_records = []
    role_dist = cfg["users"]["role_distribution"]
    roles = list(role_dist.keys())
    role_weights = list(role_dist.values())
    noise = cfg["users"]["country_noise"]
    now = datetime.utcnow()
    uid = 1
    for org in orgs.itertuples():
        min_users, max_users = cfg["users"]["per_segment_ranges"][org.segment]
        num_users = random.randint(min_users, max_users)
        for _ in range(num_users):
            role = np.random.choice(roles, p=role_weights)
            country = sample_country(org.region, noise)
            created_at = org.created_at if isinstance(org.created_at, datetime) else datetime.fromisoformat(org.created_at)
            created_at = created_at + timedelta(days=random.random() * 300)
            user_records.append(
                {
                    "user_id": uid,
                    "org_id": org.org_id,
                    "role": role,
                    "is_privileged": role in {"admin", "service"},
                    "country": country,
                    "created_at": min(created_at, now).isoformat(),
                }
            )
            uid += 1
    users_df = pd.DataFrame.from_records(user_records)
    return users_df


def generate_sessions_and_risk(
    users: pd.DataFrame, orgs: pd.DataFrame, cfg: Dict, faker: Faker
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    now = datetime.utcnow()
    session_cfg = cfg["sessions"]
    device_types = list(session_cfg["device_split"].keys())
    device_weights = list(session_cfg["device_split"].values())
    ip_levels = list(session_cfg["ip_risk_level"].keys())
    ip_weights = list(session_cfg["ip_risk_level"].values())
    base_rate = session_cfg["base_logins_per_day"]

    high_risk_orgs = set(
        np.random.choice(
            orgs["org_id"], size=max(1, int(len(orgs) * session_cfg["high_risk_org_fraction"])), replace=False
        )
    )
    high_risk_users = set(
        np.random.choice(
            users["user_id"], size=max(1, int(len(users) * session_cfg["high_risk_user_fraction"])), replace=False
        )
    )

    session_records = []
    risk_records = []
    session_id = 1

    total_sessions_est = 0
    for user in users.itertuples():
        lam = base_rate[user.role] * session_cfg["days"]
        lam *= 1.2 if user.org_id in high_risk_orgs else 1.0
        lam *= 1.3 if user.user_id in high_risk_users else 1.0
        total_sessions_est += lam
    scale = 1.0
    if total_sessions_est > 280000:
        scale = 280000 / total_sessions_est

    # State tracking
    last_success_country: Dict[int, str] = {}
    last_success_device: Dict[int, str] = {}
    last_success_time: Dict[int, datetime] = {}
    recent_failures: Dict[int, List[datetime]] = {}

    for user in users.itertuples():
        lam = base_rate[user.role] * session_cfg["days"]
        lam *= 1.2 if user.org_id in high_risk_orgs else 1.0
        lam *= 1.3 if user.user_id in high_risk_users else 1.0
        lam *= scale
        num_sessions = min(int(np.random.poisson(lam=lam)), 200)
        if num_sessions <= 0:
            continue

        timestamps = sorted(sample_timestamp(now, session_cfg["days"], user.role) for _ in range(num_sessions))
        for ts in timestamps:
            prev_country = last_success_country.get(user.user_id, user.country)
            prev_device = last_success_device.get(user.user_id, "desktop")
            prev_login = last_success_time.get(user.user_id)

            device_type = np.random.choice(device_types, p=device_weights)
            ip_country = sample_country(orgs.loc[orgs.org_id == user.org_id, "region"].iloc[0], 0.2)
            ip_risk_level = np.random.choice(ip_levels, p=ip_weights)
            if user.org_id in high_risk_orgs or user.user_id in high_risk_users:
                ip_risk_level = np.random.choice(ip_levels, p=[0.7, 0.2, 0.1])

            is_new_country = ip_country != prev_country
            is_new_device = device_type != prev_device or (np.random.rand() < 0.08)

            geo_distance_km = 0.0
            impossible_travel = False
            if prev_country and prev_country in COUNTRY_COORDS and ip_country in COUNTRY_COORDS and prev_login:
                lat1, lon1 = COUNTRY_COORDS[prev_country]
                lat2, lon2 = COUNTRY_COORDS[ip_country]
                geo_distance_km = haversine_km(lat1, lon1, lat2, lon2)
                hours_between = (ts - prev_login).total_seconds() / 3600
                impossible_travel = hours_between > 0 and (geo_distance_km / max(hours_between, 0.1)) > 900

            failures = recent_failures.get(user.user_id, [])
            failures = [f for f in failures if (ts - f) <= timedelta(hours=24)]
            recent_failures[user.user_id] = failures
            recent_failed_logins = len(failures)
            if ip_risk_level == "high":
                recent_failed_logins += np.random.poisson(0.8)
            elif ip_risk_level == "medium":
                recent_failed_logins += np.random.poisson(0.3)

            reputation_base = {"low": 0.2, "medium": 0.55, "high": 0.85}[ip_risk_level]
            ip_reputation_score = min(1.0, max(0.0, np.random.normal(reputation_base, 0.08)))

            risk_raw = (
                1.2 * (ip_risk_level == "high")
                + 0.7 * (ip_risk_level == "medium")
                + 0.8 * is_new_country
                + 0.6 * is_new_device
                + 1.0 * impossible_travel
                + 0.05 * min(recent_failed_logins, 20)
                + 0.4 * odd_login_hour(ts, user.role)
                + 1.0 * (user.is_privileged)
            )
            risk_score = float(1 / (1 + np.exp(-(risk_raw - 2.5))))

            session_records.append(
                {
                    "session_id": session_id,
                    "user_id": user.user_id,
                    "org_id": user.org_id,
                    "started_at": ts.isoformat(),
                    "device_type": device_type,
                    "ip_address": faker.ipv4(),
                    "ip_country": ip_country,
                    "ip_risk_level": ip_risk_level,
                    "previous_country": prev_country,
                    "previous_device": prev_device,
                    "previous_login_at": prev_login.isoformat() if prev_login else None,
                }
            )

            risk_records.append(
                {
                    "session_id": session_id,
                    "risk_score": risk_score,
                    "is_new_country": bool(is_new_country),
                    "is_new_device": bool(is_new_device),
                    "geo_distance_km": geo_distance_km,
                    "impossible_travel": bool(impossible_travel),
                    "recent_failed_logins": int(recent_failed_logins),
                    "odd_login_hour": bool(odd_login_hour(ts, user.role)),
                    "ip_reputation_score": ip_reputation_score,
                }
            )

            # Update previous successful markers optimistically to vary risk factors.
            last_success_country[user.user_id] = ip_country
            last_success_device[user.user_id] = device_type
            last_success_time[user.user_id] = ts

            session_id += 1

    sessions_df = pd.DataFrame.from_records(session_records)
    risk_df = pd.DataFrame.from_records(risk_records)
    return sessions_df, risk_df


def insert_policies(cfg: Dict, conn: sqlite3.Connection) -> pd.DataFrame:
    policy_records = []
    for idx, p in enumerate(cfg["policies"], start=1):
        policy_records.append(
            {
                "policy_id": idx,
                "policy_name": p["policy_name"],
                "risk_threshold": p["risk_threshold"],
                "block_high_risk": bool(p["block_high_risk"]),
                "mfa_for_admins": bool(p["mfa_for_admins"]),
                "mfa_for_new_device": bool(p["mfa_for_new_device"]),
                "mfa_for_geo_change": bool(p["mfa_for_geo_change"]),
            }
        )
    df = pd.DataFrame.from_records(policy_records)
    df.to_sql("policies", conn, if_exists="append", index=False)
    return df


def generate_policy_decisions_and_events(
    sessions: pd.DataFrame,
    risk_factors: pd.DataFrame,
    users: pd.DataFrame,
    policies: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    risk_lookup = risk_factors.set_index("session_id")
    users_lookup = users.set_index("user_id")
    events = []
    policy_decisions = []
    explanations = []
    event_id = 1
    last_success_time: Dict[int, datetime] = {}
    last_success_country: Dict[int, str] = {}
    last_success_device: Dict[int, str] = {}
    recent_failures: Dict[int, List[datetime]] = {}

    sessions_sorted = sessions.sort_values("started_at")
    policy_objs = [
        Policy(
            policy_id=row.policy_id,
            policy_name=row.policy_name,
            risk_threshold=row.risk_threshold,
            block_high_risk=bool(row.block_high_risk),
            mfa_for_admins=bool(row.mfa_for_admins),
            mfa_for_new_device=bool(row.mfa_for_new_device),
            mfa_for_geo_change=bool(row.mfa_for_geo_change),
        )
        for row in policies.itertuples()
    ]

    for sess in sessions_sorted.itertuples():
        risk_row = risk_lookup.loc[sess.session_id]
        user_row = users_lookup.loc[sess.user_id]
        ts = datetime.fromisoformat(sess.started_at)
        session_dict = sess._asdict()
        user_dict = user_row.to_dict()

        reasons = explain_session(
            {
                **risk_row.to_dict(),
                "ip_risk_level": sess.ip_risk_level,
                "is_privileged": bool(user_row.is_privileged),
            }
        )
        explanations.append(
            {"session_id": sess.session_id, "explanations_json": json.dumps(reasons)}
        )

        events.append(
            {
                "event_id": event_id,
                "session_id": sess.session_id,
                "event_type": "login_started",
                "created_at": ts.isoformat(),
                "metadata_json": None,
            }
        )
        event_id += 1

        # Track prior failures for this session to feed into later sessions.
        failure_events = recent_failures.get(sess.user_id, [])
        failure_events = [t for t in failure_events if (ts - t) <= timedelta(hours=24)]
        recent_failures[sess.user_id] = failure_events

        # Evaluate each policy.
        for pol in policy_objs:
            decision = evaluate_policy(
                session_dict,
                risk_row.to_dict(),
                pol,
                user_dict,
            )
            policy_decisions.append(
                {
                    "policy_id": pol.policy_id,
                    "session_id": sess.session_id,
                    "decision": decision,
                    "effective_risk": risk_row.risk_score,
                }
        )

        # Build events based on balanced policy to keep one canonical timeline.
        balanced_policy = next((p for p in policy_objs if p.policy_name == "balanced"), policy_objs[0])
        decision = evaluate_policy(session_dict, risk_row.to_dict(), balanced_policy, user_dict)

        if decision == "block":
            events.append(
                {
                    "event_id": event_id,
                    "session_id": sess.session_id,
                    "event_type": "policy_blocked",
                    "created_at": ts.isoformat(),
                    "metadata_json": json.dumps({"reason": "risk_block"}),
                }
            )
            event_id += 1
            recent_failures[sess.user_id].append(ts)
        elif decision == "mfa":
            events.append(
                {
                    "event_id": event_id,
                    "session_id": sess.session_id,
                    "event_type": "mfa_challenge",
                    "created_at": (ts + timedelta(seconds=5)).isoformat(),
                    "metadata_json": None,
                }
            )
            event_id += 1

            success_prob = max(0.6, 0.95 - risk_row.risk_score * 0.4)
            if np.random.rand() < success_prob:
                events.append(
                    {
                        "event_id": event_id,
                        "session_id": sess.session_id,
                        "event_type": "mfa_success",
                        "created_at": (ts + timedelta(seconds=20)).isoformat(),
                        "metadata_json": None,
                    }
                )
                event_id += 1
                events.append(
                    {
                        "event_id": event_id,
                        "session_id": sess.session_id,
                        "event_type": "login_success",
                        "created_at": (ts + timedelta(seconds=22)).isoformat(),
                        "metadata_json": None,
                    }
                )
                event_id += 1
                last_success_time[sess.user_id] = ts
                last_success_country[sess.user_id] = sess.ip_country
                last_success_device[sess.user_id] = sess.device_type
            else:
                events.append(
                    {
                        "event_id": event_id,
                        "session_id": sess.session_id,
                        "event_type": "mfa_failed",
                        "created_at": (ts + timedelta(seconds=20)).isoformat(),
                        "metadata_json": None,
                    }
                )
                event_id += 1
                recent_failures[sess.user_id].append(ts)
        else:
            # allow path
            if np.random.rand() < 0.03:
                events.append(
                    {
                        "event_id": event_id,
                        "session_id": sess.session_id,
                        "event_type": "login_failed",
                        "created_at": (ts + timedelta(seconds=5)).isoformat(),
                        "metadata_json": json.dumps({"reason": "credential_error"}),
                    }
                )
                event_id += 1
                recent_failures[sess.user_id].append(ts)
            else:
                events.append(
                    {
                        "event_id": event_id,
                        "session_id": sess.session_id,
                        "event_type": "login_success",
                        "created_at": (ts + timedelta(seconds=5)).isoformat(),
                        "metadata_json": None,
                    }
                )
                event_id += 1
                last_success_time[sess.user_id] = ts
                last_success_country[sess.user_id] = sess.ip_country
                last_success_device[sess.user_id] = sess.device_type

    events_df = pd.DataFrame.from_records(events)
    decisions_df = pd.DataFrame.from_records(policy_decisions)
    explanations_df = pd.DataFrame.from_records(explanations)
    return decisions_df, events_df, explanations_df


def persist_dataframe(conn: sqlite3.Connection, name: str, df: pd.DataFrame) -> None:
    if df.empty:
        return
    df.to_sql(name, conn, if_exists="append", index=False)


def generate_dataset(config_path: Path, output_db: Path, force: bool = False) -> None:
    cfg = load_config(config_path)
    random.seed(cfg.get("random_seed", 42))
    np.random.seed(cfg.get("random_seed", 42))

    if output_db.exists():
        if not force:
            raise SystemExit(f"{output_db} exists. Use --force to overwrite.")
        output_db.unlink()

    output_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(output_db)
    run_schema(conn)

    faker = Faker()
    orgs = generate_organizations(cfg, faker)
    users = generate_users(orgs, cfg, faker)
    sessions, risk_factors = generate_sessions_and_risk(users, orgs, cfg, faker)
    policies = insert_policies(cfg, conn)
    decisions, events, explanations = generate_policy_decisions_and_events(
        sessions, risk_factors, users, policies
    )

    persist_dataframe(conn, "organizations", orgs)
    persist_dataframe(conn, "users", users)
    persist_dataframe(conn, "sessions", sessions)
    persist_dataframe(conn, "session_risk_factors", risk_factors)
    persist_dataframe(conn, "policy_decisions", decisions)
    persist_dataframe(conn, "auth_events", events)
    persist_dataframe(conn, "session_explanations", explanations)

    create_views(conn)
    conn.commit()
    conn.close()
    print(f"Generated {len(sessions)} sessions for {len(users)} users across {len(orgs)} orgs")
    print(f"Database written to {output_db}")


def main() -> None:
    args = parse_args()
    generate_dataset(args.config, args.output_db, args.force)


if __name__ == "__main__":
    main()
