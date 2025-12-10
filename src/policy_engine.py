from dataclasses import dataclass
from typing import Dict, Iterable, Optional

import pandas as pd


@dataclass
class Policy:
    policy_id: Optional[int]
    policy_name: str
    risk_threshold: float
    block_high_risk: bool
    mfa_for_admins: bool
    mfa_for_new_device: bool
    mfa_for_geo_change: bool


def evaluate_policy(session: Dict, risk_factors: Dict, policy: Policy, user: Dict) -> str:
    """Return the decision string for a single session under a given policy."""
    risk = risk_factors["risk_score"]

    if policy.block_high_risk and risk >= 0.9:
        return "block"

    if risk >= policy.risk_threshold:
        return "mfa"

    if policy.mfa_for_admins and user.get("is_privileged"):
        return "mfa"

    if policy.mfa_for_new_device and risk_factors.get("is_new_device"):
        return "mfa"

    if policy.mfa_for_geo_change and risk_factors.get("is_new_country"):
        return "mfa"

    return "allow"


def evaluate_dataframe(
    sessions: pd.DataFrame,
    risk_factors: pd.DataFrame,
    users: pd.DataFrame,
    policy: Policy,
) -> pd.DataFrame:
    """
    Vectorized policy evaluation for UI scenarios (e.g., threshold explorer).
    Returns DataFrame with session_id and decision.
    """
    merged = (
        sessions[["session_id", "user_id"]]
        .merge(risk_factors[["session_id", "risk_score", "is_new_device", "is_new_country"]], on="session_id")
        .merge(users[["user_id", "is_privileged"]], on="user_id")
    )

    def decide(row):
        return evaluate_policy(
            {"session_id": row.session_id},
            {
                "risk_score": row.risk_score,
                "is_new_device": row.is_new_device,
                "is_new_country": row.is_new_country,
            },
            policy,
            {"is_privileged": row.is_privileged},
        )

    merged["decision"] = merged.apply(decide, axis=1)
    return merged[["session_id", "decision"]]


def thresholds_grid(
    sessions: pd.DataFrame,
    risk_factors: pd.DataFrame,
    users: pd.DataFrame,
    thresholds: Iterable[float],
    base_policy: Policy,
) -> pd.DataFrame:
    """
    Evaluate a series of thresholds, returning decisions per threshold value.
    Used for tradeoff curves.
    """
    decisions = []
    for threshold in thresholds:
        pol = Policy(
            policy_id=base_policy.policy_id,
            policy_name=f"threshold_{threshold:.2f}",
            risk_threshold=threshold,
            block_high_risk=base_policy.block_high_risk,
            mfa_for_admins=base_policy.mfa_for_admins,
            mfa_for_new_device=base_policy.mfa_for_new_device,
            mfa_for_geo_change=base_policy.mfa_for_geo_change,
        )
        df = evaluate_dataframe(sessions, risk_factors, users, pol)
        df["threshold"] = threshold
        decisions.append(df)
    return pd.concat(decisions, ignore_index=True)
