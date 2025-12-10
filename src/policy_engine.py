from dataclasses import dataclass
from typing import Dict, Iterable, Optional

import numpy as np
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
    """
    Single-record evaluation (kept for unit tests/explanations).
    """
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
    Vectorized policy evaluation for high-performance UI scenarios.
    Returns DataFrame with session_id and decision.
    """
    # 1. Merge all necessary columns into a single DataFrame
    # Note: We need to ensure we don't duplicate columns if they already exist in the inputs
    merged = (
        sessions[["session_id", "user_id"]]
        .merge(
            risk_factors[["session_id", "risk_score", "is_new_device", "is_new_country"]],
            on="session_id",
        )
        .merge(users[["user_id", "is_privileged"]], on="user_id")
    )

    # 2. Define masks for each policy condition
    # Condition: Block High Risk
    mask_block = (merged["risk_score"] >= 0.9) & (policy.block_high_risk)

    # Condition: MFA (This is a simplified OR logic of all MFA triggers)
    # We check thresholds first, then specific triggers
    mask_mfa_threshold = merged["risk_score"] >= policy.risk_threshold
    mask_mfa_admin = (merged["is_privileged"]) & (policy.mfa_for_admins)
    mask_mfa_device = (merged["is_new_device"]) & (policy.mfa_for_new_device)
    mask_mfa_geo = (merged["is_new_country"]) & (policy.mfa_for_geo_change)

    mask_mfa = (
        mask_mfa_threshold | mask_mfa_admin | mask_mfa_device | mask_mfa_geo
    ) & (~mask_block)  # Ensure block takes precedence

    # 3. Apply logic using numpy select (vectorized if/elif/else)
    conditions = [mask_block, mask_mfa]
    choices = ["block", "mfa"]
    
    merged["decision"] = np.select(conditions, choices, default="allow")

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
    """
    decisions = []
    # Pre-merge once to save time inside the loop
    merged_base = (
        sessions[["session_id", "user_id"]]
        .merge(
            risk_factors[["session_id", "risk_score", "is_new_device", "is_new_country"]],
            on="session_id",
        )
        .merge(users[["user_id", "is_privileged"]], on="user_id")
    )

    for threshold in thresholds:
        # We can reuse the vectorized logic logic but applied to the pre-merged frame
        # to avoid repeated merging.
        
        # Local logic reconstruction for speed:
        mask_block = (merged_base["risk_score"] >= 0.9) & (base_policy.block_high_risk)
        
        mask_mfa_threshold = merged_base["risk_score"] >= threshold
        mask_mfa_admin = (merged_base["is_privileged"]) & (base_policy.mfa_for_admins)
        mask_mfa_device = (merged_base["is_new_device"]) & (base_policy.mfa_for_new_device)
        mask_mfa_geo = (merged_base["is_new_country"]) & (base_policy.mfa_for_geo_change)
        
        mask_mfa = (mask_mfa_threshold | mask_mfa_admin | mask_mfa_device | mask_mfa_geo) & (~mask_block)
        
        conditions = [mask_block, mask_mfa]
        choices = ["block", "mfa"]
        
        # Create a light copy to store results
        res = merged_base[["session_id"]].copy()
        res["decision"] = np.select(conditions, choices, default="allow")
        res["threshold"] = threshold
        decisions.append(res)
        
    return pd.concat(decisions, ignore_index=True)