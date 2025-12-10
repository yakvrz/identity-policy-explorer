from typing import Dict, List


def explain_session(row: Dict) -> List[str]:
    """Return short, human-friendly explanations for why a session is risky."""
    reasons: List[str] = []

    ip_risk = row.get("ip_risk_level")
    if ip_risk == "high":
        reasons.append("IP address from a high-risk network range")
    elif ip_risk == "medium":
        reasons.append("IP address from a moderately risky network range")

    if row.get("is_new_country"):
        reasons.append("Login from a new country compared to the previous session")

    if row.get("is_new_device"):
        reasons.append("Login from a new device or browser fingerprint")

    if row.get("impossible_travel"):
        reasons.append("Timing and distance indicate impossible travel between logins")

    if row.get("recent_failed_logins", 0) >= 3:
        reasons.append("Multiple failed login attempts in the last 24 hours")

    if row.get("odd_login_hour"):
        reasons.append("Login at an unusual time for this role")

    if row.get("is_privileged"):
        reasons.append("Privileged account with elevated access")

    if not reasons:
        reasons.append("No major anomalies; risk driven by baseline factors")

    return reasons
