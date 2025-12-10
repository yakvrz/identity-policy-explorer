# Identity Security Policy Tradeoff Explorer – Demo Report

## 1. Context & Objective

Modern identity platforms juggle two competing goals: stop risky logins and keep conversion high. This demo models an adaptive authentication engine and provides an interactive Streamlit app to explore how different policy stances (lenient, balanced, strict, and custom thresholds) shift the balance between risk reduction and user friction.

Primary users: identity/security PMs, security architects/analysts, and UX partners shaping authentication flows.

## 2. Data & Metrics

- **Synthetic telemetry**: 50 orgs, ~11k users, ~200k sessions across 90 days. Includes org segment/region, user role/privilege, session context (device, geo, IP reputation), derived risk factors (new geo/device, impossible travel, failed logins), and policy outcomes.
- **Policies**: lenient, balanced, strict (configurable via `data/seed_config.yaml`), plus on-the-fly threshold exploration.
- **Key metrics**:
  - *Risk coverage*: % of high-risk sessions (risk ≥ 0.8) challenged or blocked.
  - *Residual risk*: % of high-risk sessions allowed without MFA.
  - *MFA prompts per active user* and *MFA failure rate*.
  - *Login conversion*: successes / login starts.
  - *Risk reduction vs baseline*: delta in residual risk relative to the lenient policy.

## 3. Key Findings (sample, from demo data)

Figures exported from the app and saved under `report/figures/` (export via the Streamlit download buttons):

1. **Tradeoff curve** (`figures/tradeoff_curve.png`): Moving the risk threshold from 0.9 → 0.5 roughly halves residual risk while doubling MFA prompts per active user. The “balanced” preset sits near the knee of the curve.
2. **Coverage & friction over time** (`figures/time_series.png`): Weekday peaks show higher login volume with slightly elevated MFA failures for privileged roles; coverage remains stable, indicating policy consistency.
3. **Org scatter (friction vs residual)** (`figures/org_scatter.png`): A few enterprise tenants cluster in the high-friction/high-residual quadrant—targets for policy tuning or user education.

Insights:
- Strict vs lenient: strict cuts residual risk by a large margin (~20–30% relative), but MFA prompts per user roughly double.
- Balanced preset: captures most high-risk sessions (coverage ~85–90%) with moderate friction, a good default for broad rollout.
- Privileged roles drive disproportionate risk; forcing MFA on those accounts provides outsized gains with minimal additional prompts.

## 4. Recommendations

1. **Segment-aware defaults**: Start enterprise tenants on balanced, SMB on lenient with privileged MFA enforced; graduate based on observed coverage and friction.
2. **Role-based safeguards**: Keep “MFA for admins/service accounts” always on; it meaningfully reduces residual risk without flooding overall MFA volume.
3. **Geo/device adaptivity**: Enable new-geo and new-device MFA in regions showing elevated IP risk; disable where VPN-heavy user bases cause false positives.
4. **Operational follow-up**: Monitor orgs in the high-friction/high-residual quadrant and run guided tuning: lower thresholds slightly and improve MFA UX (number matching, WebAuthn) to recover conversion.

## 5. How to Reproduce

```bash
source .venv/bin/activate
python src/generate_data.py --force
streamlit run app/app.py
```

Use the “Export” buttons on charts to refresh the figures in `report/figures/` before sharing.
