# Identity Security Policy Tradeoff Explorer

Synthetic identity authentication dataset and Streamlit UI for exploring how adaptive authentication policies balance security (risk reduction) with user friction.

## Project Layout

- `src/generate_data.py` – synthetic data generator that builds a SQLite database (`data/auth_demo.db`) with orgs, users, sessions, risk factors, policy decisions, explanations, and events.
- `src/policy_engine.py` – policy definitions and evaluation logic.
- `src/explanations.py` – human-readable risk explanations.
- `src/metrics.py` – metrics/query helpers for the app.
- `sql/` – schema, metrics views, and example queries.
- `app/app.py` – Streamlit UI with overview, threshold explorer, session explorer, and org comparison pages.
- `tests/` – small unit tests for policy logic and metrics.
- `report/demo_report.md` – product-style summary + chart placeholders.

## Setup (uv virtualenv)

```bash
uv venv .venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

## Generate Data

The generator reads `data/seed_config.yaml` for volumes, distributions, and policy defaults.

```bash
source .venv/bin/activate
python src/generate_data.py --force
# Outputs data/auth_demo.db with ~50 orgs, ~10k users, ~200k sessions
```

## Run the App

```bash
source .venv/bin/activate
streamlit run app/app.py
```

Pages:
- **Overview** – KPI cards, risk-vs-friction scatter, and time series.
- **Threshold Explorer** – tweak thresholds/toggles, tradeoff curve, and KPI lines.
- **Session Explorer** – filter high-risk sessions and inspect explanations + event timelines.
- **Org Comparison** – org-level table and residual-risk vs friction scatter.

## Tests

```bash
source .venv/bin/activate
pytest
```

## Notes & Extensibility

- Data is SQLite for portability; switch to DuckDB by swapping the connection layer if desired.
- Adjust the synthetic mix in `data/seed_config.yaml` to change segments, regions, or policy templates.
- Metrics are defined in SQL views (`sql/metrics_views.sql`) and surfaced via `src/metrics.py`; add new slices there for custom charts.
