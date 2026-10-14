# C2-Evasion RL Dashboard

Interactive visualization of experiment results (oracle sweep, RL eval, cross-engine validation).

## Quick Start

```bash
# Start server (port 8888)
cd /root/.hermes/c2-evasion-rl
.venv/bin/python dashboard/app.py

# Or via systemd
sudo systemctl start hermes-rl-dashboard.service
```

Access: `http://13.140.189.138:8888`

## Features

- **Mechanism bar chart** — evasion rate per mechanism (colour-coded: strong / weak /
  no-effect / breaks-semantics)
- **Heatmap** — mechanism × flow matrix (1 = evaded, 0 = caught, blank = n/a).
  The full 17 × 40 = 680-cell matrix comes from `p17_raw_snort_d8.json`.
- **Oracle vs Best-Single** comparison
- **Framing breakdown** — C2-HTTP vs DHT P2P (pie + grouped bar)
- **Framing filter** (All / C2-HTTP / DHT) and **mechanism filter**
- **Version selector** — all `p*.json` reports (P13 → P17)

## Data Source

`snort_validation/reports/*.json` — read-only, no mutation.

## API

| Route | Purpose |
| --- | --- |
| `GET /` | Dashboard UI |
| `GET /api/reports` | List reports (name, family, size, n_flows) |
| `GET /api/report/<name>` | Raw report JSON (passthrough) |
| `GET /api/normalized/<name>` | Canonical, chart-ready structure (see below) |
| `GET /healthz` | Health probe |

### Why a normalization layer

Reports were written across phases P13–P17 and do **not** share one schema. Examples:

- `p17_mech_sweep_*.json` — `{evaded: {...}, caught: {...}, invalid_semantics: {...}}` (no per-flow cells)
- `p17_raw_snort_d8.json` — the real 680-cell matrix, stored as `index: [[flow_idx, mech], …]`
  + `detected: {str(i): bool}` (not a `cells` array)
- `p13_*` / `p14_*` — `cells: [{flow_id, mech, evaded, …}]`
- `ppo_*_test_*.json` — `per_flow: [{action, framing, evaded, …}]`
- `p16d_eval_real_snort.json` — `rows: {method: [{flow_id, mech, evaded, …}]}`
- `p17_evasion_by_framing.json` — `per_mechanism: [{mechanism, c2_http, p2p_dht}]`

`app.py::normalize()` detects the family and emits one canonical shape
(`mechanisms`, `cells`, `framing`, `framing_by_mech`, `oracle`, `actions`, `bars`),
so `dashboard.js` stays schema-agnostic. Each cell carries a stable unique
`flow_key` (full `flow_id`) so the heatmap does not collapse distinct flows that
share a short label.

> Note: the plan's validation step expects `/api/report/p17_mech_sweep_real_snort_d8`
> to return `.cells | length == 680`. That report has **no** `cells` key — the 680-cell
> matrix is in `p17_raw_snort_d8.json`. Use
> `curl -s localhost:8888/api/normalized/p17_raw_snort_d8 | jq '.cells | length'` → `680`.

## Tech Stack

- Backend: Flask
- Frontend: Plotly.js (CDN)
- Port: 8888 (Taibu uses 3100)

## Environment note (venv)

The repo's `.venv` is mixed-version: `.venv/bin/python` → **3.11** (this is the
interpreter that owns `numpy`), while the `pip`/`python3.12` symlinks point at 3.12.
Flask was installed into the **3.11** site-packages with:

```bash
.venv/bin/python3.11 -m pip install flask
```

Always launch with `.venv/bin/python dashboard/app.py` (resolves to 3.11) — launching
with `python3.12` will not see the project's numpy.

## Service

Unit: `dashboard/hermes-rl-dashboard.service` (also installed at
`/etc/systemd/system/hermes-rl-dashboard.service`).

```bash
sudo systemctl status hermes-rl-dashboard.service
sudo journalctl -u hermes-rl-dashboard.service -n 50
```
