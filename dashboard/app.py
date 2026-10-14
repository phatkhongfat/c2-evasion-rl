#!/usr/bin/env python3
"""RL C2-Evasion Dashboard — read-only visualization of experiment results.

Reads JSON reports from snort_validation/reports/ and exposes a REST API.
The frontend is schema-agnostic: this backend normalizes the many report
shapes produced across phases (P13..P17) into one canonical structure.

Canonical shape (see normalize()):
    {
      "name", "family", "meta", "n_flows", "n_mechs",
      "mechanisms":     [{mech, evaded, caught, invalid, total, rate, category}],
      "cells":          [{mech, flow_idx, flow_id, framing, evaded, alert,
                          semantics_ok, valid_evasion}],
      "framing":        [{label, count}],
      "framing_by_mech":[{mech, c2_http, p2p_dht}],
      "oracle":         {oracle_flows, oracle_pct, best_single, best_single_mech, headroom_pp},
      "actions":        [...],
      "warnings":       [...]
    }
"""
from flask import Flask, jsonify, render_template, send_from_directory
from pathlib import Path
import json

REPO = Path("/root/.hermes/c2-evasion-rl")
REPORTS = REPO / "snort_validation/reports"

app = Flask(__name__,
            static_folder='static',
            template_folder='templates')

# Mechanism families (used to colour / group the mechanism bar).
SEMANTICS_BREAKERS = {
    "prepend4", "prepend8", "prepend12", "pad16", "corrupt8",
    "length_wrapper",
}


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------
def _load(name):
    """Load a report by stem. Returns (dict|None). Guards against traversal."""
    if not name or "/" in name or "\\" in name or ".." in name:
        return None
    path = REPORTS / f"{name}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _short_flow(flow_id):
    """Compact a long flow_id for axis labels.

    'botnet-capture-20110810-neris|147.32.84.165:2077->194.85.61.20:53|udp'
        -> '2077>53/udp'
    Falls back to the raw string if the shape is unexpected.
    """
    if not isinstance(flow_id, str):
        return str(flow_id)
    try:
        parts = flow_id.split("|")
        endpoints = parts[1]
        proto = parts[2] if len(parts) > 2 else ""
        src, dst = endpoints.split("->")
        src_port = src.rsplit(":", 1)[-1]
        dst_port = dst.rsplit(":", 1)[-1]
        label = f"{src_port}>{dst_port}"
        return f"{label}/{proto}" if proto else label
    except (IndexError, ValueError, AttributeError):
        return flow_id


# --------------------------------------------------------------------------
# Normalizers
# --------------------------------------------------------------------------
def _norm_mechanisms_from_dicts(d, n_flows):
    """Build mechanism rows from evaded/caught/invalid_semantics dicts."""
    evaded = d.get("evaded") or {}
    caught = d.get("caught") or {}
    invalid = d.get("invalid_semantics") or {}
    mechs = []
    for mech in sorted(set(evaded) | set(caught) | set(invalid)):
        ev = int(evaded.get(mech, 0))
        ca = int(caught.get(mech, 0))
        iv = int(invalid.get(mech, 0))
        total = ev + ca if (ev + ca) > 0 else n_flows
        rate = (ev / total) if total else 0.0
        if mech in SEMANTICS_BREAKERS or (ev == 0 and iv > 0):
            category = "breaks_semantics"
        elif rate >= 0.5:
            category = "strong"
        elif rate > 0:
            category = "weak"
        else:
            category = "no_effect"
        mechs.append({
            "mech": mech, "evaded": ev, "caught": ca, "invalid": iv,
            "total": total, "rate": round(rate, 4), "category": category,
        })
    return mechs


def _aggregate_cells(cells):
    """Aggregate a canonical cell list into mechanism rows."""
    agg = {}
    for c in cells:
        m = c.get("mech")
        if m is None:
            continue
        a = agg.setdefault(m, {"evaded": 0, "total": 0, "invalid": 0})
        a["total"] += 1
        if c.get("evaded"):
            a["evaded"] += 1
        if c.get("semantics_ok") is False:
            a["invalid"] += 1
    out = []
    for mech, a in sorted(agg.items()):
        rate = a["evaded"] / a["total"] if a["total"] else 0.0
        if mech in SEMANTICS_BREAKERS or (a["evaded"] == 0 and a["invalid"] > 0):
            category = "breaks_semantics"
        elif rate >= 0.5:
            category = "strong"
        elif rate > 0:
            category = "weak"
        else:
            category = "no_effect"
        out.append({
            "mech": mech, "evaded": a["evaded"], "caught": a["total"] - a["evaded"],
            "invalid": a["invalid"], "total": a["total"],
            "rate": round(rate, 4), "category": category,
        })
    return out


def _framing_from_counts(counts):
    if not isinstance(counts, dict):
        return []
    return [{"label": str(k), "count": int(v)} for k, v in counts.items()]


def _framing_from_cells(cells):
    agg = {}
    for c in cells:
        f = c.get("framing")
        if f:
            agg[f] = agg.get(f, 0) + 1
    return _framing_from_counts(agg)


def normalize(name, d):
    """Turn any report shape into the canonical structure."""
    warnings = []
    out = {
        "name": name, "family": "other", "meta": {}, "n_flows": None,
        "n_mechs": None, "mechanisms": [], "cells": [], "framing": [],
        "framing_by_mech": [], "oracle": {}, "actions": [], "bars": [],
        "warnings": warnings,
    }
    if not isinstance(d, dict):
        warnings.append("report is not a JSON object; showing raw only")
        return out

    n_flows = d.get("n_flows")
    n_mechs = d.get("n_mechs")
    out["n_flows"] = n_flows
    out["n_mechs"] = n_mechs

    # --- meta (whichever descriptive keys exist) ---
    for k in ("engine", "ruleset", "scorer", "gate", "model", "split", "method",
              "pipeline", "bar", "ownership", "frag3_timeout_s", "elapsed_s",
              "n_queries", "frozen_at"):
        if k in d:
            out["meta"][k] = d[k]

    # --- oracle ---
    oracle = {}
    for k_src, k_dst in (("oracle_flows", "oracle_flows"), ("oracle_pct", "oracle_pct"),
                         ("best_single", "best_single"), ("best_single_mech", "best_single_mech"),
                         ("headroom_pp", "headroom_pp")):
        if k_src in d:
            oracle[k_dst] = d[k_src]
    out["oracle"] = oracle

    # ------------------------------------------------------------------
    # Family detection (most specific first)
    # ------------------------------------------------------------------
    if "per_mechanism" in d:
        # p17_evasion_by_framing.json: counts + per_mechanism[{mechanism,c2_http,p2p_dht}]
        out["family"] = "framing"
        pm = d.get("per_mechanism") or []
        rows = []
        for row in pm:
            mech = row.get("mechanism")
            ev = int(row.get("evaded", 0))
            total = (int(row.get("c2_http", 0)) + int(row.get("p2p_dht", 0))) or (n_flows or 0)
            rate = ev / total if total else 0.0
            rows.append({
                "mech": mech, "evaded": ev, "caught": max(total - ev, 0),
                "invalid": 0, "total": total, "rate": round(rate, 4),
                "category": ("strong" if rate >= 0.5 else "weak" if rate > 0 else "no_effect"),
            })
        out["mechanisms"] = rows
        out["framing_by_mech"] = [
            {"mech": r.get("mechanism"),
             "c2_http": int(r.get("c2_http", 0)),
             "p2p_dht": int(r.get("p2p_dht", 0))}
            for r in pm
        ]
        out["framing"] = _framing_from_counts(d.get("counts") or {})

    elif "index" in d and any(k in d for k in ("detected", "gate_d8", "gate_strict")):
        # p17_raw_snort_d8.json: index=[[flow_idx, mech]..], detected={str(i): bool}
        out["family"] = "raw_matrix"
        index = d.get("index") or []
        gate = None
        for g in ("detected", "gate_d8", "gate_strict"):
            if isinstance(d.get(g), dict):
                gate = g
                break
        table = d.get(gate) or {} if gate else {}
        if gate and gate != "detected":
            warnings.append(f"using gate column '{gate}' as detection signal")
        if not gate:
            warnings.append("no detection column found in raw matrix")
        cells = []
        for i, pair in enumerate(index):
            try:
                flow_idx, mech = pair[0], pair[1]
            except (TypeError, IndexError, ValueError):
                continue
            detected = table.get(str(i))
            if detected is None:
                detected = table.get(i)
            evaded = None if detected is None else (not bool(detected))
            cells.append({
                "mech": mech, "flow_idx": flow_idx,
                "flow_key": f"idx_{flow_idx}",
                "flow_id": f"flow_{int(flow_idx):02d}" if isinstance(flow_idx, int) else str(flow_idx),
                "framing": None, "evaded": evaded, "alert": None,
                "semantics_ok": None, "valid_evasion": None,
            })
        out["cells"] = cells
        out["n_flows"] = n_flows or (max((c["flow_idx"] for c in cells), default=-1) + 1)
        out["n_mechs"] = n_mechs or len({c["mech"] for c in cells})
        out["mechanisms"] = _aggregate_cells(cells)

    elif isinstance(d.get("evaded"), dict) and isinstance(d.get("caught"), dict):
        # mech sweep reports (real snort / suricata / surrogate)
        out["family"] = "mech_sweep"
        out["mechanisms"] = _norm_mechanisms_from_dicts(d, n_flows or 0)

    elif isinstance(d.get("cells"), list):
        # p13_v7/v8/v9, p14 reports
        out["family"] = "cells"
        cells = []
        for c in d["cells"]:
            if not isinstance(c, dict):
                continue
            cells.append({
                "mech": c.get("mech"),
                "flow_idx": c.get("flow_idx"),
                "flow_key": str(c.get("flow_id")),
                "flow_id": _short_flow(c.get("flow_id")),
                "framing": c.get("framing"),
                "evaded": c.get("evaded"),
                "alert": c.get("baseline_alert"),
                "semantics_ok": c.get("semantics_ok"),
                "valid_evasion": c.get("valid_evasion"),
            })
        out["cells"] = cells
        out["mechanisms"] = _aggregate_cells(cells)
        out["framing"] = _framing_from_cells(cells)

    elif isinstance(d.get("per_flow"), list):
        # PPO eval reports
        out["family"] = "per_flow"
        cells = []
        for c in d["per_flow"]:
            if not isinstance(c, dict):
                continue
            cells.append({
                "mech": c.get("action"),
                "flow_idx": c.get("flow_idx"),
                "flow_key": str(c.get("flow_id")),
                "flow_id": _short_flow(c.get("flow_id")),
                "framing": c.get("framing"),
                "evaded": c.get("evaded"),
                "alert": c.get("alert"),
                "semantics_ok": c.get("semantics_ok"),
                "valid_evasion": c.get("valid_evasion"),
            })
        out["cells"] = cells
        out["mechanisms"] = _aggregate_cells(cells)
        out["framing"] = _framing_from_cells(cells)
        if "valid_evasion_pct" in d:
            out["oracle"]["policy_valid_evasion_pct"] = d["valid_evasion_pct"]

    elif isinstance(d.get("rows"), dict):
        # p16d_eval_real_snort.json: rows = {method: [{flow_id, mech, evaded, ...}]}
        out["family"] = "rows"
        cells = []
        for method, rows in d["rows"].items():
            for r in (rows or []):
                if not isinstance(r, dict):
                    continue
                cells.append({
                    "mech": r.get("mech", method),
                    "flow_idx": None,
                    "flow_key": str(r.get("flow_id")),
                    "flow_id": _short_flow(r.get("flow_id")),
                    "framing": None,
                    "evaded": r.get("evaded"),
                    "alert": r.get("alert"),
                    "semantics_ok": r.get("semantics_ok"),
                    "valid_evasion": r.get("valid_evasion"),
                })
        out["cells"] = cells
        out["mechanisms"] = _aggregate_cells(cells)
        if isinstance(d.get("policy"), dict):
            out["oracle"]["policy_evaded"] = d["policy"].get("evaded")
            out["oracle"]["policy_n"] = d["policy"].get("n")

    elif isinstance(d.get("actions"), list):
        # p17_ppo_action_* reports
        out["family"] = "actions"
        for a in d["actions"]:
            if not isinstance(a, dict):
                continue
            row = dict(a)
            row.pop("reward_vector", None)  # keep payload small
            out["actions"].append(row)

    elif isinstance(d.get("framing_counts"), dict):
        out["family"] = "framing"
        out["framing"] = _framing_from_counts(d["framing_counts"])

    elif isinstance(d.get("agent"), dict) and isinstance(d.get("random_baseline"), dict):
        # packet_level_*_evaluation.json: agent vs random baseline
        out["family"] = "agent_eval"
        a = d["agent"]; b = d.get("random_baseline", {})
        out["bars"] = [
            {"label": "Agent", "value": a.get("evasion_rate"),
             "evaded": a.get("evaded"), "detected": a.get("detected")},
            {"label": "Random baseline", "value": b.get("evasion_rate"),
             "evaded": b.get("evaded"), "detected": b.get("detected")},
        ]
        out["n_flows"] = (a.get("evaded") or 0) + (a.get("detected") or 0) or d.get("n_episodes")

    elif "evasion_pct" in d and "epochs" in d:
        # ppo_*_train.json: training-run summary
        out["family"] = "train_summary"
        out["bars"] = [
            {"label": "evasion %", "value": d.get("evasion_pct")},
            {"label": "flows solved", "value": d.get("distinct_flows_solved_cumulative")},
            {"label": "semantics breaks", "value": d.get("semantics_breaks")},
        ]
        out["oracle"]["evasion_pct"] = d.get("evasion_pct")

    elif isinstance(d.get("actions_chosen"), dict) and "evaded" in d:
        # ppo_*_test.json (short form): policy action histogram
        out["family"] = "actions_chosen"
        out["bars"] = [{"label": k, "value": v} for k, v in d["actions_chosen"].items()]

    elif isinstance(d.get("by_bar"), dict):
        # p13_composite_*: composite headroom per bar
        out["family"] = "composite"
        for bar, info in d["by_bar"].items():
            if isinstance(info, dict) and "composite_headroom" in info:
                out["bars"].append({"label": bar, "value": info["composite_headroom"]})

    else:
        warnings.append("unrecognised report shape; metadata only")

    # Best-single rate helper for the oracle chart
    if n_flows and out["oracle"].get("best_single") is not None:
        try:
            out["oracle"]["best_single_rate"] = round(int(out["oracle"]["best_single"]) / int(n_flows), 4)
        except (TypeError, ValueError, ZeroDivisionError):
            pass
    if out["oracle"].get("oracle_pct") is not None:
        try:
            out["oracle"]["oracle_rate"] = round(float(out["oracle"]["oracle_pct"]) / 100.0, 4)
        except (TypeError, ValueError):
            pass

    return out


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


def _detect_family(d):
    """Single source of truth for the report family tag."""
    if not isinstance(d, dict):
        return "other"
    if "per_mechanism" in d:
        return "framing"
    if "index" in d and any(k in d for k in ("detected", "gate_d8", "gate_strict")):
        return "raw_matrix"
    if isinstance(d.get("evaded"), dict) and isinstance(d.get("caught"), dict):
        return "mech_sweep"
    if isinstance(d.get("cells"), list):
        return "cells"
    if isinstance(d.get("per_flow"), list):
        return "per_flow"
    if isinstance(d.get("rows"), dict):
        return "rows"
    if isinstance(d.get("actions"), list):
        return "actions"
    if isinstance(d.get("framing_counts"), dict):
        return "framing"
    if isinstance(d.get("agent"), dict) and isinstance(d.get("random_baseline"), dict):
        return "agent_eval"
    if "evasion_pct" in d and "epochs" in d:
        return "train_summary"
    if isinstance(d.get("actions_chosen"), dict) and "evaded" in d:
        return "actions_chosen"
    if isinstance(d.get("by_bar"), dict):
        return "composite"
    return "other"


@app.route('/api/reports')
def list_reports():
    """List available JSON reports with a light family tag for the selector."""
    reports = sorted(REPORTS.glob("p*.json"))
    out = []
    for r in reports:
        fam = "other"
        n_flows = None
        try:
            d = json.loads(r.read_text())
            fam = _detect_family(d)
            if isinstance(d, dict):
                n_flows = d.get("n_flows")
        except (json.JSONDecodeError, OSError):
            pass
        out.append({
            "name": r.stem,
            "path": str(r.relative_to(REPO)),
            "size": r.stat().st_size,
            "family": fam,
            "n_flows": n_flows,
        })
    return jsonify(out)


@app.route('/api/report/<name>')
def get_report(name):
    """Raw report passthrough (plan-compatible)."""
    d = _load(name)
    if d is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(d)


@app.route('/api/normalized/<name>')
def get_normalized(name):
    """Canonical, chart-ready structure for any report shape."""
    d = _load(name)
    if d is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(normalize(name, d))


@app.route('/healthz')
def healthz():
    return jsonify({"status": "ok", "reports": len(list(REPORTS.glob("p*.json")))})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False)
