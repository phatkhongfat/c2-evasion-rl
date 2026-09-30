#!/usr/bin/env python3
"""Cross-check every number claimed in docs/RESULTS_PRESENTATION.md."""
import json
import re
from pathlib import Path

R = Path("/root/.hermes/c2-evasion-rl/snort_validation/reports")


def load(n):
    p = R / n
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


checks = []


def ck(label, got, want):
    ok = got == want
    checks.append((ok, label, got, want))


# --- headline
d = load("ppo_masked_test.json")
ck("masked test n_flows", d["n_flows"], 16)
ck("masked test alerted", d["alerted"], 0)
ck("masked test valid_evasion", d["valid_evasion"], 16)
ck("masked test pct", d["valid_evasion_pct"], 100.0)

# --- control
c = load("control_noop_real_snort.json")
ck("control n", c["n"], 16)
ck("control alerted", c["alerted"], 16)

# --- training
t = load("ppo_hidden_defender.json")
ck("surrogate train evaded", t["evaded"], 61)
ck("surrogate train queries", t["queries"], 704)
ck("surrogate train epochs", t["epochs"], 11)
t2 = load("ppo_realsnort_train.json")
ck("real train evaded", t2["evaded"], 58)
ck("real train queries", t2["queries"], 640)
ck("real train epochs", t2["epochs"], 10)

# --- per-mechanism (real snort matrix, HTTP-only)
m = load("hidden_defender_matrix_test.json")
flows = set()
ev = {}
evsem = {}
for k, (evaded, sem) in m.items():
    i, mech = k.split("|", 1)
    flows.add(i)
    if evaded:
        ev[mech] = ev.get(mech, 0) + 1
    if evaded and sem:
        evsem[mech] = evsem.get(mech, 0) + 1
n = len(flows)
ck("matrix flows", n, 8)
ck("matrix cells", len(m), 112)
for mech in ("split8", "split16", "split24", "http_header_pad"):
    ck(f"{mech} valid", evsem.get(mech, 0), 8)
for mech in ("prepend4", "prepend8", "prepend12", "overlap8", "length_wrapper"):
    ck(f"{mech} evaded", ev.get(mech, 0), 8)
    ck(f"{mech} valid(should be 0)", evsem.get(mech, 0), 0)
ck("corrupt8 evaded", ev.get("corrupt8", 0), 1)

# --- baselines real snort
b = load("hidden_defender_real_snort_test.json")
ck("baseline random queries", b["random_sweep"]["queries"], 25)
ck("baseline random evaded", b["random_sweep"]["evaded"], 8)
ck("baseline greedy queries", b["greedy"]["queries"], 13)
ck("baseline greedy evaded", b["greedy"]["evaded"], 8)
ck("baseline tree queries", b["supervised_tree"]["queries"], 8)
ck("baseline ppo queries", b["ppo"]["queries"], 8)

# --- corpus
co = load("hidden_defender_corpus.json")
ck("corpus n_train", co["n_train"], 64)
ck("corpus n_test", co["n_test"], 16)

# --- surrogate audit
s = load("surrogate_sweep_14mech.json")
ck("sweep overall n", s["overall"]["n"], 224)
ck("sweep overall agree", s["overall"]["n_agree"], 161)
ck("sweep overall false_safe", s["overall"]["surrogate_false_safe"], 0)
ck("sweep eligible n", s["eligible_only"]["n"], 116)
ck("sweep eligible agree", s["eligible_only"]["n_agree"], 103)
ck("sweep split8 agree", s["per_mechanism"]["split8"]["n_agree"], 5)

sv = load("surrogate_vs_real_snort.json")
ck("surrogate_vs n_agree", sv["n_agree"], 8)
ck("surrogate_vs false_safe", sv["surrogate_false_safe"], 0)

# --- scale
f = load("final_scale_up_summary.json")
rows = f["results"]
ck("scale 24 pct", rows[0]["evasion_pct"], 100.0)
ck("scale 100 evaded", rows[1]["deterministic_evaded"], 94)
ck("scale 300 evaded", rows[2]["deterministic_evaded"], 287)
ck("scale 323 evaded", rows[3]["deterministic_evaded"], 69)

# --- cross capture
x = load("cross_capture_summary.json")
ck("cross mean", x["mean_evasion_pct"], 62.5)
ck("cross std", x["std_evasion_pct"], 44.49)
byc = {r["capture"]: r for r in x["summary"]}
ck("cross win13 pct", byc["capture-win13"]["evasion_pct"], 0.0)
ck("cross 1108 pct", byc["botnet-capture-20110810-neris"]["evasion_pct"], 87.5)

# --- report
print(f"{'':3s} {'check':44s} {'got':>10s} {'want':>10s}")
bad = 0
for ok, label, got, want in checks:
    if not ok:
        bad += 1
        print(f"{'FAIL':4s} {label:44s} {got!r:>10s} {want!r:>10s}")
print(f"\n{len(checks) - bad}/{len(checks)} checks passed, {bad} failed")
