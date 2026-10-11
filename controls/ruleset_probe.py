#!/usr/bin/env python3
"""Run real Snort over the baseline test corpus for several confs; report fired SIDs
and which SIDs fall outside the naive 4-rule set (plan T0)."""
import argparse, json, pickle, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO)); sys.path.insert(0, str(REPO / "snort_validation"))

NAIVE = {2008581, 2008583, 2008585, 2012627}


def extra_vs_naive(fired):
    return sorted(set(fired) - NAIVE)


def main():
    from snort_validation.eval_pipeline import score_flow_real, client_ip_of
    ap = argparse.ArgumentParser()
    ap.add_argument("--conf", action="append", required=True, help="name=path (repeatable)")
    ap.add_argument("--corpus", default=str(REPO / "snort_validation/reports/hidden_defender_corpus.pkl"))
    ap.add_argument("--out", default=str(REPO / "snort_validation/reports/ruleset_probe.json"))
    a = ap.parse_args()
    flows = pickle.load(open(a.corpus, "rb"))["test"]
    out = {}
    for spec in a.conf:
        name, path = spec.split("=", 1)
        per, fired = {}, set()
        for i, f in enumerate(flows):
            r = score_flow_real(f["packets"], client_ip_of(f["flow_id"]), attempt_id=i, mech=None,
                                conf=Path(path).resolve(), ownership="client")
            s = sorted(x for x in (r.get("sids") or []) if isinstance(x, int))
            per[f["flow_id"]] = s
            fired.update(s)
        out[name] = {"conf": path, "fired_sids": sorted(fired), "extra_vs_naive": extra_vs_naive(fired),
                     "flows_alerting": sum(1 for v in per.values() if v), "per_flow": per}
        print(f"{name}: fired={sorted(fired)} extra={extra_vs_naive(fired)} alerting={out[name]['flows_alerting']}/{len(flows)}", flush=True)
    json.dump(out, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
