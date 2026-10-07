#!/usr/bin/env python3
"""Build the NAIVE ruleset tier: exactly the ET-Open rules that fire on this
corpus's baseline flows (measured, not hand-picked — the LCN25
MovingTargetOffense naive-vs-expert axis)."""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=str(ROOT / "snort_validation/et_open_c2/et_open_c2.rules"))
    ap.add_argument("--out", default=str(ROOT / "snort_validation/et_open_c2/naive.rules"))
    ap.add_argument("--report", default=str(ROOT / "snort_validation/reports/baseline_sids_test.json"))
    args = ap.parse_args()

    from eval_pipeline import client_ip_of, score_flow_real
    from hidden_defender_env import HiddenDefenderEnv

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    per_flow = {}
    for fi, f in enumerate(env._flows):
        cip = client_ip_of(f["flow_id"])
        # keyword mech: vị trí thứ 4 là conf, không phải mech
        r = score_flow_real(f["packets"], cip, fi % 250, mech=None)
        per_flow[f["flow_id"]] = r["sids"]
    sids = sorted({s for v in per_flow.values() for s in v})
    want = set(sids)

    keep, total = [], 0
    for line in Path(args.rules).read_text(errors="ignore").splitlines(keepends=True):
        total += 1
        m = re.search(r"sid:(\d+);", line)
        if m and int(m.group(1)) in want:
            keep.append(line)
    if not keep:
        sys.exit("ERROR: naive tier would be empty — check _SID_RE / rules format")
    Path(args.out).write_text("".join(keep))
    Path(args.report).write_text(json.dumps(
        {"sids": sids, "per_flow": per_flow}, indent=1))
    print(f"fired sids={sids}; kept {len(keep)}/{total} rule lines -> {args.out}")


if __name__ == "__main__":
    main()
