#!/usr/bin/env python3
"""NEGATIVE CONTROL: `noop` must alert on every flow under real Snort.

The masked-PPO eval reported 16/16 evasion against the real Snort binary.
That is the same number that was retracted twice before, so it needs a control:
if unmutated traffic (noop) also "evades", the real-snort scoring path is
broken and the headline number is meaningless.

Run:  PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 controls/control_noop_real_snort.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv, ACTION_NAMES  # noqa: E402

OUT = REPO / "snort_validation/reports/control_noop_real_snort.json"


def main() -> int:
    split = sys.argv[1] if len(sys.argv) > 1 else "test"
    env = HiddenDefenderEnv(split=split, seed=42, real_snort=True)
    env.reset(seed=42)
    noop = ACTION_NAMES.index("noop")

    alerted, rows = 0, []
    for _ in range(len(env._flows)):
        flow = env._flows[env._idx]
        fid, framing = flow["flow_id"], flow.get("framing", "?")
        _o, _r, _term, _t, info = env.step(noop)
        alerted += bool(info["alert"])
        rows.append({"flow_id": fid, "framing": framing,
                     "alert": bool(info["alert"]), "evaded": bool(info["evaded"])})
        print(f"{fid[:52]:52s} {framing:6s} alert={info['alert']} "
              f"evaded={info['evaded']}", flush=True)

    n = len(rows)
    print()
    print(f"NEGATIVE CONTROL noop: alerted {alerted}/{n}")
    if alerted != n:
        print("[!] FAIL -- noop failed to alert somewhere; the real-snort "
              "scoring path is NOT trustworthy for the 16/16 claim.")
    else:
        print("[+] PASS -- every unmutated flow alerts, so the detector is live "
              "and evasion numbers mean something.")

    OUT.write_text(json.dumps(
        {"control": "noop_real_snort", "split": split, "alerted": alerted,
         "n": n, "rows": rows}, indent=2))
    print(f"[+] {OUT}")
    return 0 if alerted == n else 1


if __name__ == "__main__":
    sys.exit(main())
