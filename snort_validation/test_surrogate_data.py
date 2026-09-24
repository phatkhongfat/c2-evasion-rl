import json, sys
from pathlib import Path
REPO = Path(__file__).parent.parent
sys.path.insert(0, str(REPO))
R = REPO / "snort_validation" / "reports"
expect = {"agent": 57, "random": 48, "baseline": 9}
for pol, n in expect.items():
    ev = json.loads((R / f"{pol}_evaluation.json").read_text())
    sv = json.loads((R / f"{pol}_snort_validation.json").read_text())
    det = {e["episode"]: e["detected"] for e in sv["episode_results"]}
    assert len(ev["episodes"]) == 80, f"{pol}: expected 80 episodes"
    assert sum(det.get(ep["episode_id"], 0) for ep in ev["episodes"]) == n, \
        f"{pol}: positives != {n}"
print("OK: 240 labeled episodes, positives 57/48/9")