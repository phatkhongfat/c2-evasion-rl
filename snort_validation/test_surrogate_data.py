import json, sys
from pathlib import Path
REPO = Path(__file__).parent.parent
sys.path.insert(0, str(REPO))
R = REPO / "snort_validation" / "reports"

# Pinned positives per policy for the CURRENT report set.
#
# These were regenerated in 96c1e0c ("full lambda sweep results") and no longer
# match the values this test was written against in f902c5c (57/48/9).  Two
# independent causes, neither a regression:
#   1. The agent was RETRAINED with the defense-aware surrogate reward
#      (22a6407 / 83257e0), so it emits different mutations -> different
#      detection: agent 57 -> 66.
#   2. 5436bc4 commented out a missing `emerging-botcc` include that had been
#      silently killing detections, changing the random/baseline counts:
#      random 48 -> 55, baseline 9 -> 4.
#
# The reports are internally consistent (80 episodes each, episode ids 0..79
# present in both files), so these are a labeling snapshot, not a derived
# invariant.  If a future run legitimately changes the policies or ruleset,
# update these numbers AND say why in the commit message.
expect = {"agent": 66, "random": 55, "baseline": 4}
for pol, n in expect.items():
    ev = json.loads((R / f"{pol}_evaluation.json").read_text())
    sv = json.loads((R / f"{pol}_snort_validation.json").read_text())
    det = {e["episode"]: e["detected"] for e in sv["episode_results"]}
    assert len(ev["episodes"]) == 80, f"{pol}: expected 80 episodes"
    assert sum(det.get(ep["episode_id"], 0) for ep in ev["episodes"]) == n, \
        f"{pol}: positives != {n}"
print("OK: 240 labeled episodes, positives 66/55/4")