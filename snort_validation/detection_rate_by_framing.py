#!/usr/bin/env python3
"""How many flows does real Snort actually detect, per framing?

The test-set headline (http_header_pad 8/8) turned out to rest on Snort not
alerting on 7 of those 8 flows even UNMUTATED.  A mechanism can only be
measured on flows the defender really detects, so measure that first.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from endpoint_model import detect_framing  # noqa: E402
from hidden_defender_env import load_corpus, payloads_of  # noqa: E402
from snort_batch_service import SnortBatchService  # noqa: E402

# Same default the eval harness uses: snort_validation/et_open_c2/snort_et_c2.conf
CONF = REPO / "snort_validation/et_open_c2/snort_et_c2.conf"
svc = SnortBatchService(conf=CONF, workdir=Path("/tmp/snort_detect_base"))

report = {}
for split in ("train", "test"):
    flows = load_corpus(split)
    fr = {i: detect_framing(b"".join(payloads_of(f["packets"])))
          for i, f in enumerate(flows)}
    # verdicts() returns {qid: detected}, so True means snort DID alert.
    items = [(f["packets"], k) for k, f in enumerate(flows)]
    labels = svc.verdicts(items)
    det = [i for i in range(len(flows)) if labels.get(i, False)]
    by_framing = Counter(fr[i] for i in range(len(flows)))
    det_framing = Counter(fr[i] for i in det)
    report[split] = {
        "n_flows": len(flows),
        "detected": len(det),
        "detected_rate": round(len(det) / len(flows), 3),
        "by_framing": dict(by_framing),
        "detected_by_framing": dict(det_framing),
        "detected_indices": det,
    }
    print(f"[{split}] {len(det)}/{len(flows)} detected "
          f"({100 * len(det) / len(flows):.1f}%)  "
          f"all={dict(by_framing)}  detected={dict(det_framing)}")

usable = min(report[s]["detected_by_framing"].get("http", 0)
             for s in ("train", "test"))
print(f"\n[*] minimum DETECTED http flows in either split: {usable}")
print("[!] any claim about mechanism A rests on this many flows. "
      f"{'Too few to claim anything.' if usable < 5 else 'Enough to measure.'}")

out = REPO / "snort_validation/reports/detection_rate_by_framing.json"
out.write_text(json.dumps(report, indent=2))
print(f"[+] {out}")
