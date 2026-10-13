"""Which SID survives prepend / pad / http_header_pad on the REAL C2 flows?

Answers: is `prependN`/`padN` a dead mechanism, or a stub plus a too-strict bar?
Uses only flows whose baseline alert includes the C2 SID 2012627, and the
P2P-free conf so BitTorrent rules cannot pollute the answer.
"""
import json
import sys
from pathlib import Path

ROOT = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402
from eval_pipeline import client_ip_of, score_flow_real  # noqa: E402

C2_SID = 2012627
CONF = ROOT / "snort_validation" / "et_open_c2" / "snort_et_c2_nop2p.conf"
REPORT = ROOT / "snort_validation" / "reports" / "ceiling_v4_nop2p_noop.json"

rep = json.load(open(REPORT))
c2_flows = {c["flow_id"] for c in rep["cells"]
            if c["baseline_alert"] and C2_SID in (c.get("baseline_sids") or [])}
print(f"C2 flows in report: {len(c2_flows)}")

env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
flows = [f for f in env._flows if f["flow_id"] in c2_flows]
print(f"C2 flows loaded from corpus: {len(flows)}\n")

MECHS = [None, "prepend4", "prepend8", "pad16", "http_header_pad", "split8"]
hdr = f"{'mech':<16}{'alert':<7}{'evaded':<8}{'sem_ok':<8}{'sids'}"
print(hdr)
print("-" * 78)

for i, f in enumerate(flows[:4]):
    fid = f["flow_id"]
    cip = client_ip_of(fid)
    for mi, m in enumerate(MECHS):
        r = score_flow_real(f["packets"], cip, attempt_id=(i * 10 + mi) % 250,
                            mech=m, ownership="both", conf=CONF)
        sids = sorted(x for x in (r.get("sids") or []) if x != C2_SID)
        print(f"{str(m):<16}{str(r['alert']):<7}{str(r['evaded']):<8}"
              f"{str(r['semantics_ok']):<8}{sids if sids else '(C2 SID gone)'}")
    print("-" * 78)