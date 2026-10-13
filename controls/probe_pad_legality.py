"""Where does http_header_pad actually land on the REAL FakeAV C2 flows, and can
the endpoint model still recover the command?  Prints framing + command recovery
+ the mutated bytes, on flows whose baseline alert is the C2 SID 2012627.
"""
import json
import sys
from pathlib import Path

ROOT = Path("/root/.hermes/c2-evasion-rl")
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv, _JUNK_HEADERS  # noqa: E402
from eval_pipeline import mutate_client_only, client_ip_of  # noqa: E402
from c2_semantics import reassembled_client_bytes  # noqa: E402
import endpoint_model as EM  # noqa: E402

REPORT = ROOT / "snort_validation" / "reports" / "ceiling_v4_nop2p_noop.json"
rep = json.load(open(REPORT))
c2 = {c["flow_id"] for c in rep["cells"]
      if c["baseline_alert"] and 2012627 in (c.get("baseline_sids") or [])}

env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
print(f"_JUNK_HEADERS = {_JUNK_HEADERS[:60]!r}... ({len(_JUNK_HEADERS)} B, LEGAL: unknown headers)\n")

shown = 0
for f in env._flows:
    if f["flow_id"] not in c2 or shown >= 3:
        continue
    shown += 1
    fid, cip = f["flow_id"], client_ip_of(f["flow_id"])
    orig = reassembled_client_bytes(f["packets"], cip)
    mut = reassembled_client_bytes(
        mutate_client_only(f["packets"], "http_header_pad", cip, "both"), cip)
    print(f"=== {fid.split('|')[0]} ===")
    print(f"  framing label : {f.get('framing')}")
    print(f"  stream len    : {len(orig)} -> {len(mut)}  (+{len(mut) - len(orig)})")
    print(f"  ORIG  first180: {orig[:180]}")
    print(f"  MUT   first180: {mut[:180]}")
    print(f"  X-Pad present : orig={b'X-Pad' in orig}  mut={b'X-Pad' in mut}")
    fo, fm = EM.detect_framing(orig), EM.detect_framing(mut)
    co, cm = EM.parse_command(orig, fo), EM.parse_command(mut, fm)
    print(f"  detect_framing: orig={fo}  mut={fm}")
    print(f"  parse_command : orig={'None' if co is None else repr(co)[:70]}")
    print(f"                  mut ={'None' if cm is None else repr(cm)[:70]}")
    print(f"  EQUAL         : {co == cm}  (both-None is VACUOUS)")
    print()

print(f"total C2 flows: {len(c2)}   shown: {shown}")