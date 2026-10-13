"""Does TCP-segment fragmentation still evade when Snort reassembles?

`snort_et_c2.conf` runs `stream5_tcp: policy first`, i.e. each segment is
inspected without rebuilding the stream. If that is why `split8`, `split16`
and `split24` all score the same, then the fragmentation unit is not a real
lever -- the measurement config is.

This probe runs the corpus flows through the *same* harness the ceiling sweep
uses (`score_flow_real`), under two configs that differ only in the
`stream5_tcp` policy, and reports how many baseline-alerting flows each
mechanism evades under each.

Usage:  .venv/bin/python controls/reassembly_probe.py
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

BASE_CONF = ROOT / "snort_validation" / "et_open_c2" / "snort_et_c2.conf"
MECHS = ["noop", "split8", "split16", "split24", "split_slow"]
POLICIES = ("first", "reassemble")


def policy_conf(base: Path, work: Path, policy: str) -> Path:
    """Copy `base`, changing only the stream5_tcp policy line."""
    text = base.read_text()
    text, n = re.subn(
        r"^preprocessor stream5_tcp:.*$",
        f"preprocessor stream5_tcp: policy {policy}, "
        "use_static_footprint_sizes",
        text, flags=re.M)
    if n != 1:
        raise RuntimeError(f"stream5_tcp line matched {n} times")
    out = work / f"snort_{policy}.conf"
    out.write_text(text)
    return out


def main() -> int:
    from hidden_defender_env import HiddenDefenderEnv
    from eval_pipeline import client_ip_of, score_flow_real

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    flows = env._flows
    print(f"[*] {len(flows)} test flows from the corpus", flush=True)

    tmp = Path(tempfile.mkdtemp(prefix="reassembly_"))
    confs = {p: policy_conf(BASE_CONF, tmp, p) for p in POLICIES}
    print("[*] confs differ only in: "
          + " | ".join(f"policy {p}" for p in POLICIES), flush=True)

    # Which flows alert unmodified, per config. Everything else is skipped: a
    # flow that never alerts cannot be "evaded".
    alerting = {}
    for pol, cpath in confs.items():
        ids = []
        for fi, f in enumerate(flows):
            r = score_flow_real(f["packets"], client_ip_of(f["flow_id"]),
                                attempt_id=fi, mech=None, ownership="both",
                                conf=cpath)
            if r["alert"]:
                ids.append(fi)
        alerting[pol] = ids
        print(f"[*] baseline alerts under policy {pol}: {len(ids)}/{len(flows)}",
              flush=True)

    header = f"{'mech':<12}" + "".join(f"{'evaded/' + str(len(alerting[p])):>18}"
                                      for p in POLICIES)
    print(f"\n{header}\n{'-' * len(header)}", flush=True)
    summary = {}
    for mech in MECHS:
        cells, line = {}, f"{mech:<12}"
        for pol, cpath in confs.items():
            evaded = []
            for fi in alerting[pol]:
                f = flows[fi]
                r = score_flow_real(
                    f["packets"], client_ip_of(f["flow_id"]),
                    attempt_id=(fi * len(MECHS) + MECHS.index(mech)) % 250,
                    mech=mech, ownership="both", conf=cpath)
                if not r["alert"]:
                    evaded.append(f["flow_id"])
            cells[pol] = evaded
            line += f"{len(evaded):>18}"
        summary[mech] = cells
        print(line, flush=True)

    print("\n[*] 'closed' = evaded under policy first but NOT under reassemble")
    for mech in MECHS:
        fp = set(summary[mech]["first"])
        rp = set(summary[mech]["reassemble"])
        print(f"  {mech:<12} first={len(fp):<3} reassemble={len(rp):<3} "
              f"closed={len(fp - rp):<3} still_evaded={len(fp & rp)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())