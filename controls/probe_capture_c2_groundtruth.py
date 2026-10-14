"""Which on-disk captures actually fire a trojan-activity SID?

Option C replaces the corpus source.  The only admissible criterion is the
one the thesis claims to study: the traffic must be detected as command and
control by a real IDS rule, i.e. some SID with classtype trojan-activity
must fire.  A capture labelled "botnet" is not evidence of that.

Counts SIDs by classtype over the whole capture, one flow at a time, using
the real ET Open C2 ruleset (all 21374 alert rules).  Also flags the
policy-violation DHT rules so a P2P capture cannot pass as C2.
"""
from __future__ import annotations

import collections
import pathlib
import re
import sys
from concurrent.futures import ProcessPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

from real_rules_replica import RealRulesReplica, parse_ruleset  # noqa: E402

PCAPS = sorted(
    set(ROOT.glob("data/stratosphere/**/*.pcap"))
    | set(ROOT.glob("data/stratosphere/*.pcap"))
)
RULES = ROOT / "snort_validation/et_open_c2/et_open_c2.rules"
MAX_FLOWS = 4000


def classification(raw: str) -> dict[str, str]:
    """sid -> classtype, parsed from the rule text itself.

    The shipped tree has no classification.config, so the classtype lives in
    each rule's own `classtype:` option.
    """
    out: dict[str, str] = {}
    sid = cls = None
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("alert"):
            m = re.search(r"\bsid:(\d+)", line)
            sid = m.group(1) if m else None
            c = re.search(r"\bclasstype:([^;]+);", line)
            cls = c.group(1).strip() if c else None
            if sid and cls:
                out[sid] = cls
    return out


def flows_of(path: pathlib.Path, limit: int = MAX_FLOWS):
    """Bidirectional 5-tuple flows, capped so one big pcap cannot run forever."""
    flows: dict[tuple, list] = {}
    with PcapReader(str(path)) as rd:
        for pkt in rd:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            if TCP in pkt:
                proto, l4, lp = "tcp", ip.src, pkt[TCP].sport
                rp = pkt[TCP].dport
            elif UDP in pkt:
                proto, l4, lp = "udp", ip.src, pkt[UDP].sport
                rp = pkt[UDP].dport
            else:
                continue
            key = (proto, *sorted([f"{l4}:{lp}", f"{ip.dst}:{rp}"]))
            flows.setdefault(key, []).append(pkt)
            if len(flows) >= limit:
                break
    return flows


def score_capture(args) -> str:
    """One capture, scored in its own process so captures run in parallel."""
    p, limit = args
    rules = parse_ruleset(RULES)
    rep = RealRulesReplica(rules, reassemble=True)
    cls = classification(RULES.read_text(errors="replace"))
    flows = flows_of(p, limit)
    if not flows:
        return f"{p.name:34s} (no flows)"
    sids: collections.Counter = collections.Counter()
    c2 = p2p = udp = 0
    for pkts in flows.values():
        if any(UDP in q for q in pkts):
            udp += 1
        try:
            fired = {str(getattr(r, "sid", "?"))
                     for r in rep.firing_rules(pkts, home_ip=None) or []}
        except Exception:
            continue
        sids.update(fired)
        if any(cls.get(s) == "trojan-activity" for s in fired):
            c2 += 1
        if any(cls.get(s) == "policy-violation" for s in fired):
            p2p += 1
    n = len(flows)
    verdict = ("C2" if c2 and not p2p else "MIXED" if c2 and p2p
               else "P2P-only" if p2p else "no-alert")
    line = (f"{p.name:34s} {n:>6d} {c2:>7d} {p2p:>7d} "
            f"{100.0 * udp / n:>5.1f}%  {verdict}")
    top = sorted(s for s in sids if cls.get(s) == "trojan-activity")
    if top:
        hits = ", ".join(f"{s}x{sids[s]}" for s in top[:5])
        line += f"\n{'':34s} trojan SIDs ({len(top)}): {', '.join(top[:10])}  top: {hits}"
    return line


def main() -> None:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    print(f"ruleset={len(parse_ruleset(RULES))}  max_flows={limit}  "
          f"captures={len(PCAPS)}\n")
    header = (f"{'capture':34s} {'flows':>6s} {'c2flow':>7s} {'p2pflow':>7s} "
              f"{'udp%':>6s}  verdict")
    print(header)
    print("-" * len(header))
    with ProcessPoolExecutor(max_workers=4) as pool:
        for line in pool.map(score_capture, [(p, limit) for p in PCAPS]):
            print(line, flush=True)


if __name__ == "__main__":
    main()