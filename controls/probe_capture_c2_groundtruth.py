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


def main() -> None:
    rules = parse_ruleset(RULES)
    assert rules, "empty ruleset -- refusing to score"
    rep = RealRulesReplica(rules, reassemble=True)
    cls = classification(RULES.read_text(errors="replace"))
    print(f"ruleset={len(rules)}  classification_entries={len(cls)}\n")

    header = (f"{'capture':34s} {'flows':>6s} {'trojan':>7s} {'policy':>7s} "
              f"{'udp%':>6s}  verdict")
    print(header)
    print("-" * len(header))
    for p in PCAPS:
        flows = flows_of(p)
        if not flows:
            continue
        sids: collections.Counter = collections.Counter()
        udp = 0
        for pkts in flows.values():
            if any(UDP in q for q in pkts):
                udp += 1
            try:
                fired = rep.firing_rules(pkts, home_ip=None) or []
            except Exception:
                continue
            for r in fired:
                sids[str(getattr(r, "sid", "?"))] += 1
        trojan = {s for s in sids if cls.get(s) == "trojan-activity"}
        policy = {s for s in sids if cls.get(s) == "policy-violation"}
        n = len(flows)
        udp_pct = 100.0 * udp / n
        if trojan and not policy:
            verdict = "C2"
        elif trojan and policy:
            verdict = "MIXED"
        elif policy:
            verdict = "P2P-only"
        else:
            verdict = "no-alert"
        print(f"{p.name:34s} {n:>6d} {len(trojan):>7d} {len(policy):>7d} "
              f"{udp_pct:>5.1f}%  {verdict}")
        if trojan:
            named = {cls.get(s, "?") for s in trojan}
            top = sids.most_common(3)
            print(f"{'':34s} trojan SIDs: "
                  f"{', '.join(sorted(trojan)[:6])}  "
                  f"(top hits: {', '.join(f'{s}x{c}' for s, c in top)})")


if __name__ == "__main__":
    main()