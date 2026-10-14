"""Which SID actually fires on the HTTP flows we are calling "C2"?

The cross-tab shows the 16 HTTP flows evade 16/16 under split*, which only
means SOMETHING detected them under noop.  Before calling them C2 we must
confirm the firing rule is a trojan-activity rule and not a generic HTTP or
IDS-alert rule.  If no C2 SID matches, then the "C2" half of the corpus is
mislabelled too and the 57.5% figure has no C2 content at all.

Uses the full shipped ruleset replica on the UNMODIFIED flow, so the verdict
comes from rule matching, not from the mutation being tested.
"""
import collections
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.layers.inet import IP, TCP, UDP  # noqa: E402

from real_rules_replica import RealRulesReplica, parse_ruleset  # noqa: E402
from hidden_defender_env import HiddenDefenderEnv, client_ip_of  # noqa: E402

RULES = ROOT / "snort_validation/et_open_c2/et_open_c2.rules"

# classtype of every SID in the ruleset, read from the rules themselves so the
# label is something we read rather than assert.
CLASS = {}
for line in RULES.read_text(errors="ignore").splitlines():
    if line.startswith("alert") and "sid:" in line:
        sid = line.split("sid:")[1].split(";")[0].strip()
        cls = (line.split("classtype:")[1].split(";")[0].strip()
               if "classtype:" in line else "?")
        CLASS[sid] = cls


def main() -> None:
    rules = list(parse_ruleset(RULES))
    print(f"Ruleset: {len(rules)} rule\n")
    replica = RealRulesReplica(rules)

    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    fired = collections.defaultdict(collections.Counter)
    for flow in env._flows:
        pkts = list(flow["packets"])
        cid = client_ip_of(flow["flow_id"])
        own = [p for p in pkts if IP in p and p[IP].src == cid]
        kind = "c2-http" if any(TCP in p for p in own) else (
            "p2p-dht" if any(UDP in p for p in own) else "?")
        for rule in replica.firing_rules(pkts, home_ip=cid) or ["<none>"]:
            # Rule.sid is an int; the ruleset index in CLASS is keyed by the
            # string form Snort prints, so normalise before looking up.
            sid = str(getattr(rule, "sid", "<none>"))
            fired[kind][sid] += 1

    trojan = {s for s, c in CLASS.items() if c == "trojan-activity"}
    for kind in sorted(fired):
        print(f"=== {kind} ===")
        for sid, n in fired[kind].most_common():
            print(f"  sid {sid:>8s}  cls={CLASS.get(sid, '?'):18s} "
                  f"fires on {n:2d} flow(s)")
        print()

    print("SID trojan-activity nào chạm corpus:")
    for kind in sorted(fired):
        hit = {sid for sid in fired[kind] if sid in trojan}
        print(f"  {kind:10s}: {sorted(hit) or 'KHÔNG CÓ'}")


if __name__ == "__main__":
    main()