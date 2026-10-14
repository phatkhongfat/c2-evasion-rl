"""Is the 21,374-rule replica a superset of its own 3-rule subset?

If verdict() were a plain OR over independent rules, a replica holding ALL
21,374 rules must fire at least as often as one holding 3 of them. It fires
strictly less (0/40 vs 24/40), so rule evaluation is NOT independent: some
state carries across rules inside one alert_count() pass.

This script isolates that state:
  A  shipped per-flow replica (3 SIDs)
  B  for_sids(those 3 SIDs)      -- freshly parsed from the same file
  C  full 21,374-rule replica
  D  for_sids(ALL SIDs)          -- full SID set, but the sid_filter path
If A == B but C == D == 0, the corruption is in the bulk path, not the rules.
"""
import pathlib
import sys

REPO = pathlib.Path("/root/.hermes/c2-evasion-rl")
sys.path[:0] = [str(REPO), str(REPO / "ai_agent"), str(REPO / "snort_validation")]

from real_rules_replica import RealRulesReplica, parse_ruleset, RULES  # noqa: E402

sys.path.insert(0, str(REPO / "ai_agent"))
from hidden_defender_env import load_corpus, client_ip_of  # noqa: E402


def count(rep, flows) -> int:
    # Pickle replicas predate the reassemble flag (see hidden_defender_env.py:540).
    if getattr(rep, "reassemble", None) is None:
        rep = RealRulesReplica(rep.rules, reassemble=True)
    n = 0
    for f in flows:
        cid = client_ip_of(f["flow_id"])
        if rep.verdict(f["packets"], home_ip=None):
            n += 1
    return n


def main() -> int:
    flows = load_corpus("test")
    print(f"test flows: {len(flows)}")

    sids = set()
    for f in flows:
        sids |= {r.sid for r in f["replica"].rules}
    print(f"union of shipped SIDs: {len(sids)} -> {sorted(sids)}")

    A = flows[0]["replica"]
    print(f"[A] shipped replica            : {len(A.rules):6d} rules  "
          f"{count(A, flows):2d}/40 detected")

    B = RealRulesReplica.for_sids(sids, RULES)
    print(f"[B] for_sids(3 SIDs) fresh     : {len(B.rules):6d} rules  "
          f"{count(B, flows):2d}/40 detected")

    all_rules = parse_ruleset(RULES)
    all_sids = {r.sid for r in all_rules}
    C = RealRulesReplica(all_rules)
    print(f"[C] full parse, no filter      : {len(C.rules):6d} rules  "
          f"{count(C, flows):2d}/40 detected")

    D = RealRulesReplica.for_sids(all_sids, RULES)
    print(f"[D] for_sids(ALL {len(all_sids)} SIDs)  : {len(D.rules):6d} rules  "
          f"{count(D, flows):2d}/40 detected")

    print("\n-- what the two paths do to the SAME sid --")
    def describe(rep, sid):
        hit = [r for r in rep.rules if r.sid == sid]
        if not hit:
            return "  <absent>"
        r = hit[0]
        fields = ("msg", "matches", "proto", "flowbits", "flags", "flow",
                  "group", "rev", "sid_pos", "endline", "raw", "header")
        return "  ".join(f"{k}={getattr(r, k, '<none>')!r}"[:90]
                         for k in fields)

    for sid in sorted(sids):
        print(f"\nSID {sid}")
        print("  B:", describe(B, sid))
        print("  C:", describe(C, sid))
    return 0


if __name__ == "__main__":
    sys.exit(main())
