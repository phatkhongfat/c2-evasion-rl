"""Cross-tab the real-Snort sweep against flow framing.

The sweep reports "oracle evaded 23/40".  That number is only meaningful if
the evasions land on C2 flows.  24/40 test flows are BitTorrent DHT matched
by policy-violation rules, so the same number read over a P2P sample is a
different claim than read over a C2 sample.

This probe joins the already-recorded real-Snort results per flow against the
flow's framing, and reports evasion separately for the two populations.  It
reads JSON already on disk; it does not run any engine.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

from scapy.layers.inet import IP, TCP, UDP  # noqa: E402

from hidden_defender_env import HiddenDefenderEnv, client_ip_of  # noqa: E402

REPORTS = ROOT / "snort_validation/reports"


def main() -> None:
    # framing per flow_id, in the order the env yields them
    env = HiddenDefenderEnv(split="test", seed=42, real_snort=False)
    framing = {}
    for flow in env._flows:
        pkts = list(flow["packets"])
        cid = client_ip_of(flow["flow_id"])
        own = [p for p in pkts if IP in p and p[IP].src == cid]
        kind = "c2-http" if any(TCP in p for p in own) else (
            "p2p-dht" if any(UDP in p for p in own) else "?")
        framing[flow["flow_id"]] = kind
        flow["kind"] = kind

    counts = {}
    for k in framing.values():
        counts[k] = counts.get(k, 0) + 1
    print("Mẫu test theo framing:")
    for k, v in sorted(counts.items()):
        print(f"  {k:10s} {v:3d} flow ({v / len(framing):.1%})")
    print()

    # The per-mechanism summary JSON only stores counts.  The raw index stores
    # one row per (flow, mechanism) query with the engine's verdict and the
    # gate result, so the cross-tab comes from there.
    raw_path = REPORTS / "p17_raw_snort_d8.json"
    if not raw_path.exists():
        print(f"Không có {raw_path.name} -- cần sweep D8 trước.")
        return
    raw = json.loads(raw_path.read_text())
    detected = raw["detected"]
    gate_d8 = raw["gate_d8"]

    order = [f["flow_id"] for f in env._flows]
    # `detected` / `gate_d8` are keyed by QUERY index (0..n_flows*n_mechs-1),
    # one verdict per (flow, mechanism) pair -- not by flow.  Walking `index`
    # with enumerate keeps the two aligned; indexing by flow_id would silently
    # give every mechanism the same verdicts.
    per_mech = {}
    for q, (fi, mech) in enumerate(raw["index"]):
        if not gate_d8.get(str(q), gate_d8.get(q, False)):
            continue  # semantics broken -> not a valid evasion
        evaded = not detected.get(str(q), detected.get(q, False))
        per_mech.setdefault(mech, []).append((fi, evaded))

    n_c2 = counts.get("c2-http", 0)
    n_dht = counts.get("p2p-dht", 0)
    print(f"{'mechanism':22s} {'evade':>6s} {'| c2-http':>10s} {'| p2p-dht':>10s}")
    print(f"{'':22s} {'':>6s} {'(n=%d)' % n_c2:>10s} {'(n=%d)' % n_dht:>10s}")
    rows = []
    for mech, verdicts in per_mech.items():
        ev_c2 = sum(1 for fi, e in verdicts if e and framing.get(order[fi]) == "c2-http")
        ev_dht = sum(1 for fi, e in verdicts if e and framing.get(order[fi]) == "p2p-dht")
        ev_tot = sum(1 for _, e in verdicts if e)
        rows.append((mech, ev_tot, ev_c2, ev_dht))
        print(f"{mech:22s} {ev_tot:>6d} {ev_c2:>10d} {ev_dht:>10d}")

    if rows:
        print()
        print("Oracle theo framing (chỉ flow giữ được D8):")
        for mech, tot, c2, dht in sorted(rows, key=lambda r: -r[1])[:6]:
            print(f"  {mech:20s}: C2 {c2:2d}/{n_c2} = {c2 / n_c2:6.1%}   "
                  f"DHT {dht:2d}/{n_dht} = {dht / n_dht:6.1%}")
        best_c2 = max(rows, key=lambda r: r[2])
        best_all = max(rows, key=lambda r: r[1])
        print()
        print(f"Oracle toàn mẫu : {best_all[0]} = {best_all[1]}/{len(framing)} "
              f"= {best_all[1] / len(framing):.1%}")
        print(f"Oracle CHỈ C2   : {best_c2[0]} = {best_c2[2]}/{n_c2} "
              f"= {best_c2[2] / n_c2:.1%}")

    out = REPORTS / "p17_evasion_by_framing.json"
    out.write_text(json.dumps({
        "counts": counts,
        "per_mechanism": [
            {"mechanism": m, "evaded": t, "c2_http": c, "p2p_dht": d}
            for m, t, c, d in rows
        ],
    }, indent=2))
    print(f"\n-> {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()