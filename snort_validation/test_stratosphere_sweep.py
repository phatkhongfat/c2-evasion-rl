#!/usr/bin/env python3
"""
Runnable checks for the Stratosphere sweep code (plan Phase: Tests/Validation).

One file, assert-based, no frameworks -- same style as the repo's other checks.
Covers the paths that would silently produce WRONG NUMBERS rather than crash:

  * the capture registry is well formed and its counts are real
  * ``_capture_pcap`` routes ``dataset=`` to the right root
  * the mutator corrupts exactly the packets the cost accounting charges for
  * the aggregator refuses rows with missing values instead of defaulting to 0

    python snort_validation/test_stratosphere_sweep.py
"""
import json
import sys
import tempfile
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from scapy.all import IP, Raw, TCP, Ether  # noqa: E402

from snort_bandit import apply_corrupt_mask, corrupt_targets  # noqa: E402
import aggregate_results as agg  # noqa: E402
from real_packet_env import _capture_pcap  # noqa: E402


def _pkts(n_with_payload, n_bare=2):
    out = []
    for i in range(n_with_payload):
        p = (Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
             TCP(sport=1000 + i, dport=80) / Raw(load=bytes(range(32))))
        out.append(p)
    for _ in range(n_bare):
        out.append(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                   TCP(sport=1, dport=80))   # SYN-like, no payload
    return out


def test_corrupt_accounting_matches_mutation():
    """Cost accounting must count exactly the packets the mutator changes."""
    pkts = _pkts(4, n_bare=2)
    mask = np.ones(8, dtype=np.float32)          # asks for 8 slots
    charged = len(corrupt_targets(pkts, mask))   # 4 have payload, 2 do not
    assert charged == 4, charged

    before = [bytes(p[Raw].load) for p in pkts if Raw in p]
    out = apply_corrupt_mask(pkts, mask)
    after = [bytes(p[Raw].load) for p in out if Raw in p]
    assert all(a != b for a, b in zip(before, after)), "payload not corrupted"

    # corrupting twice must not restore the original bytes (the delta bug)
    twice = apply_corrupt_mask(out, mask)
    twice_payloads = [bytes(p[Raw].load) for p in twice if Raw in p]
    assert twice_payloads == after, "corruption is not idempotent"
    print("OK  corrupt accounting == mutation target set (and idempotent)")


def test_partial_mask_selects_only_those_packets():
    pkts = _pkts(4, n_bare=0)
    mask = np.zeros(8, dtype=np.float32)
    mask[2] = 1.0
    assert corrupt_targets(pkts, mask) == [2]
    out = apply_corrupt_mask(pkts, mask)
    assert bytes(out[2][Raw].load) != bytes(pkts[2][Raw].load)
    assert bytes(out[0][Raw].load) == bytes(pkts[0][Raw].load)
    print("OK  partial mask touches only the selected packet")


def test_capture_routing():
    """dataset= picks the matching root; unknown names return None."""
    ctu = _capture_pcap("botnet-capture-20110819-bot", "ctu13")
    assert ctu is not None and "CTU-13-Dataset" in str(ctu), ctu
    assert _capture_pcap("definitely-not-a-capture", "ctu13") is None
    mcfp = _capture_pcap("botnet-capture-20110816-donbot", "stratosphere")
    if (REPO / "data/stratosphere/mcfp").exists():
        assert mcfp is not None and "mcfp" in str(mcfp), mcfp
    print("OK  _capture_pcap routes dataset= to the right root")


def test_registry_shape():
    path = REPO / "data/stratosphere_captures.json"
    if not path.exists():
        print("SKIP registry absent (run register_stratosphere_captures.py)")
        return
    d = json.loads(path.read_text())
    caps = d["captures"]
    assert len(caps) >= 10, f"expected >=10 captures, got {len(caps)}"
    for c in caps:
        for field in ("name", "url", "packets", "flows", "family"):
            assert field in c, f"{c.get('name')} missing {field}"
        assert c["packets"] >= c["flows"] >= 1, c
        assert c["url"].startswith("https://")
    print(f"OK  registry: {len(caps)} captures, all fields, counts sane")


def test_aggregator_rejects_missing_values():
    """A row with no evasion value must fail the run, not become 0%."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        good = {"capture": "cap", "dataset": "ctu13", "flows": 24,
                "corrupt_cost": 0.6, "rounds": 1, "batch": 2,
                "sweep_results": [{"corrupt_cost": 0.6, "evasion_pct": 50.0,
                                   "mean_corrupt": 3.0}]}
        (td / "sweep.json").write_text(json.dumps(good))
        rows = agg.rows_from_sweep(json.loads((td / "sweep.json").read_text()),
                                   "ctu13")
        assert rows[0]["evasion_pct"] == 50.0 and rows[0]["n_flows"] == 24

        bad = dict(good)
        bad["sweep_results"] = [{"corrupt_cost": 0.6, "evasion_pct": None,
                                 "mean_corrupt": 3.0}]
        (td / "bad.json").write_text(json.dumps(bad))
        rows = agg.rows_from_sweep(json.loads((td / "bad.json").read_text()),
                                   "ctu13")
        required = ("evasion_pct", "mean_corrupt", "n_flows", "corrupt_cost",
                    "capture")
        assert any(r.get(k) is None for r in rows for k in required), \
            "missing value not detected"

        # end-to-end: the CLI must exit non-zero on the bad file
        rc = __import__("subprocess").run(
            [sys.executable, str(REPO / "snort_validation/aggregate_results.py"),
             "--sweep", str(td / "bad.json"), "--out", str(td / "out.json")],
            capture_output=True, text=True)
        assert rc.returncode == 1, (rc.returncode, rc.stdout, rc.stderr)
        assert not (td / "out.json").exists(), "wrote a table from bad input"
    print("OK  aggregator fails (rc=1, no output) on missing values")


def test_rewrite_keeps_the_session_coherent():
    """Only the initiator's src may be rewritten; the responder's dst must move.

    Both Snort services used to rewrite ``src`` on EVERY packet.  That makes
    the responder appear to answer a different host, so every ET Open C2 rule
    carrying ``flow:established`` silently stops firing -- measured on a real
    flow that alerts when replayed unmodified.  This check fails if the
    direction-aware rewrite is reverted.
    """
    from snort_batch_service import SnortBatchService
    from snort_resident_service import ResidentSnortService

    # client -> server SYN, server -> client SYN-ACK
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80,
                                                          flags="S"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1111,
                                                          flags="SA"),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1111, dport=80,
                                                          flags="A") / Raw(b"x"),
    ]

    batch = SnortBatchService(batch_size=1)
    batch_pcap = batch._tmp / "probe.pcap"
    batch._write_batch_pcap([(pkts, 0)], batch_pcap)
    from scapy.all import Ether as E, IP as I2, rdpcap
    from scapy.all import TCP as T2

    parsed = rdpcap(str(batch_pcap))
    assert len(parsed) == 3, len(parsed)
    # forward packets: source rewritten, destination preserved
    assert parsed[0][I2].src == parsed[2][I2].src != "10.0.0.1"
    assert parsed[0][I2].dst == "10.0.0.2", parsed[0][I2].dst
    # reverse packet: DESTINATION rewritten (this is the regression guard)
    assert parsed[1][I2].dst == parsed[0][I2].src, (
        parsed[1][I2].dst, parsed[0][I2].src)
    assert parsed[1][I2].src == "10.0.0.2", parsed[1][I2].src
    assert parsed[1][T2].dport == parsed[0][T2].sport

    # the resident service builds raw frames; check its own rewrite too
    svc = ResidentSnortService()
    parsed = [E(f) for f in svc._build_frames([(pkts, 0)], 0)]
    assert len(parsed) == 3, len(parsed)
    assert parsed[1][I2].dst == parsed[0][I2].src, (
        parsed[1][I2].dst, parsed[0][I2].src)
    assert parsed[1][I2].src == "10.0.0.2", parsed[1][I2].src
    print("OK  rewrite is direction-aware (flow:established stays coherent)")


def test_env_loads_both_directions():
    """A loaded flow must carry the responder's packets, not just the initiator's.

    Collecting only the forward tuple drops the handshake half, which is what
    made ``baseline detected 0`` on captures whose flows do alert.
    """
    from real_packet_env import RealPacketEnv
    try:
        env = RealPacketEnv(n_flows=24, batch_size=1,
                            capture="botnet-capture-20110811-neris",
                            dataset="stratosphere")
    except (FileNotFoundError, ValueError) as exc:
        print(f"SKIP env check ({exc})")
        return
    keys = {k for k, _p in env.flows}
    both = 0
    for k, pkts in env.flows:
        srcs = {p[IP].src for p in pkts if IP in p}
        if len(srcs) > 1:
            both += 1
    assert both >= len(env.flows) // 2, (both, len(env.flows))
    assert len(keys) == len(env.flows), "duplicate flow keys"
    print(f"OK  env loads bidirectional flows ({both}/{len(env.flows)} "
          f"have both directions)")


if __name__ == "__main__":
    test_corrupt_accounting_matches_mutation()
    test_partial_mask_selects_only_those_packets()
    test_capture_routing()
    test_rewrite_keeps_the_session_coherent()
    test_env_loads_both_directions()
    test_registry_shape()
    test_aggregator_rejects_missing_values()
    print("\nAll stratosphere sweep checks passed.")
