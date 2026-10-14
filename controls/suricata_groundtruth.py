"""Frozen Suricata 7.0.3 ground truth for the 20 frozen HTTP-D4 flows.

READ-ONLY loader. The verdicts come from committed engine runs; this module must
never run an engine. Fail-closed: an unknown flow/mech raises instead of
defaulting, so a typo cannot silently produce a "0 disagreements" table.

Label discipline (decision 58): ``evaded`` is copied verbatim from the report
cell, where evaded = (n_alerts == 0). Do NOT recompute it from ``alerts`` -- the
two fields are stored separately and a mismatch means the report is corrupt.
"""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "snort_validation/reports/p16b_http_d4_sample.json"
REPORTS = ("suricata_g1b_fakeav.json", "suricata_g1b_virut.json")


def frozen_flow_ids() -> list[str]:
    """The 20 flow ids, in the order they were frozen (16 FakeAV then 4 Virut)."""
    smp = json.loads(SAMPLE.read_text())
    fids = list(smp["fakeav_flows"]) + list(smp["virut_flows"])
    assert len(fids) == smp["n"] == 20, "frozen sample changed -- re-freeze first"
    return fids


def load_ground_truth() -> dict[tuple[str, str], dict]:
    """(mech, flow_id) -> {"evaded": bool, "alerts": int, "sids": list}."""
    out: dict[tuple[str, str], dict] = {}
    for name in REPORTS:
        d = json.loads((ROOT / "snort_validation/reports" / name).read_text())
        assert d["engine"].startswith("suricata"), f"{name} is not a Suricata run"
        for c in d["cells"]:
            key = (c["mech"], c["flow_id"])
            if key in out:
                raise AssertionError(f"duplicate cell {key} in {name}")
            out[key] = {"evaded": c["evaded"], "alerts": c["alerts"],
                        "sids": c["sids"], "pkts": c["pkts"]}
    return out


def assert_complete(mechs: tuple[str, ...]) -> dict:
    """Ground truth for exactly `mechs` x 20 flows. Raises on any gap."""
    gt = load_ground_truth()
    fids = frozen_flow_ids()
    missing = [(m, f) for m in mechs for f in fids if (m, f) not in gt]
    if missing:
        raise AssertionError(
            f"ground truth incomplete: {len(missing)} cells missing, "
            f"first={missing[0]}")
    return gt


if __name__ == "__main__":
    gt = assert_complete(("noop", "split8", "split24",
                          "http_header_case", "query_param_prepend"))
    print(f"ground truth OK: {len(gt)} cells, "
          f"{len(frozen_flow_ids())} flows, engine=suricata 7.0.3")