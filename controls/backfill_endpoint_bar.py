#!/usr/bin/env python3
"""Add the endpoint-command verdict to an EXISTING ceiling sweep.

Mutations are deterministic given (flow, mechanism, ownership), so the new bar
can be recomputed from the corpus without re-running Snort.  Snort-derived
fields (alert/evaded/sids/baseline_sids/...) are COPIED VERBATIM from the input
report; only ``endpoint_ok`` / ``valid_evasion_endpoint`` are computed here.
Writes a NEW file; never edits the input.

Why this is safe (the assumption this tool rests on, and how it is checked):
``eval_pipeline.score_flow_real`` builds its mutation as
``mutate_client_only([p.copy() for p in packets], mech, client_ip,
ownership=ownership)`` and applies the endpoint bar to that pre-translation
pair.  This tool rebuilds the SAME pair with the SAME call and the SAME
ownership (defaulting to ``report["ownership"]``, else ``"both"`` -- the
sweep's default).  ``tests/test_backfill_endpoint_bar.py`` proves the two are
byte-identical by capturing the packets backfill hands to the bar and comparing
them with the mutation produced by the real ``score_flow_real`` code path.
Note that ``score_flow_real`` runs Snort on the SOURCE-TRANSLATED capture, but
``translate_source`` rewrites only addressing (IP/port) and drops checksums --
payload bytes are untouched -- and the endpoint bar reads the reassembled
CLIENT PAYLOAD, so the verdict is unchanged by translation.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from hidden_defender_env import HiddenDefenderEnv  # noqa: E402
from eval_pipeline import client_ip_of, mutate_client_only  # noqa: E402
from c2_semantics import (  # noqa: E402
    endpoint_command_preserved,
    endpoint_commands_preserved,
    endpoint_query_preserved,
)

BAR_ENDPOINT = "endpoint_command_preserved (c2_semantics.py)"
BAR_ENDPOINT_Q = "endpoint_commands_preserved (c2_semantics.py, D7: per-request, Content-Length aware)"
BAR_QUERY = "endpoint_query_preserved (c2_semantics.py, D5: parsed-query equivalence, citation-gated)"


def backfill(report: dict, env, split: str = "test") -> dict:
    """Return a copy of ``report`` with the endpoint verdict added per cell."""
    flows = {f["flow_id"]: f for f in env._flows}
    ownership = report.get("ownership", "both")
    out = dict(report)
    cells = []
    for c in report["cells"]:
        f = flows.get(c["flow_id"])
        if f is None:
            # A cell whose flow is absent from the corpus cannot be recomputed;
            # pass it through unchanged rather than dropping it silently.
            cells.append(c)
            continue
        cip = client_ip_of(c["flow_id"])
        if c["mech"] in ("None", None):
            mut = f["packets"]
        else:
            mut = mutate_client_only(f["packets"], c["mech"], cip,
                                     ownership=ownership)
        ep = endpoint_command_preserved(f["packets"], mut, cip)
        epq = endpoint_commands_preserved(f["packets"], mut, cip)
        qy = endpoint_query_preserved(f["packets"], mut, cip)
        n = dict(c)
        n["endpoint_ok"] = ep
        n["valid_evasion_endpoint"] = bool(c["evaded"]) and ep
        n["endpoint_q_ok"] = epq
        n["valid_evasion_endpoint_q"] = bool(c["evaded"]) and epq
        n["query_ok"] = qy
        n["valid_evasion_query"] = bool(c["evaded"]) and qy
        cells.append(n)
    out["cells"] = cells
    out["bar_endpoint"] = BAR_ENDPOINT
    out["bar_endpoint_q"] = BAR_ENDPOINT_Q
    out["bar_query"] = BAR_QUERY
    return out


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="add the endpoint-command verdict to an existing sweep")
    ap.add_argument("report", help="existing ceiling sweep report JSON")
    ap.add_argument("--split", default="test",
                    help="corpus split to rebuild mutations from (default test)")
    ap.add_argument("--corpus", default=None,
                    help="corpus pickle override (e.g. the P13 extended corpus "
                         "a v7/v8 report was swept on)")
    ap.add_argument("--out", required=True, help="output JSON (a NEW file)")
    return ap


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    env = HiddenDefenderEnv(split=a.split, seed=42, real_snort=False,
                            corpus=a.corpus)
    src = json.loads(Path(a.report).read_text())
    Path(a.out).write_text(json.dumps(backfill(src, env, a.split), indent=1))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
