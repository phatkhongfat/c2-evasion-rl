#!/usr/bin/env python3
"""Report the protocol framing of every flow in the hidden-defender corpus.

Mechanism B (length-prefixed wrapper) is only semantically valid on a flow whose
handler reads a declared offset.  If the corpus has no such flow, B cannot be
scored on real traffic and we must say so rather than invent a flow.
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from endpoint_model import detect_framing, parse_command  # noqa: E402
from hidden_defender_env import load_corpus, payloads_of  # noqa: E402


def main() -> int:
    per_split: dict[str, collections.Counter[str]] = {}
    unparseable: dict[str, list[str]] = {"train": [], "test": []}
    total = 0

    for split in ("train", "test"):
        counts: collections.Counter[str] = collections.Counter()
        for flow in load_corpus(split):
            raw = b"".join(payloads_of(flow["packets"]))
            framing = detect_framing(raw)
            counts[framing] += 1
            total += 1
            if parse_command(raw, framing) is None:
                unparseable[split].append(flow.get("label", flow.get("name", "?")))
        per_split[split] = counts

    combined: collections.Counter[str] = collections.Counter()
    for c in per_split.values():
        combined.update(c)

    report = {
        "total": total,
        "by_framing": dict(combined),
        "by_split": {k: dict(v) for k, v in per_split.items()},
        "flows_unparseable_by_detected_framing": {
            k: len(v) for k, v in unparseable.items()
        },
        "length_prefixed_available": combined.get("length2", 0) > 0,
    }
    out = ROOT / "snort_validation/reports/corpus_framing.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))

    if not report["length_prefixed_available"]:
        print(
            "\nBRANCH: no length-prefixed flow in corpus. Mechanism B cannot be\n"
            "scored on real traffic here; it is exercised only by the unit test\n"
            "and by a synthetic flow. Report that, do not report 0/16 as a\n"
            "negative result about B.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
