#!/usr/bin/env python3
"""Augment corpus pickle with framing field for each flow."""

from __future__ import annotations

import pickle
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_agent"))
sys.path.insert(0, str(ROOT / "snort_validation"))

from endpoint_model import detect_framing  # noqa: E402
from hidden_defender_env import CORPUS_PKL, payloads_of  # noqa: E402


def main() -> int:
    with open(CORPUS_PKL, "rb") as fh:
        data = pickle.load(fh)

    for split in ("train", "test"):
        for flow in data[split]:
            if "framing" not in flow:
                raw = b"".join(payloads_of(flow["packets"]))
                flow["framing"] = detect_framing(raw)
                print(f"{split} flow {flow.get('flow_id', '?')}: framing={flow['framing']}")

    with open(CORPUS_PKL, "wb") as fh:
        pickle.dump(data, fh)
    print(f"\n[+] augmented {CORPUS_PKL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
