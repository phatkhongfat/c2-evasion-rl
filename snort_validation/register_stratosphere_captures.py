#!/usr/bin/env python3
"""
Register + validate the Stratosphere IPS / MCFP captures.

Task 0.1 of the sweep plan wants ``data/stratosphere_captures.json`` with
``{name, url, packets, flows, family}``.  The packet and flow counts are
MEASURED here by running the same one-pass extractor the training pipeline
uses (``extract_ctu13_real_features.extract_pcap``), not copied from a web
page -- a registry with unverified counts is worse than no registry, because
every later "we only loaded 24 of the N flows" claim leans on it.

USAGE
-----
    python snort_validation/register_stratosphere_captures.py \\
        --root data/stratosphere/mcfp --out data/stratosphere_captures.json
"""
import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "snort_validation"))

from extract_ctu13_real_features import extract_pcap  # noqa: E402

MCFP = "https://mcfp.felk.cvut.cz/publicDatasets"
FAMILY_RE = re.compile(r"Probable\s*[Nn]ame:\s*([A-Za-z0-9 ._-]+)")


def family_of(dataset_dir: str) -> str:
    """Malware family from the capture's published README ('' if unknown)."""
    try:
        with urllib.request.urlopen(f"{MCFP}/{dataset_dir}/README.md",
                                    timeout=25) as fh:
            m = FAMILY_RE.search(fh.read().decode("utf-8", "ignore"))
    except Exception:
        return ""
    return m.group(1).strip() if m else ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="data/stratosphere/mcfp")
    ap.add_argument("--out", default="data/stratosphere_captures.json")
    ap.add_argument("--max-packets", type=int, default=None,
                    help="cap packets scanned per capture (measurement is "
                         "exact only when omitted)")
    ap.add_argument("--skip-measure", action="store_true",
                    help="reuse counts already present in --out")
    args = ap.parse_args()

    root = Path(args.root)
    pcaps = sorted(p for p in root.glob("*/*.pcap")
                   if not p.name.startswith("normal-"))
    if not pcaps:
        print(f"[-] no pcaps under {root}", file=sys.stderr)
        return 1

    prev = {}
    out = Path(args.out)
    if out.exists():
        prev = {c["name"]: c for c in json.loads(out.read_text()).get("captures", [])}

    captures = []
    for pcap in pcaps:
        name = pcap.stem
        rec = {"name": name,
               "dataset_dir": pcap.parent.name,
               "url": f"{MCFP}/{pcap.parent.name}/{pcap.name}",
               "pcap_bytes": pcap.stat().st_size,
               "family": family_of(pcap.parent.name)}
        if args.skip_measure and name in prev:
            rec.update({k: prev[name][k] for k in ("packets", "flows")
                        if k in prev[name]})
        else:
            rows = extract_pcap(pcap, {}, max_packets=args.max_packets)
            rec["flows"] = len(rows)
            # packet count is not returned by extract_pcap; sum flow packet
            # counts (exact: every IP packet lands in exactly one flow)
            rec["packets"] = int(sum(r["tot_pkts"] for r in rows))
            del rows
        captures.append(rec)
        print(f"[+] {name:<44} {rec['packets']:>10,} pkts "
              f"{rec['flows']:>8,} flows  {rec['family']}")

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(
        {"source": MCFP, "n_captures": len(captures),
         "note": ("packets/flows are MEASURED by extract_ctu13_real_features."
                  "extract_pcap over each pcap, not copied from metadata"),
         "captures": captures}, indent=2))
    tmp.replace(out)
    print(f"\n[+] wrote {out}: {len(captures)} captures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
