#!/usr/bin/env python
"""Collect `suricata -T` signature-load errors into an evidence file.

Input format for controls/convert_rules_for_suricata.py --rejected-from:
    sid:<number>\t<verbatim suricata -T error line>

Nothing is filtered: every signature Suricata refuses to load gets a row, so
the downstream ruleset can only lose rules that this file already records.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SID_IN_ERR = re.compile(r"sid:(\d+);")
ERR_LINE = re.compile(r'^E: (?P<msg>.+?)(?: from file .* at line \d+)?$')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suricata", default="suricata")
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--rules", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args()

    proc = subprocess.run(
        [a.suricata, "-T", "-c", str(a.config), "-S", str(a.rules)],
        capture_output=True, text=True,
    )
    blob = proc.stdout + proc.stderr

    # Keep the detailed parse error attached to each signature, so the reason
    # column is the *cause* (e.g. the pcre /R complaint), not just "parse error".
    details: dict[str, str] = {}
    lines = blob.splitlines()
    rows: list[str] = []
    for i, ln in enumerate(lines):
        if "error parsing signature" not in ln:
            continue
        m = SID_IN_ERR.search(ln)
        if not m:
            continue
        sid = m.group(1)
        reason = "unspecified parse error"
        for nxt in lines[i + 1 :]:
            em = ERR_LINE.match(nxt)
            if em:
                reason = em.group("msg")
                break
            if "error parsing signature" in nxt:
                break
        if sid not in details:
            details[sid] = reason
            rows.append(f"sid:{sid}\t{reason}")

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(
        "# sids that Suricata refused to load, with the verbatim -T error.\n"
        f"# suricata: {subprocess.run([a.suricata, '-V'], capture_output=True, text=True).stdout.splitlines()[0]}\n"
        f"# config: {a.config}\n# rules: {a.rules}\n"
        + "\n".join(rows) + ("\n" if rows else "")
    )
    print(f"rejected_sids={len(rows)} -> {a.out}")
    return 0 if proc.returncode != 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())