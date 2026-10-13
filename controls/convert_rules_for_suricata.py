#!/usr/bin/env python
"""Prepare the committed ET Open C2 ruleset for Suricata 7 -- WITHOUT EDITING
RULE CONTENT.

Ghi chú (P16b, Hướng 1 -- xem docs/p16_direction_gates.md "Anti-gaming"):
- Nếu ruleset bị cắt, G1b(i) mất ý nghĩa ("split chết" có thể chỉ vì thiếu rule).
  Vì vậy mọi dòng bị loại đều ghi ra reject-log kèm lý do NGUYÊN VĂN từ
  `suricata -T`, và số đó phải được đọc trước khi diễn giải bất kỳ con số
  evasion nào. Rule bị loại được COMMENT OUT, không xoá và không sửa nội dung.
- Danh sách SID loại không viết tay: nó đến từ evidence file sinh bằng
  `controls/collect_suricata_load_errors.py`. Không có đường nào loại rule mà
  không để lại dấu vết -- đó là cơ chế "no silent tuning".
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SID_RE = __import__("re").compile(r"\bsid:(\d+)\s*;")
LINE_COMMENT = "#REJECTED-BY-SURICATA "


def load_rejected(path: Path) -> dict[str, str]:
    """sid -> verbatim `suricata -T` error, from a checked-in evidence file."""
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("sid:") and "\t" in line:
            sid, err = line.split("\t", 1)
            out[sid[4:].strip()] = err.strip()
    return out


def convert(inp: Path, out: Path, reject_log: Path, rejected: dict[str, str]) -> tuple[int, int, int]:
    total = kept = rejected_n = 0
    rejects: list[str] = []
    out.parent.mkdir(parents=True, exist_ok=True)
    with inp.open(encoding="utf-8", errors="replace") as src, out.open("w") as dst:
        for raw in src:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                dst.write(line + "\n")
                continue
            if not line.lstrip().startswith(("alert", "drop", "pass", "reject", "log")):
                dst.write(line + "\n")
                continue
            total += 1
            m = SID_RE.search(line)
            sid = m.group(1) if m else "?"
            if sid in rejected:
                # Comment out, never edit: the rule text stays byte-identical.
                dst.write(f"{LINE_COMMENT}{line}\n")
                rejects.append(f"sid {sid}: {rejected[sid]}\n  {line.strip()}")
                rejected_n += 1
                continue
            dst.write(line + "\n")
            kept += 1
    reject_log.write_text(
        "# Rejected rules -- P16b Suricata 7 (2026-10-13).\n"
        f"# total={total} kept={kept} rejected={rejected_n}\n"
        "# Every rejected rule is commented out (never edited) in the output\n"
        "# ruleset; the reason is the verbatim `suricata -T` error.\n"
        "# See docs/p16_direction_gates.md (Anti-gaming) before interpreting any\n"
        "# coverage number from this ruleset.\n"
        + ("\n".join(rejects) + "\n" if rejects else "(none)\n")
    )
    return total, kept, rejected_n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--reject-log", required=True, type=Path)
    ap.add_argument("--rejected-from", required=True, type=Path)
    a = ap.parse_args()
    rejected = load_rejected(a.rejected_from)
    total, kept, rej = convert(a.inp, a.out, a.reject_log, rejected)
    print(f"total={total} kept={kept} rejected={rej}")
    if rej:
        print(f"reject log: {a.reject_log}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())