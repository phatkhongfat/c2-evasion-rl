#!/usr/bin/env python3
"""Build the FROZEN 20-flow HTTP-D4 sample for Hướng 1 (gate G1b).

Mẫu số (docs/p16_direction_gates.md, frozen 2026-10-13):
    subset HTTP của mẫu D4 = 16 flow FakeAV (corpus cũ, test split)
                           + 4 flow Virut  (corpus mở rộng, test split)

Hai tập này nằm ở HAI corpus khác nhau, nên script phải:
  1. lấy flow_id từ chính dữ liệu (không gõ tay) -- bằng cách lọc theo SID trong
     các report đã commit, chứ không lọc theo trí nhớ;
  2. ghi ra một file JSON đóng băng, để mọi bảng kết quả về sau dùng đúng một
     danh sách;
  3. báo cáo cả những gì KHÔNG tìm thấy (thiếu flow = thiếu mẫu số, không im lặng).

KHÔNG CHẠY ENGINE. Đây chỉ là bước đóng băng mẫu số.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "ai_agent"), str(ROOT / "snort_validation")]

REPORTS = ROOT / "snort_validation/reports"

# Frozen before measurement: which SID belongs to which corpus.
SID_FAKEAV = 2012627      # corpus cũ, 16 flow, HTTP
SID_VIRUT = 2012533       # corpus mở rộng, 4 flow, HTTP GET list.php?c=


def _load(name: str):
    p = REPORTS / name
    if not p.exists():
        return None
    return json.loads(p.read_text())


def flows_from_report(rep, sid: int):
    """flow_id list carrying `sid` in baseline_sids (i.e. the unmutated flow was
    alerted by that rule -- that is how the frozen denominator defines the group).

    Uses baseline_sids, not `sids`: `sids` is the post-mutation alert set and is
    empty exactly on the flows the mechanism evaded, which would drop them from
    the sample and silently shrink the denominator.
    """
    out = []
    for c in rep.get("cells", []):
        fid = c.get("flow_id")
        if not fid:
            continue
        base = c.get("baseline_sids") or []
        try:
            base = {int(s) for s in base}
        except (TypeError, ValueError):
            continue
        if sid in base:
            out.append(fid)
    seen, uniq = set(), []
    for f in out:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    return uniq


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="snort_validation/reports/p16b_http_d4_sample.json")
    ap.add_argument("--fakeav-report", default="control_noop_real_snort.json",
                    help="report whose cells carry the 16 FakeAV flow_ids (corpus cũ)")
    ap.add_argument("--virut-report", default="p14_v10_qpp_old_corpus.json",
                    help="report whose cells carry the 4 Virut flow_ids (corpus mở rộng)")
    a = ap.parse_args()

    fakeav_rep = _load(a.fakeav_report)
    virut_rep = _load(a.virut_report)
    problems = []

    fakeav = flows_from_report(fakeav_rep, SID_FAKEAV) if fakeav_rep else []
    virut = flows_from_report(virut_rep, SID_VIRUT) if virut_rep else []

    if not fakeav:
        problems.append(f"{a.fakeav_report}: no flow_id carried sid {SID_FAKEAV} "
                        "(check whether that report stores sids per cell)")
    if not virut:
        problems.append(f"{a.virut_report}: no flow_id carried sid {SID_VIRUT}")
    if len(fakeav) and len(fakeav) != 16:
        problems.append(f"FakeAV sample is {len(fakeav)}, frozen denominator says 16")
    if len(virut) and len(virut) != 4:
        problems.append(f"Virut sample is {len(virut)}, frozen denominator says 4")

    sample = {
        "frozen_at": "2026-10-13",
        "gate": "G1b (docs/p16_direction_gates.md)",
        "denominator_note": ("HTTP subset of D4: 16 FakeAV (corpus cũ, test split) "
                             "+ 4 Virut (corpus mở rộng, test split). Every result "
                             "table must print BOTH x/20 (HTTP-D4) and x/40 (full test)."),
        "fakeav_sid": SID_FAKEAV,
        "virut_sid": SID_VIRUT,
        "fakeav_flows": fakeav,
        "virut_flows": virut,
        "n": len(fakeav) + len(virut),
        "source_reports": {"fakeav": a.fakeav_report, "virut": a.virut_report},
        "problems": problems,
    }
    out = ROOT / a.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sample, indent=1))

    print(f"FakeAV ({SID_FAKEAV}): {len(fakeav)} flows")
    print(f"Virut  ({SID_VIRUT}): {len(virut)} flows")
    print(f"total sample: {sample['n']} / 20 expected")
    for p in problems:
        print(f"  [!] {p}")
    print(f"[+] {out}")
    # Non-zero exit if the frozen denominator could not be reproduced: a wrong
    # sample would silently invalidate every later number.
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())