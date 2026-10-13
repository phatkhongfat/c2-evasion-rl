#!/usr/bin/env python3
"""Verify the P16b Hướng 1 headroom claim straight from the committed reports.

Tồn tại vì con số headroom trong docs/p16b_direction1_results.md từng bị chính tôi
tính SAI một lần (so best_single với oracle trong từng nhóm SID thay vì trên toàn
mẫu). Script này tính lại từ JSON đã commit, không từ doc, và in cả hai mẫu số mà
gate yêu cầu: x/20 (HTTP-D4) và x/40 (full test).

Fail-closed: nếu một mech trong mẫu đóng băng thiếu cell, hoặc control âm tính
noop không phải 0/20, script exit 1 -- không in ra một con số không diễn giải được.

Run: .venv/bin/python controls/verify_p16b_headroom.py
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "snort_validation/reports"

MECHS = ("noop", "split8", "split24", "http_header_case", "query_param_prepend")


def load(name: str):
    return json.loads((R / name).read_text())


def main() -> int:
    sample = load("p16b_http_d4_sample.json")
    fakeav = set(sample["fakeav_flows"])
    virut = set(sample["virut_flows"])
    n_expected = sample["n"]

    cells = load("suricata_g1b_fakeav.json")["cells"] + \
        load("suricata_g1b_virut.json")["cells"]

    problems = []
    if n_expected != 20:
        problems.append(f"frozen sample n={n_expected}, gate says 20")
    if fakeav & virut:
        problems.append(f"{len(fakeav & virut)} flow in BOTH groups")

    # cell completeness: every (flow, mech) exactly once
    seen = defaultdict(int)
    for c in cells:
        seen[(c["flow_id"], c["mech"])] += 1
    dup = [k for k, v in seen.items() if v > 1]
    if dup:
        problems.append(f"{len(dup)} duplicated (flow,mech) cells, e.g. {dup[0]}")
    for f in fakeav | virut:
        for m in MECHS:
            if (f, m) not in seen:
                problems.append(f"missing cell ({f[:40]}..., {m})")

    ev = defaultdict(int)
    for c in cells:
        ev[c["mech"]] += int(c["evaded"])

    # Control âm tính phải 0/20, nếu không mọi con số evasion vô nghĩa.
    if ev["noop"] != 0:
        problems.append(f"noop control evaded {ev['noop']}/20 -- harness invalid")

    # flow không có cơ chế nào né được
    by_flow = defaultdict(list)
    for c in cells:
        if c["mech"] != "noop":
            by_flow[c["flow_id"]].append(c["evaded"])
    uncovered = [f for f, v in by_flow.items() if not any(v)]
    oracle = len(by_flow) - len(uncovered)
    best_single = max((m for m in MECHS if m != "noop"), key=lambda m: ev[m])

    print("P16b Hướng 1 -- headroom, tính lại từ JSON đã commit")
    print("=" * 62)
    print(f"mẫu số đóng băng: {len(fakeav)} FakeAV + {len(virut)} Virut "
          f"= {n_expected} (HTTP-D4)")
    print(f"cells: {len(cells)} ({len(cells)//n_expected} mech x {n_expected} flow)")
    print()
    print(f'{"mech":22s} {"evaded":>8s} {"coverage":>10s}')
    for m in MECHS:
        print(f'{m:22s} {ev[m]:3d}/{n_expected:<3d} {100*ev[m]/n_expected:8.1f}%')
    print(f'{"per-flow oracle":22s} {oracle:3d}/{n_expected:<3d} '
          f'{100*oracle/n_expected:8.1f}%')
    print()
    print(f"best_single_mech      = {best_single} ({ev[best_single]}/{n_expected})")
    print(f"COVERAGE HEADROOM     = {oracle} - {ev[best_single]} "
          f"= {oracle - ev[best_single]} flow "
          f"({100*(oracle-ev[best_single])/n_expected:.1f} pp)")
    print(f"flow KHÔNG mech nào né = {len(uncovered)}/{n_expected}")
    print()
    print("mẫu số thứ hai gate yêu cầu (x/40 full test): KHÔNG đo ở P16b --")
    print("  20 flow HTTP-D4 là subset; 24 flow neris UDP còn lại không nằm trong")
    print("  claim của Hướng 1 (semantic-preserving rewrite an toàn không tồn tại")
    print("  trên UDP/binary). Ghi rõ để không ai đọc 20/20 thành 40/40.")

    if problems:
        print()
        for p in problems:
            print(f"  [!] {p}")
        return 1
    print("\n[+] mọi kiểm tra nhất quán: exit 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())