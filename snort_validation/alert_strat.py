"""Stratify sweep results theo CLASSTYPE của rule đã nổ (plan P2).

Cùng một số "evade" nhìn khác hẳn khi tách:
  trojan-activity / exploit     = mục tiêu thật của C2 evasion
  policy-violation (DHT/P2P)    = Informational, không phải detec malware
"""
import json
import re
from collections import defaultdict
from pathlib import Path


def sid_classtypes(rules_path) -> dict:
    """{sid: classtype} đọc trực tiếp từ file .rules (ET: sid + classtype
    cùng dòng)."""
    out = {}
    for line in Path(rules_path).read_text(errors="ignore").splitlines():
        ms, mc = re.search(r"sid:(\d+);", line), re.search(r"classtype:([^;]+);", line)
        if ms and mc:
            out[int(ms.group(1))] = mc.group(1).strip()
    return out


def stratify(sweep_path, rules_path) -> dict:
    """-> {classtype: {mech: {"flows": n, "evaded": n, "valid": n}}}

    - một flow thuộc nhóm G nếu baseline_sids của nó chứa ≥1 sid map sang G
      (flow có thể thuộc nhiều nhóm; mỗi nhóm chỉ đếm 1 lần/flow)
    - "valid" = valid_evasion của ô (mech, flow) đó
    """
    data = json.loads(Path(sweep_path).read_text())
    ct = sid_classtypes(rules_path)
    # sweep ghi cells (schema thật của ownership_ceiling_sweep); "rows" là
    # tên plan — chấp nhận cả hai để tool chạy được với report cũ/mới.
    rows = data.get("rows") or data.get("cells") or []
    flows = {}
    for r in rows:
        flows.setdefault(r["flow_id"], r.get("baseline_sids", []))
    groups = defaultdict(set)
    for fid, sids in flows.items():
        for s in sids:
            groups[ct.get(s, "unknown")].add(fid)
    out = {}
    for g, fids in sorted(groups.items()):
        per = {}
        for r in rows:
            if r["flow_id"] not in fids:
                continue
            d = per.setdefault(r["mech"], {"flows": 0, "evaded": 0, "valid": 0})
            d["flows"] += 1
            d["evaded"] += bool(r["evaded"])
            d["valid"] += bool(r.get("valid_evasion"))
        out[g] = per
    return out
