#!/usr/bin/env python3
"""Run Suricata on one pcap and count / attribute alerts from its LOG FILES.

Why this module exists (P16b, Hướng 1 -- docs/p16_direction_gates.md)
---------------------------------------------------------------------
`controls/cross_engine_check.py` (P4) counted alerts with
`p.stdout.count("[**]")` and was never validated.  Its report
`cross_engine_v2.json` has 5/5 cells = -1 (an exception swallowed by a
try/except), i.e. **no Suricata verdict has ever existed in this project**.
Counting from the log files is what Suricata documents; `eve.json` is the
structured cross-check, and tests/test_suricata_alert_count.py pins the two
against a known-alerting capture BEFORE any evasion number uses them.

Fail-closed: a non-zero exit status raises.  Silently scoring 0 alerts on a
crashed engine run would look exactly like a successful evasion.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List

TIMEOUT_S = 300

# Docs-only option: -k none disables checksum validation. The batch harness
# rewrites IP/transport fields without recomputing every checksum, and we must
# NOT reject a flow for that -- it is an artifact of the 5-tuple rewrite, not of
# the mutation under test. Semantics gates (D5/D7) run on the packet objects,
# not on these pcaps.
CMD_EXTRA = ("-k", "none")


def run_suricata(pcap: Path, rules: Path, yaml: Path, logdir: Path) -> None:
    """Invoke Suricata; raise on failure so a crash can never read as 'clean'."""
    logdir = Path(logdir)
    logdir.mkdir(parents=True, exist_ok=True)
    for stale in ("fast.log", "eve.json"):
        (logdir / stale).unlink(missing_ok=True)
    cmd = ["suricata", "-c", str(yaml), "-S", str(rules),
           "-r", str(pcap), "-l", str(logdir), *CMD_EXTRA]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True,
                          timeout=TIMEOUT_S)
    if proc.returncode != 0:
        raise RuntimeError(
            f"suricata rc={proc.returncode} on {pcap}:\n{proc.stdout[-800:]}")


def _fast_log_alerts(logdir: Path) -> int:
    fast = Path(logdir) / "fast.log"
    if not fast.exists():
        return 0
    return sum(1 for line in fast.read_text(errors="ignore").splitlines()
               if "[**]" in line)


def _eve_alerts(logdir: Path) -> List[dict]:
    eve = Path(logdir) / "eve.json"
    if not eve.exists():
        return []
    out = []
    for line in eve.read_text(errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("event_type") == "alert":
            out.append(rec)
    return out


def count_alerts(pcap: Path, rules: Path, yaml: Path, logdir: Path) -> int:
    """Number of alerts on `pcap` (fast.log)."""
    run_suricata(pcap, rules, yaml, logdir)
    return _fast_log_alerts(logdir)


def alert_sids(pcap: Path, rules: Path, yaml: Path, logdir: Path) -> List[int]:
    """Signature IDs from eve.json -- needed to attribute WHICH rule fired."""
    run_suricata(pcap, rules, yaml, logdir)
    return [int(r["alert"]["signature_id"]) for r in _eve_alerts(logdir)
            if "signature_id" in r.get("alert", {})]


def alert_records(pcap: Path, rules: Path, yaml: Path, logdir: Path) -> List[dict]:
    """Full eve.json alert records (sid + src/dst + flow id) for attribution."""
    run_suricata(pcap, rules, yaml, logdir)
    return _eve_alerts(logdir)


def alert_profile(pcap: Path, rules: Path, yaml: Path,
                  logdir: Path) -> tuple[int, List[int]]:
    """(fast.log count, unique sids) from ONE engine run.

    Cost matters here: a per-flow sweep pays the ~25 s rule load per flow, so
    counting and attributing in two separate runs would double the measurement
    and make the G1c budget check meaningless.
    """
    run_suricata(pcap, rules, yaml, logdir)
    n = _fast_log_alerts(logdir)
    sids = {int(r["alert"]["signature_id"]) for r in _eve_alerts(logdir)
            if "signature_id" in r.get("alert", {})}
    return n, sorted(sids)