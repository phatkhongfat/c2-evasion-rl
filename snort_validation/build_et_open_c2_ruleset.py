#!/usr/bin/env python3
"""
Build a C2-focused Snort ruleset from the ET Open distribution.

Why this exists
---------------
The project previously used hand-written rules (`botnet-behavior.rules`,
`botnet-aggressive.rules`) whose thresholds were reverse-engineered from the
same flow aggregates used as RL features. That makes the "defense" a mirror of
the reward function instead of an independent judge. This script builds the
ruleset from ET Open instead: rules written by a third party, shipped as-is.

Selection policy
----------------
INCLUDE a rule when ALL hold:
  1. It is an `alert` rule (drop/reject rules never fire in offline pcap mode
     without inline mode, and would silently contribute nothing).
  2. It has at least one `content:` match. Pure IP-blacklist rules
     (emerging-botcc, emerging-ciarmy, emerging-compromised, emerging-dshield,
     threatview_CS_c2) can never fire on captured pcaps because the IPs are
     from live abuse.ch feeds, not from a 2011 lab capture. Including them
     would inflate the rule count while contributing zero detections.
  3. Its msg / metadata marks it as C2 / botnet / backdoor / RAT / beacon
     activity, or it comes from a file that is C2-specific by construction.

EXCLUDE: rules whose only match is on a flowbit set by another rule we are not
shipping (`flowbits:isset` with no producer) — those silently never fire. The
builder reports how many it dropped for this reason so the number is auditable.

Output
------
snort_validation/rules/et_open_c2/et_open_c2.rules   (the ruleset)
snort_validation/rules/et_open_c2/BUILD_REPORT.json  (what was included/excluded)
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ET_DIR = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/etopen/rules")
OUT_DIR = Path(__file__).resolve().parent / "et_open_c2"
OUT_RULES = OUT_DIR / "et_open_c2.rules"
OUT_REPORT = OUT_DIR / "BUILD_REPORT.json"

# Files that are C2-specific by construction (see file headers in ET Open).
C2_FILES = {
    "emerging-malware.rules",
    "emerging-trojan.rules",
    "emerging-mobile_malware.rules",
    "emerging-botcc.portgrouped.rules",
    "emerging-p2p.rules",
    "emerging-dns.rules",
    "threatview_CS_c2.rules",
}

# Pure IP-blacklist files: kept out of the ruleset, counted in the report.
BLACKLIST_FILES = {
    "emerging-botcc.rules",
    "emerging-ciarmy.rules",
    "emerging-compromised.rules",
    "emerging-dshield.rules",
}

# Message keywords marking C2 / implant / botnet behaviour.
C2_KEYWORDS = [
    r"\bC2\b", r"\bC&C\b", r"\bCnC\b", r"Command and Control", r"Command & Control",
    r"Botnet", r"Beacon", r"Backdoor", r"\bRAT\b", r"implant",
    r"Cobalt Strike", r"Meterpreter", r"Trickbot", r"Emotet", r"Qakbot", r"Qbot",
    r"IcedID", r"Dridex", r"Ursnif", r"Remcos", r"AgentTesla", r"njRAT", r"AsyncRAT",
    r"Gh0st", r"PoisonIvy", r"PlugX", r"ShadowPad", r"Winnti", r"ZeuS", r"SpyEye",
    r"Citadel", r"Kelihos", r"Cutwail", r"BredoLab", r"Gootkit", r"Necurs",
    r"Pony", r"Kronos", r"Danabot", r"Gozi", r"ISFB", r"Tinba", r"Ramnit",
    r"TorrentLocker", r"TeslaCrypt", r"CryptoWall", r"Locky", r"Petya",
    r"WannaCry", r"Sality", r"XAgent", r"BlackShades", r"DarkComet",
]
C2_RE = re.compile("|".join(C2_KEYWORDS), re.IGNORECASE)

ALERT_RE = re.compile(r"^\s*alert\s", re.IGNORECASE)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")
MSG_RE = re.compile(r'msg\s*:\s*"((?:[^"\\]|\\.)*)"')
FLOWBITS_ISSET_RE = re.compile(r"flowbits\s*:\s*isset\s*,\s*([A-Za-z0-9_.\-]+)")


def parse_rule(raw: str) -> dict | None:
    """Parse one physical rule line into its parts. Returns None if not an alert rule."""
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    if not ALERT_RE.match(line):
        return None

    sid_m = SID_RE.search(line)
    if not sid_m:
        return None
    msg_m = MSG_RE.search(line)
    if not msg_m:
        return None

    return {
        "raw": line,
        "sid": int(sid_m.group(1)),
        "msg": msg_m.group(1),
        "has_content": "content:" in line,
        "flowbits_isset": FLOWBITS_ISSET_RE.findall(line),
        "flowbits_set": re.findall(r"flowbits\s*:\s*set\s*,\s*([A-Za-z0-9_.\-]+)", line),
    }


def main() -> int:
    if not ET_DIR.is_dir():
        print(f"[-] ET Open rules dir not found: {ET_DIR}", file=sys.stderr)
        return 1

    included: dict[int, dict] = {}
    stats = Counter()
    per_file = defaultdict(lambda: Counter())
    excluded_flowbits: list[dict] = []
    produced_bits: set[str] = set()

    # Pass 1: collect every candidate and every flowbit any shipped rule sets.
    candidates: list[dict] = []
    for path in sorted(ET_DIR.glob("*.rules")):
        fname = path.name
        for raw in path.read_text(errors="replace").splitlines():
            rule = parse_rule(raw)
            if rule is None:
                continue
            stats["alert_rules_seen"] += 1
            per_file[fname]["alert"] += 1

            if fname in BLACKLIST_FILES:
                stats["skipped_blacklist_file"] += 1
                per_file[fname]["skipped_blacklist_file"] += 1
                continue

            if not rule["has_content"]:
                stats["skipped_no_content"] += 1
                per_file[fname]["skipped_no_content"] += 1
                continue

            is_c2_file = fname in C2_FILES
            is_c2_msg = bool(C2_RE.search(rule["msg"]))
            if not (is_c2_file or is_c2_msg):
                stats["skipped_not_c2"] += 1
                per_file[fname]["skipped_not_c2"] += 1
                continue

            rule["file"] = fname
            rule["match_reason"] = "c2_file" if is_c2_file else "c2_msg"
            candidates.append(rule)
            produced_bits.update(rule["flowbits_set"])

    # Pass 2: drop rules gated on a flowbit nobody in this set produces.
    for rule in candidates:
        missing = [b for b in rule["flowbits_isset"] if b not in produced_bits]
        if missing:
            stats["skipped_orphan_flowbit"] += 1
            per_file[rule["file"]]["skipped_orphan_flowbit"] += 1
            excluded_flowbits.append(
                {"sid": rule["sid"], "msg": rule["msg"], "missing_flowbits": missing}
            )
            continue

        if rule["sid"] in included:
            stats["skipped_duplicate_sid"] += 1
            continue
        included[rule["sid"]] = rule
        stats["included"] += 1

    # Write the ruleset, grouped by source file for auditability.
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_file: dict[str, list[dict]] = defaultdict(list)
    for rule in included.values():
        by_file[rule["file"]].append(rule)

    with OUT_RULES.open("w") as fh:
        fh.write(
            "# ET Open C2 subset — generated by build_et_open_c2_ruleset.py\n"
            "# Source: https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz\n"
            "# Do not edit by hand; regenerate with the builder script.\n"
            f"# Rules: {len(included)}\n\n"
        )
        for fname in sorted(by_file):
            fh.write(f"# ---- from {fname} ({len(by_file[fname])} rules) ----\n")
            for rule in sorted(by_file[fname], key=lambda r: r["sid"]):
                fh.write(rule["raw"] + "\n")
            fh.write("\n")

    report = {
        "et_source_dir": str(ET_DIR),
        "output_rules": str(OUT_RULES),
        "counts": dict(stats),
        "included_rules": len(included),
        "included_by_file": {k: len(v) for k, v in sorted(by_file.items())},
        "per_file_detail": {k: dict(v) for k, v in sorted(per_file.items())},
        "excluded_orphan_flowbit_sample": excluded_flowbits[:20],
        "unique_sids": len(included),
        "classtype_counts": dict(
            Counter(
                re.search(r"classtype:([A-Za-z0-9_-]+)", r["raw"]).group(1)
                for r in included.values()
                if re.search(r"classtype:([A-Za-z0-9_-]+)", r["raw"])
            ).most_common()
        ),
    }
    OUT_REPORT.write_text(json.dumps(report, indent=2))

    print(f"[+] ET Open rules scanned from {ET_DIR}")
    print(f"[+] alert rules seen:            {stats['alert_rules_seen']}")
    print(f"[+] skipped (IP blacklist file): {stats['skipped_blacklist_file']}")
    print(f"[+] skipped (no content match):  {stats['skipped_no_content']}")
    print(f"[+] skipped (not C2-related):    {stats['skipped_not_c2']}")
    print(f"[+] skipped (orphan flowbit):    {stats['skipped_orphan_flowbit']}")
    print(f"[+] skipped (duplicate sid):     {stats['skipped_duplicate_sid']}")
    print(f"[+] INCLUDED C2 rules:           {stats['included']}")
    print(f"[+] ruleset written:             {OUT_RULES}")
    print(f"[+] report written:              {OUT_REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
