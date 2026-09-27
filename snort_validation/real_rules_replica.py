#!/usr/bin/env python3
"""A replica of the REAL ET Open C2 rules that fire on a capture.

WHY THIS EXISTS
---------------
The previous replica (`snort_query_service.RULES` + `enhanced_snort_replica`) is
6 hand-written threshold rules plus 5 heuristics.  It never reads the ET Open C2
ruleset, so a policy trained against it learns to defeat rules Snort does not
have.  Measured consequence: 82% evasion against that replica, 0% against the
real Snort binary on the same flows.

This module parses the ACTUAL rules that fire on a capture -- the same `content:`
byte patterns the real Snort binary matches -- and evaluates them against real
packet payloads.  A policy trained here optimises the real matching surface at
Python speed instead of ~10 s per Snort call.

SUPPORTED
---------
`content:` with `|hex|` escapes, `nocase`, `offset:`, `depth:`, `distance:`,
`within:`, and the `flow:established[,to_server|from_server]` gate.

NOT SUPPORTED (and why that is safe here)
-----------------------------------------
`pcre:`, `byte_test:`, `byte_extract:`, `byte_jump:` are not interpreted.  Rules
using them still load and still require their `content:` parts to match, which
errs in the safe direction: the replica can only fire when the literal byte
patterns are present, so it never invents a detection.  It may MISS detections
whose only discriminator is a pcre.  `coverage_report()` measures that gap
against real Snort's measured alert counts, and prints it.

Usage:
    python snort_validation/real_rules_replica.py --capture botnet-capture-20110811-neris
    python snort_validation/real_rules_replica.py --capture <cap> --dump-rules
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

REPO = Path(__file__).resolve().parent.parent
RULES = REPO / "snort_validation/et_open_c2/et_open_c2.rules"
SNORT_CONF = REPO / "snort_validation/et_open_c2/snort_et_c2.conf"

CONTENT_RE = re.compile(r'content\s*:\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)
MOD_RE = re.compile(
    r"\b(nocase|offset\s*:\s*\d+|depth\s*:\s*\d+|distance\s*:\s*\d+|"
    r"within\s*:\s*\d+)\b", re.IGNORECASE)
FLOW_RE = re.compile(r"flow\s*:\s*([a-z_,\s]+)", re.IGNORECASE)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)")
MSG_RE = re.compile(r'msg\s*:\s*"((?:[^"\\]|\\.)*)"')
UNSUPPORTED_RE = re.compile(r"\b(pcre|byte_test|byte_extract|byte_jump)\s*:",
                            re.IGNORECASE)

_ESCAPES = {"n": 0x0A, "r": 0x0D, "t": 0x09, "\\": 0x5C, '"': 0x22,
            ";": 0x3B, ":": 0x3A}


def parse_content(raw: str) -> bytes:
    """Snort content string -> bytes, decoding |hex| runs.

    `content:"HTTP/1.1|0d 0a|Accept|3a 20|*/*"` mixes literal text with hex.
    """
    out = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            out.append(_ESCAPES.get(nxt, ord(nxt) & 0xFF))
            i += 2
            continue
        if ch == "|":
            end = raw.find("|", i + 1)
            if end == -1:
                out.extend(raw[i:].encode("latin-1"))
                break
            for tok in raw[i + 1:end].split():
                out.append(int(tok, 16))
            i = end + 1
            continue
        out.append(ord(ch) & 0xFF)
        i += 1
    return bytes(out)


@dataclass
class ContentMatch:
    """One `content:` plus the modifiers attached to it."""

    pattern: bytes
    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None

    def find(self, payload: bytes, prev_end: Optional[int]) -> Optional[int]:
        """Return the match start, or None.

        `prev_end` is where the previous content in this rule ended (None for
        the first), used by the relative modifiers.
        """
        hay = payload.lower() if self.nocase else payload
        needle = self.pattern.lower() if self.nocase else self.pattern
        if not needle:
            return None

        if self.distance is not None or self.within is not None:
            if prev_end is None:
                return None
            lo = prev_end + (self.distance or 0)
            hi = len(hay) if self.within is None else lo + self.within
        else:
            lo = self.offset or 0
            hi = len(hay) if self.depth is None else lo + self.depth

        lo = max(0, min(lo, len(hay)))
        hi = max(lo, min(hi, len(hay)))
        idx = hay.find(needle, lo, hi)
        return idx if idx >= 0 else None


@dataclass
class Rule:
    sid: int
    msg: str
    matches: List[ContentMatch] = field(default_factory=list)
    established: bool = False
    to_server: bool = False
    from_server: bool = False
    uses_unsupported: bool = False

    def fires(self, payloads: Sequence[bytes], has_handshake: bool) -> bool:
        """True when every content matches, in order, inside ONE payload."""
        if not self.matches:
            return False
        if self.established and not has_handshake:
            return False
        for payload in payloads:
            if not payload:
                continue
            prev_end: Optional[int] = None
            ok = True
            for m in self.matches:
                idx = m.find(payload, prev_end)
                if idx is None:
                    ok = False
                    break
                prev_end = idx + len(m.pattern)
            if ok:
                return True
        return False


def _mods_before_next_content(rule_text: str, content_end: int):
    tail = rule_text[content_end:]
    stop = tail.find("content:")
    if stop == -1:
        stop = len(tail)
    return MOD_RE.finditer(tail[:stop])


def parse_ruleset(path: Path = RULES,
                  sid_filter: Optional[set] = None) -> List[Rule]:
    """Parse alert rules carrying at least one `content:` match."""
    rules: List[Rule] = []
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.lower().startswith("alert"):
            continue
        sid_m = SID_RE.search(line)
        if not sid_m:
            continue
        sid = int(sid_m.group(1))
        if sid_filter is not None and sid not in sid_filter:
            continue

        contents = list(CONTENT_RE.finditer(line))
        if not contents:
            continue

        msg_m = MSG_RE.search(line)
        rule = Rule(sid=sid, msg=msg_m.group(1) if msg_m else "",
                    uses_unsupported=bool(UNSUPPORTED_RE.search(line)))
        flow_m = FLOW_RE.search(line)
        if flow_m:
            flags = flow_m.group(1).lower()
            rule.established = "established" in flags
            rule.to_server = "to_server" in flags
            rule.from_server = "from_server" in flags

        for cm in contents:
            match = ContentMatch(pattern=parse_content(cm.group(1)))
            for mod in _mods_before_next_content(line, cm.end()):
                tok = mod.group(1).lower().replace(" ", "")
                if tok == "nocase":
                    match.nocase = True
                elif tok.startswith("offset:"):
                    match.offset = int(tok.split(":")[1])
                elif tok.startswith("depth:"):
                    match.depth = int(tok.split(":")[1])
                elif tok.startswith("distance:"):
                    match.distance = int(tok.split(":")[1])
                elif tok.startswith("within:"):
                    match.within = int(tok.split(":")[1])
            rule.matches.append(match)
        rules.append(rule)
    return rules


# ---------------------------------------------------------------------------
# which rules actually fire on a capture
# ---------------------------------------------------------------------------
def firing_sids(capture: str, dataset: str = "stratosphere",
                conf: Path = SNORT_CONF) -> set:
    """SIDs the real Snort binary fires on this capture, unmutated.

    One ~10 s Snort pass, cached on disk, so repeated replica construction is
    free.  Filtering to the firing rules is sound: payload corruption can only
    DESTROY byte patterns, so a rule that never fires unmutated cannot start
    firing afterwards.
    """
    cache = REPO / "snort_validation/data/firing_sids.json"
    key = f"{dataset}:{capture}"
    if cache.exists():
        import json
        data = json.loads(cache.read_text())
        if key in data:
            return set(data[key])

    sys.path.insert(0, str(REPO / "ai_agent"))
    from real_packet_env import _capture_pcap
    pcap = _capture_pcap(capture, dataset)
    if pcap is None:
        raise FileNotFoundError(f"no pcap for {capture} ({dataset})")

    with tempfile.TemporaryDirectory(prefix="fire_") as tmp:
        subprocess.run(["snort", "-c", str(conf), "-r", str(pcap),
                        "-A", "fast", "-l", tmp, "-q"],
                       capture_output=True, timeout=900)
        alert = Path(tmp) / "alert"
        text = alert.read_text(errors="ignore") if alert.exists() else ""
    sids = {int(m) for m in re.findall(r"\[\d+:(\d+):\d+\]", text)}

    import json
    data = json.loads(cache.read_text()) if cache.exists() else {}
    data[key] = sorted(sids)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(data, indent=2))
    return sids


# ---------------------------------------------------------------------------
# flow-level evaluation
# ---------------------------------------------------------------------------
def _has_handshake(packets: Sequence) -> bool:
    from scapy.all import TCP
    flags = [int(p[TCP].flags) for p in packets if TCP in p]
    return any(f & 0x02 for f in flags) and any(f & 0x10 for f in flags)


def _initiator(packets: Sequence) -> Optional[str]:
    from scapy.all import IP, TCP, UDP
    for p in packets:
        if IP in p and (TCP in p or UDP in p):
            return p[IP].src
    return None


def _payloads(packets: Sequence, forward_only: bool = False) -> List[bytes]:
    from scapy.all import IP, Raw
    init = _initiator(packets) if forward_only else None
    out = []
    for p in packets:
        if Raw not in p:
            continue
        if forward_only and init is not None and p[IP].src != init:
            continue
        out.append(bytes(p[Raw].load))
    return out


class RealRulesReplica:
    """Evaluate real ET Open C2 rules against real packet payloads."""

    def __init__(self, rules: Sequence[Rule]):
        self.rules = list(rules)

    @classmethod
    def for_sids(cls, sids: set, path: Path = RULES) -> "RealRulesReplica":
        return cls(parse_ruleset(path, sid_filter=set(sids)))

    @classmethod
    def for_capture(cls, capture: str, dataset: str = "stratosphere",
                    path: Path = RULES) -> "RealRulesReplica":
        return cls.for_sids(firing_sids(capture, dataset), path)

    def _arms(self, packets: Sequence):
        handshake = _has_handshake(packets)
        fwd = _payloads(packets, forward_only=True)
        both = _payloads(packets, forward_only=False)
        return handshake, fwd, both

    def alert_count(self, packets: Sequence) -> int:
        """How many real rules fire -- the shaped reward signal."""
        if not packets:
            return 0
        handshake, fwd, both = self._arms(packets)
        n = 0
        for rule in self.rules:
            payloads = fwd if (rule.to_server and not rule.from_server) else both
            if rule.fires(payloads, handshake):
                n += 1
        return n

    def verdict(self, packets: Sequence) -> bool:
        """True = detected (alert), matching real Snort's semantics."""
        return self.alert_count(packets) > 0

    def firing_rules(self, packets: Sequence) -> List[Rule]:
        """Which rules fire -- for diagnosis, not for the reward."""
        if not packets:
            return []
        handshake, fwd, both = self._arms(packets)
        hit = []
        for rule in self.rules:
            payloads = fwd if (rule.to_server and not rule.from_server) else both
            if rule.fires(payloads, handshake):
                hit.append(rule)
        return hit


def coverage_report(capture: str, dataset: str = "stratosphere",
                    n_flows: int = 24) -> Dict:
    """Replica verdicts vs real Snort's measured alert counts."""
    sys.path.insert(0, str(REPO / "ai_agent"))
    from real_packet_env import RealPacketEnv

    env = RealPacketEnv(n_flows=n_flows, capture=capture, dataset=dataset)
    measured = env.baseline_alert_counts()
    replica = RealRulesReplica.for_capture(capture, dataset)

    agree = both_det = rep_det = 0
    for i, (_k, pkts) in enumerate(env.flows):
        r = replica.verdict(pkts)
        real = measured.get(i, 1) > 0
        rep_det += int(r)
        both_det += int(real)
        agree += int(r == real)
    return {"capture": capture, "flows": len(env.flows),
            "rules_loaded": len(replica.rules),
            "rules_with_unsupported": sum(r.uses_unsupported
                                          for r in replica.rules),
            "real_detected": both_det, "replica_detected": rep_det,
            "agree": agree,
            "agreement_pct": round(100 * agree / max(len(env.flows), 1), 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="botnet-capture-20110811-neris")
    ap.add_argument("--dataset", default="stratosphere")
    ap.add_argument("--flows", type=int, default=24)
    ap.add_argument("--dump-rules", action="store_true")
    args = ap.parse_args()

    if args.dump_rules:
        rep = RealRulesReplica.for_capture(args.capture, args.dataset)
        for r in rep.rules:
            print(f"sid:{r.sid} est={r.established} to_server={r.to_server} "
                  f"unsupported={r.uses_unsupported} n_content={len(r.matches)}")
            print(f"   {r.msg}")
        return 0

    print(coverage_report(args.capture, args.dataset, args.flows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
