#!/usr/bin/env python3
"""Fixed evaluation pipeline for the hidden-defender problem (6 critical fixes).

WHY THIS MODULE EXISTS
----------------------
The original scoring path (`hidden_defender_env.score`) was built for fast
surrogate training, not for the integrity-check evaluation.  Six properties it
lacked are required before any evasion number can be quoted:

  Fix 1  bidirectional flows       -- a flow must carry both directions or a
        ``flow:established`` rule never sees the session.
  Fix 2  client-only mutation      -- the attacker owns the client side only;
        rewriting the responder's bytes is outside the threat model.
  Fix 3  byte-equality semantics   -- the command is "preserved" only if the
        recovered CLIENT stream is byte-for-byte identical.  A parser that
        tolerates extra bytes is too loose to certify a real evasion.
  Fix 4  per-flow PCAP scoring     -- one flow per PCAP, one Snort call, so
        one flow's alert can never shadow another's.
  Fix 5  dynamic source translation-- a globally unique source (IP, port) per
        attempt, so ``threshold ... track by_src`` rules do not suppress an
        alert that a fresh attacker host would have raised.
  Fix 6  I/O sync                  -- wait for Snort to exit 0 and fsync the
        alert file before reading it; a crashed Snort must RAISE, never be
        read as "no alert" (which would score as an evasion).

The module is deliberately dependency-light (scapy + subprocess) so the tests
can exercise every fix without the RL stack or the 21k-rule replica.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parent.parent
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if str(REPO / "ai_agent") not in sys.path:
    sys.path.insert(0, str(REPO / "ai_agent"))

SNORT_CONF = _HERE / "et_open_c2" / "snort_et_c2.conf"

# Fix 5: a dedicated translation range, one address per attempt.  Distinct from
# the batch service's 198.51.100.0/24 so a per-flow run is never confused with
# a batched one.  RFC 5737 documentation range, as in snort_batch_service.
ATTEMPT_NET = "203.0.113."
ATTEMPT_PORT_BASE = 40000
MAX_ATTEMPTS = 250
_MAX_WAIT_S = 5.0


# ---------------------------------------------------------------------------
# Fix 1 helpers: direction / client identification
# ---------------------------------------------------------------------------
# Fix 2/5: the attacker controls the infected host.  In these C2 captures the
# bot (the "client" whose bytes the attacker owns) is the endpoint in the
# 147.32.84.0/24 honeynet; the other endpoint is the C2 peer/responder, whose
# bytes are outside the threat model.  A flow's 5-tuple initiator is NOT always
# the bot: neris C2 flows are captured in both directions.
HOME_NET_PREFIX = "147.32.84."


def client_ip_of(flow_id: str) -> str:
    """The attacker-controlled (bot) IP for a flow.

    The flow id is ``capture|src:sport->dst:dport|proto``.  The bot is the
    endpoint in ``HOME_NET_PREFIX`` when one is present; otherwise fall back to
    the flow initiator, which is the attacker for ordinary client-initiated
    C2 traffic.
    """
    endpoint = flow_id.split("|")[1]
    src = endpoint.split("->")[0].split(":")[0]
    dst = endpoint.split("->")[1].split(":")[0]
    for ip in (src, dst):
        if ip.startswith(HOME_NET_PREFIX):
            return ip
    return src


def server_ip_of(packets: Sequence, client_ip: str) -> Optional[str]:
    """The responder address: the other endpoint of the session."""
    from scapy.all import IP

    for p in packets:
        if IP in p and p[IP].src != client_ip:
            return p[IP].src
        if IP in p and p[IP].dst != client_ip:
            return p[IP].dst
    return None


def split_directions(packets: Sequence) -> Tuple[list, list]:
    """Return (client_packets, server_packets) for one bidirectional flow.

    The client is the flow's initiator: the source of the first IP packet.  A
    flow that is missing a direction returns an empty list for it, which the
    caller must treat as an extraction failure (Fix 1).
    """
    from scapy.all import IP

    ip_pkts = [p for p in packets if IP in p]
    if not ip_pkts:
        return [], []
    client_ip = ip_pkts[0][IP].src
    fwd = [p for p in ip_pkts if p[IP].src == client_ip]
    rev = [p for p in ip_pkts if p[IP].src != client_ip]
    return fwd, rev


