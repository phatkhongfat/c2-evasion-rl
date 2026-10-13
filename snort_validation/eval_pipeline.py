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


# http_header_case helper (mirrors hidden_defender_env): the field-name token
# of a header line (RFC 7230 s3.2 token grammar), matched at line start only.
_HEADER_NAME_RE = re.compile(rb"^([!#$%&'*+.^_`|~0-9A-Za-z-]+):")


def _lower_field_names(head: bytes) -> bytes:
    """Lower-case the field NAME of every header line; leave values alone."""
    lines = head.split(b"\r\n")
    out = [lines[0]]
    for line in lines[1:]:
        m = _HEADER_NAME_RE.match(line)
        out.append(line if m is None else m.group(1).lower() + b":" + line[m.end():])
    return b"\r\n".join(out)


# ---------------------------------------------------------------------------
# Fix 1 helpers: direction / client identification
# ---------------------------------------------------------------------------
# The client identity rule and the strict semantics bar live in c2_semantics so
# the TRAINING reward and this evaluation cannot drift apart (Fix 3).  Imported
# at module level: c2_semantics imports nothing from here, so there is no cycle.
from c2_semantics import (  # noqa: E402
    HOME_NET_PREFIX as HOME_NET_PREFIX,
    bytes_equal_semantics as bytes_equal_semantics,
    client_ip_of as client_ip_of,
    endpoint_command_preserved as endpoint_command_preserved,
    endpoint_commands_preserved as endpoint_commands_preserved,
    endpoint_query_preserved as endpoint_query_preserved,
    ensure_chain as ensure_chain,
    reassembled_client_bytes as reassembled_client_bytes,
    as_raw as as_raw,
    server_ip_of as server_ip_of,
)


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


# ---------------------------------------------------------------------------
# Fix 2 + 5: mutation is client-only, on a dynamically translated source
# ---------------------------------------------------------------------------
def mutate_client_only(packets: Sequence, mech: str, client_ip: Optional[str] = None,
                        ownership: str = "client"):
    """Apply a mechanism while touching ONLY the client's packets (Fix 2).

    This does NOT delegate to ``hidden_defender_env.apply_mech``: that function
    splits/reorders/rewrites TTL on *every* packet regardless of
    ``payload_indices``, so it mutates the responder's bytes too.  The attacker
    owns the client side only, so each mechanism is re-implemented here over the
    client packet set alone.  ``client_ip`` defaults to the flow initiator.

    ownership="client" (default): conservative, server untouched.
    ownership="both": allow mutating server's payload packets too (mirrors env)
    to test the two-sided bar.
    """
    if ownership not in ("client", "both"):
        raise ValueError(f"ownership must be 'client' or 'both', got {ownership!r}")
    from scapy.all import IP, Raw, TCP, UDP
    from fragment_ops import (fragment_plan_to_packets, fix_checksums,  # noqa: E501
                              has_payload, make_slow_fragments,
                              overlap_fragments, split_fragments,
                              transport_payload)
    from endpoint_model import is_http_request
    from hidden_defender_env import _JUNK_HEADERS, _WRAP_OFFSET

    # ensure_chain: a lazily unpickled packet reports `IP in p` as False, which
    # would empty client_idx and make the mechanism a silent no-op.
    out = [ensure_chain(p).copy() for p in packets]
    if client_ip is None:
        ip_pkts = [p for p in out if IP in p]
        client_ip = ip_pkts[0][IP].src if ip_pkts else None

    client_idx = [i for i, p in enumerate(out)
                  if IP in p and p[IP].src == client_ip]
    payload_idx = [i for i in client_idx
                   if has_payload(out[i])]

    tgt_idx = list(payload_idx)
    sip = None
    if ownership == "both" and client_ip:
        from c2_semantics import server_ip_of
        sip = server_ip_of(out, client_ip)
        srv_idx = [i for i, p in enumerate(out)
                   if IP in p and sip is not None and p[IP].src == sip]
        srv_pay = [i for i in srv_idx
                   if has_payload(out[i])]
        tgt_idx = sorted(set(payload_idx) | set(srv_pay))

    if mech == "split_slow":
        # Byte-safe fragmentation with the tail held back past frag3's default
        # 60s timeout. Bytes and offsets are untouched, so the two-stream
        # byte-equality bar passes by construction. Intercepted BEFORE the
        # generic startswith("split") branch below, which would try
        # int("slow").
        rebuilt: list = []
        for i, p in enumerate(out):
            out_frags = None
            if i in tgt_idx:
                payload = transport_payload(p)
                if 0 < 8 < len(payload):
                    try:
                        out_frags = fragment_plan_to_packets(
                            out, make_slow_fragments(payload, 8), i)
                    except ValueError:
                        out_frags = None
            if out_frags is not None:
                # Turn the per-fragment delay into a real timestamp gap so
                # frag3's timeout window actually sees the separation.
                t = float(getattr(p, "time", 0.0) or 0.0)
                for f in out_frags:
                    f.time = t
                    t += 75.0
                rebuilt.extend(out_frags)
            else:
                rebuilt.append(p)
        return rebuilt

    if mech.startswith("split"):
        off = int(mech[5:])
        rebuilt: list = []
        for i, p in enumerate(out):
            out_frags = None
            if i in tgt_idx:
                payload = transport_payload(p)
                if 0 < off < len(payload):
                    try:
                        out_frags = fragment_plan_to_packets(out, split_fragments(payload, off), i)
                    except ValueError:
                        out_frags = None
            if out_frags is not None:
                rebuilt.extend(out_frags)
            else:
                rebuilt.append(p)
        return rebuilt

    if mech == "overlap8":
        rebuilt = []
        for i, p in enumerate(out):
            out_frags = None
            if i in tgt_idx:
                payload = transport_payload(p)
                if 8 < len(payload):
                    try:
                        out_frags = fragment_plan_to_packets(out, overlap_fragments(payload, 8), i)
                    except ValueError:
                        out_frags = None
            if out_frags is not None:
                rebuilt.extend(out_frags)
            else:
                rebuilt.append(p)
        return rebuilt

    if mech == "http_header_pad":
        for i in payload_idx:
            out[i] = as_raw(out[i])
            raw = bytes(out[i][Raw].load)
            if not is_http_request(raw):
                continue
            head, sep, body = raw.partition(b"\r\n")
            if not sep:
                continue
            out[i][Raw].load = head + b"\r\n" + _JUNK_HEADERS + body

    elif mech == "http_header_case":
        # RFC 7230 s3.2: field names are case-insensitive, so folding the NAME
        # changes the wire but not the meaning of the request.  Breaks Snort
        # rule SID 2012627 (FakeAV C2 check-in), which matches `Accept|3a 20|`
        # case-SENSITIVELY as part of a 4-content distance:0 adjacency chain.
        # This is a property of the ET Open ruleset signature, not a general
        # technique.  Nothing legal goes after the request line on a non-HTTP
        # framing, so guard on is_http_request like the pad mech.
        for i in payload_idx:
            out[i] = as_raw(out[i])
            raw = bytes(out[i][Raw].load)
            if not is_http_request(raw):
                continue
            head, sep, body = raw.partition(b"\r\n\r\n")
            if not sep:
                continue
            out[i][Raw].load = _lower_field_names(head) + b"\r\n\r\n" + body

    elif mech == "query_param_prepend":
        # Insert one benign query parameter right after the '?'.  Breaks the
        # literal content-chains that anchor on "<path>?<firstkey>=" -- e.g.
        # sid:2012533 (Virut.BN checkin) matches content:"list.php?c=" within:32
        # plus "&v="/"&t=" distance:0 and a pcre on the c= value -- while every
        # standard query parser still recovers c/v/t identically (split '&' then
        # '='; RFC 3986: the inserted key x=0 is simply unknown to the handler).
        # Request line only; body and other packets untouched.  +4 bytes, no
        # fragmentation.  Client-owned by construction (the request line is the
        # bot's), so payload_idx is used regardless of `ownership`.  EVERY
        # request-bearing packet is rewritten -- the fast-flux capture repeats
        # the same GET twice in one flow, and Snort alerts on either copy, so
        # stopping after the first would leave the rule firing on the second.
        for i in payload_idx:
            out[i] = as_raw(out[i])
            raw = bytes(out[i][Raw].load)
            if not is_http_request(raw):
                continue
            head, sep, rest = raw.partition(b"\r\n")
            if not sep:
                continue
            parts = head.split(b" ")
            if len(parts) < 2 or b"?" not in parts[1]:
                continue
            uri = parts[1]
            q = uri.index(b"?")
            parts[1] = uri[:q + 1] + b"x=0&" + uri[q + 1:]
            out[i][Raw].load = b" ".join(parts) + sep + rest

    elif mech == "length_wrapper":
        for i in payload_idx:
            out[i] = as_raw(out[i])
            out[i] = fix_checksums(
                out[i], b"LEN%d:" % _WRAP_OFFSET + bytes(_WRAP_OFFSET)
                + bytes(out[i][Raw].load))
            break

    elif mech.startswith("pad"):
        n = int(mech[3:])
        for i in tgt_idx:
            out[i] = as_raw(out[i])
            out[i][Raw].load = bytes(out[i][Raw].load) + bytes(n)

    elif mech.startswith("prepend"):
        n = int(mech[7:])
        for i in tgt_idx:
            out[i] = as_raw(out[i])
            out[i][Raw].load = bytes(n) + bytes(out[i][Raw].load)

    elif mech.startswith("corrupt"):
        k = int(mech[7:])
        for i in tgt_idx:
            out[i] = as_raw(out[i])
            pl = bytearray(bytes(out[i][Raw].load))
            for j in range(min(k, len(pl))):
                pl[j] = (j * 97 + 13) % 256
            out[i][Raw].load = bytes(pl)

    elif mech == "reorder":
        own = client_idx
        if ownership == "both" and sip:
            srv_idx = [i for i, p in enumerate(out)
                       if IP in p and p[IP].src == sip]
            own = sorted(set(client_idx) | set(srv_idx))
        if len(own) >= 3:
            a, b = own[1], own[2]
            out[a], out[b] = out[b], out[a]

    elif mech == "ttl":
        own = client_idx
        if ownership == "both" and sip:
            srv_idx = [i for i, p in enumerate(out)
                       if IP in p and p[IP].src == sip]
            own = sorted(set(client_idx) | set(srv_idx))
        for i in own:
            if IP in out[i]:
                out[i][IP].ttl = 33

    elif mech == "noop":
        pass

    if mech not in ("reorder", "ttl", "noop"):
        for p in out:
            if Raw not in p:
                continue
            if IP in p:
                del p[IP].chksum
            if UDP in p:
                del p[UDP].chksum
            elif TCP in p:
                del p[TCP].chksum
    else:
        for p in out:
            if IP in p:
                del p[IP].chksum
    return out


def attempt_source_ip(attempt_id: int) -> str:
    """Deterministic unique source address for one attempt (Fix 5)."""
    if attempt_id < 0:
        raise ValueError("attempt_id must be >= 0")
    if attempt_id >= MAX_ATTEMPTS:
        raise ValueError(
            f"attempt_id {attempt_id} exceeds the /24 translation range "
            f"({MAX_ATTEMPTS} attempts); run in chunks")
    return f"{ATTEMPT_NET}{1 + (attempt_id % 254)}"


def attempt_source_port(attempt_id: int) -> int:
    return ATTEMPT_PORT_BASE + (attempt_id % 60000)


def translate_source(packets: Sequence, client_ip: str, attempt_id: int,
                     force_new_port: bool = False):
    """Rewrite the client's (IP, port) to a unique per-attempt pair (Fix 5).

    Only the CLIENT side is translated.  Server packets keep their real address
    so the session stays coherent; the client's own packets have their source
    rewritten, and any server->client packet addressed to the old client IP has
    its destination rewritten so the conversation still pairs up.  Checksums
    are dropped for scapy to recompute.
    """
    from scapy.all import IP, TCP, UDP

    new_ip = attempt_source_ip(attempt_id)
    new_port = attempt_source_port(attempt_id)
    out = []
    for pkt in packets:
        p = pkt.copy()
        if IP not in p:
            out.append(p)
            continue
        if p[IP].src == client_ip:
            p[IP].src = new_ip
            if TCP in p:
                p[TCP].sport = new_port
                del p[TCP].chksum
            elif UDP in p:
                p[UDP].sport = new_port
                del p[UDP].chksum
            del p[IP].chksum
        elif p[IP].dst == client_ip:
            # server -> client: keep the responder's address, retarget the client
            p[IP].dst = new_ip
            if TCP in p:
                p[TCP].dport = new_port
                del p[TCP].chksum
            elif UDP in p:
                p[UDP].dport = new_port
                del p[UDP].chksum
            del p[IP].chksum
        out.append(p)
    return out


# ---------------------------------------------------------------------------
# Fix 3: byte-equality semantics -- imported from c2_semantics (shared with the
# training reward) so the two bars cannot drift.  See the import block above.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Fix 4 + 6: one PCAP, one Snort call, synchronized read
# ---------------------------------------------------------------------------
_ALERT_LINE = re.compile(r"\[\*\*\]")
_SID_RE = re.compile(r"\[\d+:(\d+):\d+\]")   # [1:SID:rev] trong dòng alert fast


def _run_snort(pcap: Path, conf: Path, logdir: Path,
               timeout: int = 600) -> "tuple[int, list[int]]":
    """Run Snort on ONE pcap, wait for exit, fsync, then return
    (alert_count, fired_sids).

    Fix 6: a non-zero exit RAISES.  Silently returning 0 alerts on a crashed
    Snort would score every flow as evaded -- the single most dangerous failure
    mode in this pipeline.  Fix 4: this function is called once per flow.
    sids -> P2 severity stratification (plan 2026-10-07).
    """
    logdir.mkdir(parents=True, exist_ok=True)
    for stale in logdir.glob("alert*"):
        stale.unlink()

    proc = subprocess.run(
        ["snort", "-c", str(conf), "-r", str(pcap),
         "-l", str(logdir), "-q", "-A", "fast"],
        capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Snort exited {proc.returncode} on {pcap}: {proc.stderr.strip()[:400]}")

    # The file is closed once subprocess.run returns, but the page cache may
    # not be visible to a fresh open on some filesystems; fsync + a bounded
    # wait removes the race without an unconditional sleep on the happy path.
    alerts = sorted(logdir.glob("alert*"))
    deadline = time.time() + _MAX_WAIT_S
    while not alerts and time.time() < deadline:
        time.sleep(0.02)
        alerts = sorted(logdir.glob("alert*"))
    n = 0
    sids: set = set()
    for af in alerts:
        try:
            fd = os.open(af, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass
        with open(af, errors="ignore") as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    n += 1
                    # fired sids -> P2 severity stratification
                    sids.update(int(x) for x in _SID_RE.findall(line))
    return n, sorted(sids)


def run_snort_single(pcap: Path, conf: Path, logdir: Path,
                     timeout: int = 600) -> int:
    """Back-compat wrapper: chỉ trả số alert như trước (plan P2)."""
    return _run_snort(pcap, conf, logdir, timeout)[0]


def score_flow_real(packets: Sequence, client_ip: str, attempt_id: int,
                    conf: Path = SNORT_CONF, workdir: Optional[Path] = None,
                    mech: Optional[str] = None,
                    ownership: str = "client") -> dict:
    """Score ONE (flow, mechanism) with real Snort, end to end.

    Returns a dict with the alert verdict, the per-flow Snort call count, the
    translated source, and the semantics verdict under the byte-equality bar.
    ``mech=None`` scores the unmodified (baseline) flow.  ``ownership``
    selects the threat model: mechanisms may rewrite 'client' packets only
    (default) or 'both' endpoints (two-sided model, still under the strict
    two-stream bar).
    """
    import tempfile

    from scapy.all import wrpcap

    tmp = Path(workdir) if workdir else Path(
        tempfile.mkdtemp(prefix="evalflow_"))
    tmp.mkdir(parents=True, exist_ok=True)

    orig = [p.copy() for p in packets]
    if mech is not None:
        mut = mutate_client_only(orig, mech, client_ip, ownership=ownership)
    else:
        mut = orig
    sem = bytes_equal_semantics(orig, mut, client_ip)
    endpoint_ok = endpoint_command_preserved(orig, mut, client_ip)
    endpoint_q_ok = endpoint_commands_preserved(orig, mut, client_ip)
    query_ok = endpoint_query_preserved(orig, mut, client_ip)

    translated = translate_source(mut, client_ip, attempt_id)
    pcap = tmp / f"flow_{attempt_id}.pcap"
    wrpcap(str(pcap), translated)

    n_alerts, fired_sids = _run_snort(pcap, conf, tmp / "log")
    return {
        "attempt_id": attempt_id,
        "source_ip": attempt_source_ip(attempt_id),
        "source_port": attempt_source_port(attempt_id),
        "alert": n_alerts > 0,
        "n_alerts": n_alerts,
        "evaded": n_alerts == 0,
        "semantics_ok": sem,
        "valid_evasion": (n_alerts == 0) and sem,
        "endpoint_ok": endpoint_ok,
        "valid_evasion_endpoint": (n_alerts == 0) and endpoint_ok,
        "endpoint_q_ok": endpoint_q_ok,
        "valid_evasion_endpoint_q": (n_alerts == 0) and endpoint_q_ok,
        "query_ok": query_ok,
        "valid_evasion_query": (n_alerts == 0) and query_ok,
        "sids": fired_sids,          # fired sids -> P2 severity stratification
        "n_snort_calls": 1,
    }

