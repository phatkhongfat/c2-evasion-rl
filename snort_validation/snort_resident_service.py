#!/usr/bin/env python3
"""
Resident Snort service: score many flows with NO per-verdict rule reload.

THE PROBLEM
-----------
Measured with the batch service (one process per verdict):
    1 packet  -> 9.93 s
    120k pkts -> 11.8 s
~9.9 s of every call is loading the 21k ET Open C2 rules, and it is paid on
EVERY verdict.  Batching amortised it (one call per 200 flows) but the floor
remained: ~10 s per batch regardless of batch size.

THE FIX
-------
Start Snort ONCE in IDS mode on a loopback interface (``-i lo``), where it
loads the rules a single time and then inspects frames as they arrive.  The
"pcap" for a batch is not a file but a burst of frames replayed onto ``lo``;
Snort's fast-alert output is written to a FIFO that a reader thread drains.

The alert->flow mapping is unchanged from the batch service: each query's
packets are rewritten to carry a unique source address in 198.51.100.0/24, and
the id is parsed out of the alert line, which is direction-independent.

WHY THIS IS CHEAPER
-------------------
    per-verdict cost  = (frame replay time) + (reader latency)
                      ~ tens of ms, instead of ~9.9 s

Fallback: if the resident Snort cannot be started (no CAP_NET_RAW, no ``lo``,
Snort refusing IDS mode), ``ResidentSnortService.available()`` returns False and
callers can fall back to ``SnortBatchService``.

Usage:
    svc = ResidentSnortService()
    print(svc.stats())
    v = svc.verdicts_chunked([(packets, 0), (packets, 1)])
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parent.parent
DEFAULT_CONF = REPO / "snort_validation/et_open_c2/snort_et_c2.conf"
IFACE = "lo"

# Documentation range (RFC 5737).  Each query gets its OWN address AND port, and
# ids are NEVER reused within a run.  This is not cosmetic: ET content rules
# commonly carry `threshold: type limit, track by_src, count 1` (the ruleset even
# warns in-rule thresholds are deprecated), so a repeated source address inside
# the time window is THROTTLED and silently produces no alert.  Measured: the
# first injection of 24 flows gave 35 alert lines covering all 24 flows, and an
# immediate second injection of the SAME flows gave ZERO -- which made every
# later batch read as "no alert" (and produced impossible numbers such as
# "baseline detected 0/24" and a 100% evasion rate for a random policy).
QUERY_NET = "198.51."
QUERY_PORT_BASE = 40000
MAX_QUERIES_PER_BATCH = 250      # keeps one batch inside a single /24
UID_PER_NET = 200                # addresses per /24 before moving to the next


def _uid_to_addr_port(uid: int):
    """Map a globally unique query id to a unique (ip, port) pair."""
    hi = (uid // UID_PER_NET) % 250
    lo = (uid % UID_PER_NET) + 1
    return f"{QUERY_NET}{hi}.{lo}", QUERY_PORT_BASE + (uid % 20000)


def _uid_from_alert(text: str):
    """Recover the unique query id from an alert line, if present."""
    m = re.search(re.escape(QUERY_NET) + r"(\d{1,3})\.(\d{1,3})\b", text)
    if not m:
        return None
    return int(m.group(1)) * UID_PER_NET + (int(m.group(2)) - 1)


class ResidentSnortService:
    """One long-lived Snort process; verdicts by replaying frames onto ``lo``."""

    def __init__(self, conf: Path = DEFAULT_CONF, iface: str = IFACE,
                 startup_timeout: float = 40.0, verbose: bool = False,
                 max_pkts_per_flow: int = 0):
        self.conf = Path(conf)
        self.iface = iface
        self.verbose = verbose
        self.startup_timeout = startup_timeout
        # A single CTU-13 flow can carry thousands of packets (measured: one
        # flow had 7652), and scapy's per-packet Python overhead then dominates
        # (7907 frames took 3.95 s to BUILD but only 0.02 s to send).  0 = no
        # cap.  NOTE: capping CHANGES verdicts -- a 100-packet flow detected
        # one-shot was missed at a 40-packet cap, so the cap must match whatever
        # the reference service does, or the comparison is not like-for-like.
        self.max_pkts_per_flow = int(max_pkts_per_flow)
        self._proc: Optional[subprocess.Popen] = None
        self._reader: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._seen: set = set()
        self._lock = threading.Lock()
        self.n_calls = 0
        self.n_flows = 0
        self.seconds = 0.0
        self.send_seconds = 0.0
        self.last_send_s: Optional[float] = None
        self.last_total_s: Optional[float] = None
        self._tmp = Path(tempfile.mkdtemp(prefix="snortres_"))
        self._alert_path = self._tmp / "alert"
        self._uid_base = 0        # never reuse an id: ET rules throttle by_src
        self._started = False
        self.error: Optional[str] = None

    # -- lifecycle --------------------------------------------------------
    def start(self) -> bool:
        if self._started:
            return True
        try:
            self._alert_path.write_text("")
            self._proc = subprocess.Popen(
                ["snort", "-c", str(self.conf), "-i", self.iface,
                 "-A", "fast", "-l", str(self._tmp), "-q"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self._open_socket()
        except Exception as e:            # pragma: no cover
            self.error = f"spawn failed: {e}"
            return False

        self._reader = None
        self._started = False
        t0 = time.time()
        while time.time() - t0 < self.startup_timeout:
            if self._proc.poll() is not None:
                self.error = "snort exited during startup"
                return False
            # Ready only once it can actually INSPECT traffic.  A fixed sleep is
            # not enough: the service is used immediately by callers, and any
            # frames injected while Snort is still loading its 21k rules are
            # silently missed.  (That produced "baseline detected 0/24" in one
            # caller and 24/24 in another, purely depending on how much time
            # elapsed between start() and the first query.)
            if time.time() - t0 > 2.0 and self._probe_ready():
                self._started = True
                return True
            time.sleep(0.5)
        self.error = "startup timed out (readiness probe never alerted)"
        return False

    def _probe_ready(self) -> bool:
        """Inject one frame that must alert, and wait for its alert line."""
        try:
            from scapy.all import DNS, DNSQR, Ether, IP, UDP
            probe_ip, probe_port = _uid_to_addr_port(999999)
            probe = (Ether(dst="ff:ff:ff:ff:ff:ff")
                     / IP(src=probe_ip, dst="10.0.0.53")
                     / UDP(sport=probe_port, dport=53)
                     / DNS(rd=1, qd=DNSQR(qname="readiness-probe.su")))
            pos = self._file_size()
            self._sock.send(bytes(probe))
            deadline = time.time() + 3.0
            marker = probe_ip
            while time.time() < deadline:
                time.sleep(0.05)
                pos, data = self._read_from(pos)
                if data and marker in data.decode("utf-8", "ignore"):
                    return True
            return False
        except Exception:
            return False

    def available(self) -> bool:
        return self._started and self._proc is not None and \
            self._proc.poll() is None

    def stop(self) -> None:
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()

    # -- querying ---------------------------------------------------------
    def _open_socket(self):
        """One persistent RAW AF_PACKET socket, reused for every batch.

        Measured injection cost:
            scapy L2socket.send   ~0.4   ms/pkt
            raw AF_PACKET send    ~0.003 ms/pkt
        so frames are built once to bytes and written to a raw socket.
        """
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self._sock.bind((self.iface, 0))
        return self._sock

    def _build_frames(self, batch: Sequence[Tuple[List, int]],
                      uid_base: int = 0) -> List[bytes]:
        """Rewrite each flow onto its own query address, as raw frame bytes.

        The real CTU-13 packets ALREADY carry an Ether layer.  Wrapping them in
        another one produced Ether/Ether/IP, which Snort parses as a malformed
        frame and ignores entirely -- measured: double Ether -> 0 alerts,
        original Ether preserved -> 41 alerts.

        DIRECTION-AWARE REWRITE (required, not cosmetic)
        ------------------------------------------------
        Only the FLOW INITIATOR's packets get their source replaced; the
        responder's packets get their DESTINATION replaced instead.  Rewriting
        ``src`` on every packet makes the responder appear to answer a
        different host, which breaks every rule carrying ``flow:established``
        -- and the ET Open C2 set is built on them.  Measured on one real
        ``botnet-capture-20110811-neris`` flow whose 10 packets DO alert in
        file mode: rewriting ``src`` on all of them -> 0 alerts; rewriting only
        the initiator's ``src`` (responder's ``dst``) -> 1 alert.
        """
        from scapy.all import Ether, IP, TCP, UDP

        blobs: List[bytes] = []
        for packets, qid in batch:
            uid = uid_base + qid
            src_ip, src_port = _uid_to_addr_port(uid)
            client = packets[0][IP].src if packets else None
            for pkt in (packets if self.max_pkts_per_flow <= 0
                        else packets[:self.max_pkts_per_flow]):
                p = pkt.copy()
                if IP not in p:
                    continue
                if client is not None and p[IP].src != client:
                    p[IP].dst = src_ip
                    if UDP in p:
                        p[UDP].dport = src_port
                        del p[UDP].chksum
                    elif TCP in p:
                        p[TCP].dport = src_port
                        del p[TCP].chksum
                    del p[IP].chksum
                    if Ether not in p:
                        p = Ether(dst="ff:ff:ff:ff:ff:ff") / p
                    blobs.append(bytes(p))
                    continue
                p[IP].src = src_ip
                if UDP in p:
                    p[UDP].sport = src_port
                    del p[UDP].chksum
                elif TCP in p:
                    p[TCP].sport = src_port
                    del p[TCP].chksum
                del p[IP].chksum
                if Ether not in p:
                    p = Ether(dst="ff:ff:ff:ff:ff:ff") / p
                blobs.append(bytes(p))
        return blobs

    def _write_frames(self, batch: Sequence[Tuple[List, int]],
                      uid_base: int = 0) -> None:
        for blob in self._build_frames(batch, uid_base):
            self._sock.send(blob)

    def _read_from(self, pos: int):
        """Read alert bytes written after ``pos``; return (new_pos, bytes).

        Reads by PATH, not through a persistent fd.  Measured: opening the file
        once with O_RDWR and reading from it returned nothing at all, while
        reading the same bytes by path returned the full alert text -- so the
        long-lived descriptor was the bug that made every verdict look like
        "no alert" (observed as an impossible "baseline detected 0/24" and a
        100% evasion rate for a random policy).
        """
        try:
            with open(self._alert_path, "rb") as fh:
                fh.seek(pos)
                data = fh.read()
        except OSError:
            return pos, b""
        return pos + len(data), data

    def _file_size(self) -> int:
        try:
            return self._alert_path.stat().st_size
        except OSError:
            return 0

    def alert_counts_chunked(
            self, items: Sequence[Tuple[List, int]]) -> Dict[int, int]:
        """Score a batch from the alert bytes written after the send.

        No reader thread and no shared mutable state: the offset is taken from
        the file itself, so alerts can never be attributed to the wrong batch
        (a threaded version raced and produced nonsense verdicts).
        """
        if not self.available():
            raise RuntimeError(f"resident snort unavailable: {self.error}")

        out: Dict[int, int] = {}
        for i in range(0, len(items), MAX_QUERIES_PER_BATCH):
            chunk = items[i:i + MAX_QUERIES_PER_BATCH]
            uid_base = self._uid_base
            self._uid_base += MAX_QUERIES_PER_BATCH   # never reuse ids
            t0 = time.time()
            pos = self._file_size()          # everything before is old
            self._write_frames(chunk, uid_base)
            send_s = time.time() - t0

            counts: Dict[int, int] = {qid: 0 for _p, qid in chunk}
            buf = b""
            # Snort writes its fast-alert file through a BUFFERED stream, so a
            # batch's alerts do not appear until the stream is flushed.  The
            # whole batch lands in ONE flush (measured: 1 size-growth event per
            # batch), but the first flush can be late: over 25 batches of 96
            # flows the first-alert latency was 0.28-1.25 s (mean 0.77 s).
            #
            # The previous floor of 0.60 s therefore closed the window BEFORE
            # the flush and scored every flow as "no alert".  That is the true
            # cause of the impossible "baseline detected 0/24" -- NOT alert
            # cross-talk between batches: the per-batch uid stride already
            # isolates alerts correctly (alerts from an earlier batch carry an
            # earlier uid_base, so they fall outside ``counts`` and are
            # discarded rather than misattributed).
            #
            # The floor must exceed the worst observed flush latency; 2.5 s is
            # ~2x the measured maximum.  A batch that genuinely evades emits no
            # alerts at all, so the floor (not a "saw data" test) is what
            # terminates the read in that case.
            #
            # CONCURRENCY HAZARD: every instance shares iface ``lo``, so two
            # resident services running at once INSPECT EACH OTHER'S frames and
            # both read nonsense (measured: one run's controls inverted to
            # argmax 0% / random 100% while an identical run in isolation
            # reproduced file mode exactly).  Run one resident bandit at a time,
            # or give each run its own interface.
            quiet_needed, min_elapsed = 0.35, 2.5
            last_change = time.time()
            deadline = time.time() + 8.0
            while time.time() < deadline:
                time.sleep(0.01)
                pos, data = self._read_from(pos)
                if data:
                    buf += data
                    last_change = time.time()
                    continue
                if (time.time() - last_change > quiet_needed
                        and time.time() - t0 > min_elapsed):
                    break

            for line in buf.decode("utf-8", "ignore").splitlines():
                if QUERY_NET not in line:
                    continue
                uid = _uid_from_alert(line)
                if uid is None:
                    continue
                qid = uid - uid_base
                if qid in counts:
                    counts[qid] += 1

            self.n_calls += 1
            self.n_flows += len(chunk)
            self.seconds += time.time() - t0
            self.send_seconds += send_s
            self.last_send_s = send_s
            self.last_total_s = time.time() - t0
            out.update(counts)
        return out

    def verdicts_chunked(self, items) -> Dict[int, bool]:
        return {q: (c > 0)
                for q, c in self.alert_counts_chunked(items).items()}

    def restart(self) -> bool:
        """Kill and relaunch Snort, keeping the query-id counter.

        The plan requires sweep/scale/cross-capture loops to survive a Snort
        crash.  Reusing ``self._uid_base`` matters: ET rules throttle
        ``by_src``, so a restarted process that reused query addresses would
        silently report "no alert" for flows that do alert.
        """
        self.stop()
        self._started = False
        self._proc = None
        self.error = None
        return self.start()

    def stats(self) -> Dict:
        return {"mode": "resident", "iface": self.iface,
                "available": self.available(), "error": self.error,
                "snort_calls": self.n_calls, "flows": self.n_flows,
                "seconds": round(self.seconds, 1),
                "send_seconds": round(self.send_seconds, 3),
                "last_send_s": (round(self.last_send_s, 4)
                                if self.last_send_s is not None else None),
                "last_total_s": (round(self.last_total_s, 4)
                                 if self.last_total_s is not None else None),
                "ms_per_flow": (round(1000 * self.seconds / self.n_flows, 2)
                                if self.n_flows else None)}


def _selftest() -> int:
    """Correctness + timing: resident verdicts vs the one-shot batch service."""
    sys.path.insert(0, str(REPO / "ai_agent"))
    sys.path.insert(0, str(REPO / "snort_validation"))
    import numpy as np
    from snort_batch_service import SnortBatchService

    svc = ResidentSnortService(verbose=True)
    print("[*] starting resident snort ...")
    if not svc.start():
        print(f"[!] could not start resident snort: {svc.error}")
        return 2
    print(f"[+] resident snort up (pid {svc._proc.pid})")

    # real flows, mixed positives (bot capture) and negatives (neris capture)
    from real_packet_env import RealPacketEnv
    pos_env = RealPacketEnv(n_flows=6, batch_size=6,
                            capture="botnet-capture-20110819-bot")
    neg_env = RealPacketEnv(n_flows=6, batch_size=6,
                            capture="botnet-capture-20110810-neris")
    flows = [pk for _k, pk in pos_env.flows] + [pk for _k, pk in neg_env.flows]
    items = [(pk, i) for i, pk in enumerate(flows)]
    print(f"[*] {len(items)} flows "
          f"({len(pos_env.flows)} from bot, {len(neg_env.flows)} from neris)")

    # ground truth via the one-shot batch service
    ref = SnortBatchService(batch_size=len(items))
    truth = ref.verdicts_chunked(items)
    print(f"[*] ground truth (one-shot): {sum(truth.values())}/{len(items)} "
          f"detected")

    t0 = time.time()
    got = svc.verdicts_chunked(items)
    dt = time.time() - t0
    agree = sum(1 for i in truth if got.get(i) == truth[i])
    print(f"[*] resident: {sum(got.values())}/{len(items)} detected "
          f"in {dt:.2f}s ({1000*dt/len(items):.1f} ms/flow)")
    print(f"[*] agreement: {agree}/{len(truth)}")

    for i in sorted(truth):
        mark = "OK " if got.get(i) == truth[i] else "DIFF"
        if mark == "DIFF":
            print(f"    {mark} flow {i}: truth={truth[i]} resident={got.get(i)}")

    print(f"[*] stats: {svc.stats()}")
    print(f"[*] one-shot cost was ~9.9s rule load per call; "
          f"resident amortised it to {dt:.2f}s for {len(items)} flows")
    svc.stop()
    return 0 if agree == len(truth) else 1


if __name__ == "__main__":
    sys.exit(_selftest())
