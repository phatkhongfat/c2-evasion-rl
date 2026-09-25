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

QUERY_NET = "198.51.100."
MAX_QUERIES_PER_BATCH = 250
_QUERY_IP_RE = re.compile(re.escape(QUERY_NET) + r"(\d{1,3})\b")


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
        self._started = False
        self.error: Optional[str] = None

    # -- lifecycle --------------------------------------------------------
    def start(self) -> bool:
        if self._started:
            return True
        try:
            self._alert_path.write_text("")
            fd = os.open(str(self._alert_path), os.O_RDWR)
            self._alert_fd = fd
            os.set_blocking(fd, False)

            self._proc = subprocess.Popen(
                ["snort", "-c", str(self.conf), "-i", self.iface,
                 "-A", "fast", "-l", str(self._tmp), "-q"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self._open_socket()
        except Exception as e:            # pragma: no cover
            self.error = f"spawn failed: {e}"
            return False

        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

        t0 = time.time()
        while time.time() - t0 < self.startup_timeout:
            if self._proc.poll() is not None:
                self.error = "snort exited during startup"
                return False
            # ready once it has been alive long enough to load rules and the
            # alert file is open for appends
            if time.time() - t0 > 3.0:
                self._started = True
                return True
            time.sleep(0.5)
        self.error = "startup timed out"
        return False

    def available(self) -> bool:
        return self._started and self._proc is not None and \
            self._proc.poll() is None

    def _read_loop(self) -> None:
        """Drain the alert FIFO and record query ids."""
        while not self._stop.is_set():
            try:
                data = os.read(self._alert_fd, 65536)
            except BlockingIOError:
                time.sleep(0.002)
                continue
            except OSError:
                break
            if not data:
                time.sleep(0.002)
                continue
            text = data.decode("utf-8", "ignore")
            for line in text.splitlines():
                if QUERY_NET not in line:
                    continue
                m = _QUERY_IP_RE.search(line)
                if m:
                    with self._lock:
                        self._seen.add(int(m.group(1)) - 1)

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

    def _build_frames(self, batch: Sequence[Tuple[List, int]]) -> List[bytes]:
        """Rewrite each flow onto its own query address, as raw frame bytes.

        The real CTU-13 packets ALREADY carry an Ether layer.  Wrapping them in
        another one produced Ether/Ether/IP, which Snort parses as a malformed
        frame and ignores entirely -- measured: double Ether -> 0 alerts,
        original Ether preserved -> 41 alerts.
        """
        from scapy.all import Ether, IP, TCP, UDP

        blobs: List[bytes] = []
        for packets, qid in batch:
            src_ip = f"{QUERY_NET}{1 + (qid % 254)}"
            for pkt in (packets if self.max_pkts_per_flow <= 0
                        else packets[:self.max_pkts_per_flow]):
                p = pkt.copy()
                if IP not in p:
                    continue
                p[IP].src = src_ip
                if UDP in p:
                    del p[UDP].chksum
                elif TCP in p:
                    del p[TCP].chksum
                del p[IP].chksum
                if Ether not in p:
                    p = Ether(dst="ff:ff:ff:ff:ff:ff") / p
                blobs.append(bytes(p))
        return blobs

    def _write_frames(self, batch: Sequence[Tuple[List, int]]) -> None:
        for blob in self._build_frames(batch):
            self._sock.send(blob)

    def alert_counts_chunked(
            self, items: Sequence[Tuple[List, int]]) -> Dict[int, int]:
        if not self.available():
            raise RuntimeError(f"resident snort unavailable: {self.error}")

        out: Dict[int, int] = {}
        for i in range(0, len(items), MAX_QUERIES_PER_BATCH):
            chunk = items[i:i + MAX_QUERIES_PER_BATCH]
            t0 = time.time()
            with self._lock:
                self._seen.clear()
            t_send = time.time()
            self._write_frames(chunk)
            send_s = time.time() - t_send
            # Settle.  Measured: alerts appear up to ~0.25 s after injection,
            # so a quiet window that starts immediately would expire BEFORE the
            # first alert and return an empty snapshot (that produced a bogus
            # 0/12 result).  Require a minimum elapsed time before allowing the
            # quiet-window break.
            quiet_needed = 0.30
            min_elapsed = 0.60
            deadline = time.time() + 8.0
            last = time.time()
            prev = -1
            snapshot = set()
            while time.time() < deadline:
                time.sleep(0.01)
                with self._lock:
                    cur = len(self._seen)
                    snapshot = set(self._seen)
                if cur != prev:
                    prev = cur
                    last = time.time()
                elif (time.time() - last > quiet_needed
                      and time.time() - t0 > min_elapsed):
                    break

            self.n_calls += 1
            self.n_flows += len(chunk)
            self.seconds += time.time() - t0
            self.send_seconds += send_s
            self.last_send_s = send_s
            self.last_total_s = time.time() - t0
            for _pkts, qid in chunk:
                out[qid] = 1 if qid in snapshot else 0
        return out

    def verdicts_chunked(self, items) -> Dict[int, bool]:
        return {q: (c > 0)
                for q, c in self.alert_counts_chunked(items).items()}

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
