#!/usr/bin/env python3
"""
Batched real-Snort verdict service.

PROBLEM
-------
Snort 2.9 spends ~10 s loading the 21k ET Open C2 rules *per invocation*,
independent of pcap size (measured: 5 packets -> 9.9 s, 120k packets -> 10.9 s).
Calling it once per RL step would take ~139 h for a 50k-step run.

SOLUTION
--------
Amortise the rule load across many flows: put N flows into ONE pcap, run Snort
once, and map alerts back to flows by 5-tuple.  Cost becomes ~10 s / N instead
of 10 s / flow, so N=512 gives ~20 ms/flow -- the same order as the surrogate,
but with REAL Snort semantics and no surrogate-reality gap.

WHY THE 5-TUPLE REWRITE IS SOUND
--------------------------------
Each query gets a unique source IP/port.  Destination address/port and payload
bytes are preserved, so port-based and content-based rules still see exactly
what they would see for the original flow.  $HOME_NET/$EXTERNAL_NET are both
`any` in snort_et_c2.conf, so rewriting the source does not change which rules
are eligible.

Usage (library):
    svc = SnortBatchService()
    verdicts = svc.verdicts([(packets_a, key_a), (packets_b, key_b), ...])
    # -> {key_a: bool, key_b: bool}

Usage (self-test, checks batch == per-flow ground truth):
    python snort_validation/snort_batch_service.py --selftest
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

_HERE = Path(__file__).resolve().parent
REPO = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

SNORT_CONF = _HERE / "et_open_c2" / "snort_et_c2.conf"

ALERT_RE = re.compile(
    r"\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*"
    r"(?P<msg>.*?)\s*\[\*\*\].*?"
    r"\{(?P<proto>TCP|UDP|ICMP)\}\s*"
    r"(?P<src>[\d.]+):(?P<sport>\d+)\s*->\s*(?P<dst>[\d.]+):(?P<dport>\d+)"
)

# Documentation range (RFC 5737).  Each query gets its OWN address so the
# alert->query mapping survives whichever direction the alerting packet went:
# a client->server hit logs the address as src, a server->client hit logs it
# as dst.  Extracting the id from the address (not the port) makes the mapping
# direction-independent, which port-based extraction was not.
QUERY_NET = "198.51.100."
QUERY_PORT_BASE = 40000
MAX_QUERIES_PER_BATCH = 250      # keeps addresses inside 198.51.100.0/24
_QUERY_IP_RE = re.compile(re.escape(QUERY_NET) + r"(\d{1,3})\b")


class SnortBatchService:
    """Resolve many flow verdicts with one Snort invocation per batch."""

    def __init__(self, conf: Path = SNORT_CONF, workdir: Optional[Path] = None,
                 batch_size: int = 200, keep_artifacts: bool = False):
        self.conf = Path(conf)
        # Each query needs its own source address for direction-independent
        # alert mapping, so a batch can never exceed the /24.
        self.batch_size = max(1, min(int(batch_size), MAX_QUERIES_PER_BATCH))
        self.keep = keep_artifacts
        self._tmp = Path(workdir) if workdir else Path(
            tempfile.mkdtemp(prefix="snortbatch_"))
        self._tmp.mkdir(parents=True, exist_ok=True)
        self.n_calls = 0
        self.n_flows = 0
        self.seconds = 0.0

    # -- pcap writing -----------------------------------------------------
    def _write_batch_pcap(self, batch: Sequence[Tuple[List, int]], path: Path):
        """Write all flows into one pcap with unique source 5-tuples.

        ``batch`` is a sequence of (packets, query_id).  Each packet must be a
        scapy packet with IP/TCP or IP/UDP layers.  The source IP/port is
        rewritten so alerts map back to the query; destination and payload are
        left untouched.
        """
        from scapy.all import IP, TCP, UDP, wrpcap

        out = []
        for packets, qid in batch:
            # one unique address per query (direction-independent mapping)
            src_ip = f"{QUERY_NET}{1 + (qid % 254)}"
            src_port = QUERY_PORT_BASE + (qid % 60000)
            for pkt in packets:
                p = pkt.copy()
                p[IP].src = src_ip
                if UDP in p:
                    p[UDP].sport = src_port
                    # Delete the TRANSPORT checksum explicitly.  A bare
                    # `del p.chksum` only removes the IP-layer checksum,
                    # leaving a stale UDP/TCP checksum; Snort then discards
                    # the datagram and content rules never fire (measured:
                    # alert present without rewrite, absent with it).
                    del p[UDP].chksum
                elif TCP in p:
                    p[TCP].sport = src_port
                    del p[TCP].chksum
                del p[IP].chksum
                out.append(p)
        wrpcap(str(path), out)

    # -- verdicts ---------------------------------------------------------
    def verdicts(self, batch: Sequence[Tuple[List, int]]) -> Dict[int, bool]:
        """Return {query_id: detected} for one batch (single Snort call)."""
        if not batch:
            return {}
        pcap = self._tmp / "batch.pcap"
        logdir = self._tmp / "batch_log"
        logdir.mkdir(exist_ok=True)
        for stale in logdir.glob("alert*"):
            stale.unlink()

        self._write_batch_pcap(batch, pcap)

        t0 = time.time()
        subprocess.run(
            ["snort", "-c", str(self.conf), "-r", str(pcap),
             "-l", str(logdir), "-q", "-A", "fast"],
            capture_output=True, text=True, timeout=600)
        self.seconds += time.time() - t0
        self.n_calls += 1
        self.n_flows += len(batch)

        detected = set()
        for af in logdir.glob("alert*"):
            with open(af, errors="ignore") as fh:
                for line in fh:
                    if QUERY_NET not in line:
                        continue
                    m = _QUERY_IP_RE.search(line)
                    if not m:
                        continue
                    qid = int(m.group(1)) - 1
                    detected.add(qid)

        if not self.keep:
            pcap.unlink(missing_ok=True)
            for f in logdir.glob("alert*"):
                f.unlink()
        return {qid: (qid in detected) for _pkts, qid in batch}

    @staticmethod
    def _qid_from_sport(sport: int) -> Optional[int]:
        if sport < QUERY_PORT_BASE:
            return None
        return sport - QUERY_PORT_BASE

    def verdicts_chunked(self, items: Sequence[Tuple[List, int]]) -> Dict[int, bool]:
        """Split into batches of ``batch_size`` and resolve all."""
        out: Dict[int, bool] = {}
        for i in range(0, len(items), self.batch_size):
            out.update(self.verdicts(items[i:i + self.batch_size]))
        return out

    def stats(self) -> Dict:
        return {"snort_calls": self.n_calls, "flows": self.n_flows,
                "seconds": round(self.seconds, 1),
                "ms_per_flow": round(1000 * self.seconds / self.n_flows, 2)
                if self.n_flows else None}


# ---------------------------------------------------------------------------
# self-test: batch verdicts must equal per-flow ground truth
# ---------------------------------------------------------------------------
def _load_real_flows(pcap_path: Path, n: int, min_pkts: int = 4):
    """Pull n real multi-packet flows out of a capture, grouped by 5-tuple."""
    from scapy.all import PcapReader, IP, TCP, UDP

    flows: Dict[tuple, List] = {}
    with PcapReader(str(pcap_path)) as rd:
        for pkt in rd:
            if IP not in pkt:
                continue
            if TCP in pkt:
                proto, layer = "tcp", TCP
            elif UDP in pkt:
                proto, layer = "udp", UDP
            else:
                continue
            key = (pkt[IP].src, pkt[layer].sport, pkt[IP].dst,
                   pkt[layer].dport, proto)
            flows.setdefault(key, []).append(pkt)
            if len(flows) >= n * 4:
                break
    keep = [(k, v) for k, v in flows.items() if len(v) >= min_pkts]
    keep.sort(key=lambda kv: -len(kv[1]))
    return keep[:n]


def selftest(pcap: Path, n: int = 12, batch_size: int = 6) -> int:
    from scapy.all import wrpcap
    import tempfile as tf

    print(f"[*] pulling {n} real flows from {pcap.name}")
    flows = _load_real_flows(pcap, n)
    if len(flows) < 4:
        print("[-] not enough multi-packet flows")
        return 1
    print(f"[+] got {len(flows)} flows")

    # --- ground truth: one Snort call per flow ---
    print("[*] ground truth (1 Snort call per flow) ...")
    gt = {}
    with tf.TemporaryDirectory(prefix="gt_") as td:
        td = Path(td)
        for i, (_key, pkts) in enumerate(flows):
            single = td / f"f{i}.pcap"
            wrpcap(str(single), pkts)
            logdir = td / f"l{i}"
            logdir.mkdir(exist_ok=True)
            subprocess.run(["snort", "-c", str(SNORT_CONF), "-r", str(single),
                            "-l", str(logdir), "-q", "-A", "fast"],
                           capture_output=True, text=True, timeout=300)
            hits = 0
            for af in logdir.glob("alert*"):
                hits += len([ln for ln in open(af, errors="ignore")
                             if ln.strip() and not ln.startswith("#")])
            gt[i] = hits > 0

    # --- batched ---
    print(f"[*] batched (batch_size={batch_size}) ...")
    svc = SnortBatchService(batch_size=batch_size)
    got = svc.verdicts_chunked([(pkts, i) for i, (_k, pkts) in enumerate(flows)])

    agree = sum(1 for i in gt if gt[i] == got.get(i))
    print(f"\n  flow |  truth  batch")
    for i in sorted(gt):
        mark = "OK " if gt[i] == got.get(i) else "MISMATCH"
        print(f"  {i:>4} | {str(gt[i]):>5}  {str(got.get(i)):>5}   {mark}")
    print(f"\n[{'PASS' if agree == len(gt) else 'FAIL'}] agreement "
          f"{agree}/{len(gt)}")
    print(f"[*] batch stats: {svc.stats()}")
    print(f"[*] ground-truth cost: {len(gt)} Snort calls (1 per flow)")
    return 0 if agree == len(gt) else 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--pcap", default="data/stratosphere/CTU-13-Dataset/"
                                     "1/botnet-capture-20110810-neris.pcap")
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--batch-size", type=int, default=6)
    args = ap.parse_args()
    if args.selftest:
        return selftest(Path(args.pcap), args.n, args.batch_size)
    print("nothing to do; pass --selftest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
