# P16c — CORRECTION: fragmentation was never an evasion mechanism

**Date:** 2026-10-14
**Commit:** see `git log --oneline | head -3`
**Status:** engine-verified. Suricata 7.0.3, 21288 rules, on the frozen 20-flow sample.

---

## 1. What changed

`RealRulesReplica` used to match rule content **within a single packet**. Every
real engine matches against the **reassembled stream**. That gap made
fragmentation look like a working evasion mechanism when it is not.

Two distinct bugs, both found by probing rather than guessing:

| # | Bug | Consequence |
|---|---|---|
| 1 | `Rule.fires()` iterated `for payload in payloads`, matching content inside one packet | fragmentation "evaded" |
| 2 | The obvious first fix gated on TCP only — but `apply_mech("split8")` fragments at **layer 3 (IP)**, not layer 4 | first fix was **no better** (24/100) |

The second bug only became visible *because* the first fix existed and failed.
Suricata performs **IPv4 defrag first, then TCP stream reassembly**; a
TCP-only gate skips defrag entirely.

A third, subtler bug: scapy keeps the **MF bit in `IP.flags`**, not in
`IP.frag`. `IP.frag` holds the 13-bit fragment offset in 8-byte units. Reading
`ip.frag & 0x2000` therefore yields `False` forever, and no fragment was ever
recognised as a fragment.

Fragments are keyed `(src, dst, proto, id)` per RFC 791. Keying without `proto`
silently dropped reassembly whenever the tail fragment's protocol field differed
from the head's.

## 2. The measurement

Replica vs. committed Suricata 7.0.3 verdicts, 20 frozen flows × 5 mechanisms:

| | before fix | after fix |
|---|---:|---:|
| agreement | 76/100 | **100/100** |
| `split8` cells agreeing | 16/20 | **20/20** |
| `split24` cells agreeing | 0/20 | **20/20** |
| `noop` / `http_header_case` / `query_param_prepend` | already correct | unchanged |

Zero previously-agreeing cells broke. Pinned by
`tests/test_replica_matches_suricata.py` (5 new tests), which also fix the
boundary: IP fragments rejoin, TCP joins **per 5-tuple**, and **UDP never
concatenates** — a datagram is a message, not a stream. That last one matters:
`neris` is BitTorrent DHT over UDP, and joining its datagrams would invent
matches no engine performs.

## 3. The consequence, measured

Same 1153-flow train corpus, same binaries, **only the scoring changes**:

| mechanism | evaded (per-packet, old) | evaded (reassembled, new) | semantics OK |
|---|---:|---:|---:|
| `noop` | 0/1153 | 0/1153 | 1153/1153 |
| `split8` | 5/1153 | **0/1153** | 1153/1153 |
| `split16` | 4/1153 | **0/1153** | 1153/1153 |
| `split24` | **454/1153** | **0/1153** | 1153/1153 |
| `split_slow` | 5/1153 | **0/1153** | 1153/1153 |
| `pad16` | 0/1153 | 0/1153 | 1/1153 |
| `reorder` | 0/1153 | 0/1153 | 565/1153 |
| `ttl` | 0/1153 | 0/1153 | 1153/1153 |
| `http_header_case` | 450/1153 | **450/1153** | 1153/1153 |
| `query_param_prepend` | 4/1153 | **4/1153** | 1153/1153 |
| **per-flow oracle** | **761/1153** | **456/1153** | — |

Three things to read off this table:

1. **The split family evaporates.** `split24` was the single most "successful"
   mechanism the surrogate ever reported, at 454/1153 (39%). It is 0. Not
   reduced — zero.
2. **The two real mechanisms do not move at all.** `http_header_case` 450 and
   `query_param_prepend` 4 are identical before and after. They evade by
   breaking *where a pattern starts*, which no amount of stream reassembly can
   repair. That is exactly why they are the P14 result and why they cost
   `+0 byte`.
3. **The semantics bar is untouched.** `sem OK` is identical in every row. The
   fix is surgical: it changed only the *detection* half, never the
   "did the C2 command survive" half. So no semantic claim in the thesis moves.

Suricata 7.0.3 independently measured `split8` **0/20** and `split24` **0/20**
on the frozen sample. The surrogate now agrees with the engine instead of
contradicting it.

### 3b. This reconciles P13 with P14

P13 measured **real Snort 2.9** and reported eviction headroom 0 for the whole
split family. The surrogate disagreed with it, and this file explains why: the
surrogate scored per-packet. So **P13 was right and the surrogate was wrong**,
and P14 only found headroom after leaving fragmentation behind for
head-anchored mechanisms. The two phases were never in conflict — one of them
was measuring a broken instrument.

### 3c. THE DECISIVE NUMBER: RL headroom is 0.35 pp

With the surrogate faithful, the per-flow oracle over all 9 candidate
mechanisms on the full **1153-flow train corpus**:

| | value |
|---|---:|
| best single mechanism (`http_header_case`) | 450/1153 = 39.0% |
| per-flow oracle | 454/1153 = 39.4% |
| **headroom** | **4 flows = 0.35 pp** |

All 4 flows that only the oracle reaches want `query_param_prepend`, and all 4
are `20110811-neris`:

```
147.32.84.165:1102->60.190.223.75:888|tcp
147.32.84.165:1118->94.63.150.20:80|tcp
147.32.84.165:2905->94.63.150.20:80|tcp
147.32.84.165:3653->60.190.223.75:888|tcp
```

**A one-bit rule — "if `query_param_prepend` works, use it, else
`http_header_case`" — attains the oracle exactly.** There is nothing left for a
policy to learn. This is the same negative result P13 reached with real Snort,
now reproduced on the corrected instrument.

Note where the 20 pp of P16b came from: that sample was **selected** to hold
16 FakeAV + 4 Virut, i.e. two families with deliberately *different* winning
mechanisms, and those 4 Virut flows are the same 4 here. The 20 pp measured
selection, not structure. On the corpus as it actually ships
(`20110819-bot` 698 + `20110811-neris` 455 for train; 24 + 16 for test) the two
mechanisms are near-nested and the gap collapses.

## 4. What this refutes

`docs/headroom_root_cause.md` rests on `split8` evading 40/40. That number is
an artefact of the per-packet scorer, as is the 454/1153 figure here. The
split-family rows in `docs/THREAT_MODEL.md` are affected the same way.

`tests/test_hidden_defender_env.py::test_split24_preserves_semantics_and_evades`
asserted `split24` evades. It pinned the artefact. It now pins the truth, and
the reward assertion moved to `http_header_case`, which still evades — the
reward formula is unchanged (`10.0 − 0.05 + 0.15 = 10.1`, verified).

## 5. What this strengthens

The P14 result is now the *only* evasion story, and it is a real one:
**head-anchored content mismatch is the mechanism, fragmentation never was.**
`http_header_case` and `query_param_prepend` evade by breaking where a pattern
*starts*, not by splitting a stream — which is why they survive reassembly and
why both are `+0 byte` on the wire.

The action space's split family (`split8`/`split16`/`split24`/`split_slow`) is
now known to be **inert** against a reassembling detector. That is a finding
about the threat model, not a reason to delete them: they remain the honest
negative control. See `docs/action_space_policy_p15.md` for why they stay.

## 6. Honest limits

- Measured on the **frozen 20-flow** sample for the engine cross-check, and on
  the full 1153-flow **train** corpus for the surrogate. Those are different
  denominators; the second does not have engine verdicts for every cell.
- 4 of the 20 flows were used to probe before being frozen (caveat #5), so the
  20 pp headroom figure is partly self-fulfilling. Unchanged by this fix.
- `http_header_case` reaching 450/1153 is a **surrogate** number. The engine
  has only adjudicated 16/16 on FakeAV and 0/4 on Virut.
