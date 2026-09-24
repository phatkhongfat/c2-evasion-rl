# Snort Decision Boundaries (Task 1)

**Scope:** the ruleset actually used for validation is
`snort_validation/rules/botnet-behavior.rules`, loaded by
`snort_validation/rules/snort.conf` into **Snort 2.9.20 GRE (Build 82)**.

Everything below was measured against the real Snort binary, not inferred from
the rule text. The measured semantics are encoded in
`snort_validation/snort_query_service.py` and scored against real verdicts by
`snort_validation/verify_snort_replica.py` (428 real-labelled flows, 99.77%
agreement, 0 false negatives).

---

## 1. Rules and thresholds

| sid | proto | dsize | count / window | flow | track | aggregate checked |
|---|---|---|---|---|---|---|
| 3000001 | tcp | `>800` | 3 / 120 s | established | by_src | TCP large payload burst (exfil / download) |
| 3000002 | tcp | `>1200` | 3 / 120 s | from_server, established | by_dst | TCP large download chunk |
| 3000003 | udp | `<65` | 5 / 30 s | — | by_src | UDP small-packet beacon burst |
| 3000004 | tcp | `<65` | 8 / 60 s | established | by_src | TCP small-packet beacon burst |
| 3000005 | tcp | — | 6 / 10 s (`flags:F`) | — | by_src | TCP FIN burst |
| 3000006 | tcp | `>1400` | none (fires on 1) | — | — | single large-packet exfil |

`dsize` is **payload length**, not frame length.

### Rules that do not fire

- **sid 3000005 (FIN burst)** never fired on any synthesized flow. `flow_to_pcap`
  emits at most one FIN pair per flow, so 6 FINs inside 10 s is unreachable.
  It is deliberately **not modelled** in the replica.
- **ICMP** is never matched by any rule in this file, so ICMP flows always evade.
  (Observed: 0/1 ICMP flow detected in the blind seeded run.)

---

## 2. Measured semantics that the rule text does not tell you

Three behaviours were derived empirically. Each one changed real verdicts, so
each is a correctness requirement for any training reward built on this ruleset.

### 2.1 `flow:established` does not count pre-handshake packets

Snort's stream5 only marks a TCP flow established once it sees the 3rd
handshake packet (the client ACK). Packets seen **before** that point (SYN,
SYN-ACK) do **not** count toward an `established` rule's threshold; the ACK
itself does.

Measured: a TCP flow with 8 small packets is not detected, with 11 it is
(sid 3000004 nominal count is 8). The gap is exactly the 2 pre-establishment
packets plus Snort's `threshold:type both` requiring the count to be exceeded
within the window.

### 2.2 `threshold:type both` anchors on the FIRST match, not a sliding window

The window starts at the first packet that matches the rule's `dsize` and
covers the next `seconds` seconds. It does not slide.

Measured: 10 small TCP packets spread over 90 s **do not** alert real Snort,
even though a sliding window would see 10 > 8 matches inside 60 s. Over
428 real-labelled flows the anchored model scores 99.77% and the sliding model
99.30%; on the discriminating long-duration set the anchored model is exact.

### 2.3 Rules are `any any -> any any`: they match BOTH directions

`track by_src` groups by the packet's **source address**, not by the direction
the rule author intended. For a client→server packet the source is the client;
for a server→client packet the source is the server. Modelling 3000001 as
"client bytes only" produces a false negative on server-heavy flows.

Measured: `{'dur': 1.0, 'tot_pkts': 5, 'tot_bytes': 2000, 'src_bytes': 200}`
is **detected** by real Snort — the server side carries the large payload and
`any any` lets 3000001 match it.

---

## 3. Effective decision boundary (what actually decides a verdict)

For the flows this project generates, the verdict is a function of the
**mutated** feature vector `(dur, tot_pkts, tot_bytes, src_bytes, proto, state)`:

- **`proto = icmp`** → always evades.
- **`proto = udp`, `tot_pkts` ≥ 7** → detected (sid 3000003, count 5) *unless*
  `dur` is large enough to stretch the first-to-5th small-packet span past 30 s.
- **`proto = tcp`, `tot_pkts` ≥ 11** → detected (sid 3000004) unless the span
  from the first small packet exceeds 60 s.
- **any proto with a large single payload** (`dsize > 1400` on TCP, i.e.
  `tot_bytes` concentrated in one packet) → detected (sid 3000006).
- **`proto = tcp` with ~1400 B/packet** → detected (3000001 / 3000006).

### Mutation strategies implied

| to evade | do this |
|---|---|
| 3000001 / 3000006 | keep every individual TCP packet ≤ 800 B, and never > 1400 B |
| 3000003 | fewer than 5 small UDP packets, or spread the first-to-5th span past 30 s |
| 3000004 | fewer than 8 small TCP packets counted after the handshake, or span past 60 s |
| 3000002 | keep the server→client packets ≤ 1200 B |

**The dominant lever is `tot_pkts`.** Growing packet count is what the current
blind agent does (it grew `tot_pkts` to escape XGBoost), and it is precisely
what drives Snort detection.

---

## 4. Why the blind agent evades only 30%

The no-mutation **baseline already evades Snort at 93.75%** (detection 6.25%,
`baseline_snort_validation_seeded_blind.json`). The agent makes it *worse*:
detection rises to 70%.

Correlation with the real verdict over the blind seeded run:

```
corr(tot_pkts, detected)  = +0.283     corr(steps, detected) = +0.462
corr(tot_bytes, detected) = +0.283     corr(dur, detected)   = -0.230
```

Detection rate by mutated `tot_pkts`:

```
[  3, 10)  n=22  det=  0.0%     <- evades
[ 10, 50)  n=27  det= 96.3%     <- detected
[ 50,100)  n= 4  det=100.0%
```

The agent learned that XGBoost is fooled by large, long, packet-heavy flows
(`judge` predicts benign at `tot_pkts=30, tot_bytes=1200`), so it inflates
`tot_pkts` and `tot_bytes`. Those are exactly Snort's detection triggers. The
reward target is wrong, not the policy — hence the switch to a snort-direct
reward (Task 2+).

---

## 5. Consequence for the Task-3 stub in the plan

The plan's Task 3 proposes `tot_pkts > 50` as the mock Snort verdict. Measured
against 428 real Snort verdicts this stub agrees only **57.5%** of the time
(`tp=107 fp=6 fn=176 tn=139`) — it misses 176 real detections, including every
UDP flow with 29–50 packets, which real Snort detects via sid 3000003.

Training against that stub would reward the agent for the wrong boundary. This
implementation therefore uses the **verified rule-level replica** (99.77%
agreement, 0 false negatives) as the training reward, and keeps the stub only
as a documented negative control.

Reproduce:

```bash
/tmp/jev-poc/venv/bin/python snort_validation/verify_snort_replica.py
```

---

## 6. Caveats

- Payloads in the reconstructed pcaps are synthetic filler, so content/signature
  rules cannot fire. These rules detect behaviour, which is what this project
  studies.
- `emerging-botcc.rules` (pure IP blacklist) is intentionally not loaded: it can
  never match synthesized addresses, and leaving it active makes Snort exit
  fatally, which silently zeroes every detection.
- The replica is tuned to *this* ruleset and *this* pcap synthesizer. Changing
  either invalidates it; re-run `verify_snort_replica.py` after any change.
