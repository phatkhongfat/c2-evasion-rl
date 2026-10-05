# Audit: why 40/40 and 38.89% are both "true" — and which one was lying

Date: 2026-10-05
Scope: `snort_validation/reports/ppo_masked_test.json` (40/40 = 100%) vs
`snort_validation/reports/cross_capture_summary.json` (mean evasion 38.89%).

## Headline finding

**They are not the same measurement, and neither is the number the thesis
needs.** The 38.89% figure is an artefact of three broken pieces of the
evaluation pipeline; the 40/40 figure is real for its own (narrow) question but
rests on a semantics bar and a mutation model that overstate what "evasion"
means.

### 1. What each number actually measures

| Report | Unit | Scored on | Meaning |
|---|---|---|---|
| `ppo_masked_test.json` | held-out test **split** (40 flows) | real Snort, one PCAP per flow | 40/40 alerts suppressed |
| `cross_capture_summary.json` | 3 **captures** (24 flows each) | real Snort, replay loop | mean of (16.67%, 100%, 0%) = 38.89% |

38.89% is `(16.67 + 100.0 + 0.0) / 3`. It is a **per-capture** mean over three
different corpora, one of which (`capture-win13`) is a Windows capture with
almost no payload. The two numbers answer different questions:

* 40/40 = "can the policy suppress Snort on the held-out flows of the captures
  it was trained on?"
* 38.89% = "does the policy transfer across captures?"

Averaging three captures — including one the policy provably cannot act on —
produces a number that is neither the test-split evasion nor an honest
transfer figure. Quoting 38.89% as "the evasion rate" is a category error, and
quoting 40/40 without the transfer caveat is over-claiming. Both must be
reported, labelled, and never averaged together.

### 2. The pipeline defects that made the numbers unreliable

Every one of these was reproduced on the shipped artefacts before being fixed.

**D1 — Mutation was not client-only.** `hidden_defender_env.apply_mech` calls
`fragment_plan_to_packets` / `fix_checksums` on *every* packet of the flow, not
on `payload_indices`. The split mechanisms therefore fragmented the **server's**
response too. An attacker does not control the responder's bytes; the evasion
was partly an artefact of mutating traffic outside the threat model.
Verified: on a test flow the server payload went from one 302-response to
fragments — the responder's bytes changed.

**D2 — Direction was never modelled.** Corpus flows are bidirectional (40/40
test flows carry both directions). The split target was chosen by payload size,
so the "largest payload" (often the server response) absorbed the mutation. The
threat model needs the *client* (bot) side, which is the endpoint inside the
`147.32.84.0/24` honeynet — **not** always the flow initiator, because neris C2
flows are captured in both directions. Selecting by "initiator" mislabels 12 of
40 test flows.

**D3 — Byte-equality was not the bar.** `semantics_intact` used a protocol
parser (`endpoint_model.parse_command`) that *accepts* padding: an unknown
`X-Junk` header is skipped by a real server, so the parser reported "semantics
intact" for a stream whose bytes differ. That is a legitimate protocol argument
but it is **not** byte equality, and it silently made `prepend`/`pad` look like
evasions. The two bars were conflated.

**D4 — Scoring was not per-flow.** `snort_batch_service` replayed all flows in
one Snort invocation with a resident process. An alert could not be attributed
to a flow, and one flow's traffic could influence the alert state of another.

**D5 — The source IP was static.** The same source address was reused across
attempts, so Snort's `threshold`/`detection_filter` state (`track by_src`,
`count 1, seconds 300`) and flowbits carried across independent attempts. A
second attempt could evade because a first attempt had already tripped a
rate-limited rule — evasion by state leakage, not by the mechanism.

**D6 — I/O was not synchronized.** The alert log was read without waiting for
Snort to flush; a slow write made an alerted flow score as evaded. This is the
single most dangerous failure mode: it *inflates* evasion silently.

### 3. Reproduction evidence

* Direction: `client_ip_of` (initiator) vs honeynet-bot selection disagree on
  12/40 test flows — the 24 neris flows split 12/12.
* Client-only split8 on the 24 neris flows: **0/24** evade the in-corpus
  replica, because the replica is direction-agnostic and the responder's copy
  of the pattern is untouched. Real Snort is direction-aware and behaves
  differently (see the FIXED report).
* Reassembly: grouping fragments by IP id fails on captured traffic because
  unrelated packets share id 0; the fix groups by consecutive runs and splits
  at each offset-0 fragment.
* Static source: the ruleset contains 551 alert lines with `flowbits` and the
  firing BitTorrent SIDs carry `threshold: type both, count 1, seconds 300`.

## 4. Fixes landed

| Fix | Defect | Change |
|---|---|---|
| 1 | D2 | flows modelled as bidirectional; client = honeynet bot |
| 2 | D1 | mutation restricted to the client packet set |
| 3 | D3 | `bytes_equal_semantics`: strict byte equality of the recovered client stream |
| 4 | D4 | one PCAP + one Snort call per (flow, mechanism) |
| 5 | D5 | unique per-attempt source IP **and** port translation |
| 6 | D6 | wait for Snort exit + fsync before reading alerts; non-zero exit raises |

Implemented in `snort_validation/eval_pipeline.py`, exercised by
`tests/test_evaluation_fixes.py`, and driven by
`ai_agent/eval_fixed_pipeline.py` → `ppo_masked_test_FIXED.json`.

## 5. Open question the audit cannot settle by itself

Fix 2 makes mutation client-only, which is correct for the threat model but
*reduces* what the mechanism can suppress when the responder also carries the
pattern. The FIXED report measures the consequence honestly; if evasion drops,
the previous 40/40 was partly an artefact of mutating the server, and the drop
is the correct number to publish.
