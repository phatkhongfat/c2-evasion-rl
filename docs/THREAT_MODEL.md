# Threat model — who the attacker owns in evasion benchmarks

Every valid-evasion number in this repo is only meaningful under an explicit
statement of **which endpoint of the C2 session the attacker may rewrite**.
This file fixes the two supported models and labels every number in this repo
with one of them.

## Model `client` (default, conservative)

The attacker owns the **bot** (the C2 client).  Only the client's own packets
may be rewritten by a mechanism (`apply_mech(..., ownership="client")`).
The responder's (C2 server / peer) packets are **never mutated** — enforced by
`test_server_packets_are_never_mutated` in `tests/test_evaluation_fixes.py`.

Numbers under this model:
- honest eval (real Snort, byte-equality): **40.0 %** (16/40) @ `split16` policy
- structural ceiling (oracle `split8` on all flows): **57.5 %** (23/40)
  = 16/16 http + 7/24 neris.  The 17 unevadable neris flows have their first
  packet emitted by the *peer* carrying the raw DHT signature (ET P2P
  BitTorrent DHT, sid 2008581/2008583/2008585, `HOME_NET=any`) — the alert
  fires before the client can do anything, and the server side is off-limits.

### P2P rules are out of threat model (P11, measured)

The rule harvest keeps every ET Open rule that ever fired, which swept in **102
`classtype:policy-violation` rules** (BitTorrent DHT). They are not C2 and must
never be counted as detection of the thing being measured.

Measured on the 40-flow test split under `ownership=both`:

- **16 flows** (all `http`) alert on `sid 2012627` — *ET TROJAN FakeAV
  Check-in purporting to be MSIE with invalid terse HTTP headers* —
  `classtype:trojan-activity`. These are the only flows with a genuine C2
  baseline.
- **24 flows** (all `neris`) alert **only** on `2008581`/`2008583`/`2008585`.
  Removing the 102 P2P rules and re-running `noop` (`snort -T` passes on the
  21,317-rule ruleset) leaves 16/16 http still alerting on `2012627` and makes
  24/24 neris go **silent** — those flows have no C2 detection at all.

Consequence: a flow counts toward an evasion measurement only if its baseline
SID is C2. Headline numbers are reported on the 16 http flows; reporting
across all 40 conflates "fragmentation defeats C2 detection" (16/16) with
"fragmentation defeats a BitTorrent signature" (0/24).

P2P-free conf: `snort_validation/et_open_c2/snort_et_c2_nop2p.conf`; regenerate
its ruleset with `controls/build_c2_only_ruleset.py` (verified byte-identical to
the on-disk file). Report for the `noop` control: `ceiling_v4_nop2p_noop.json`.
The fragmentation sweep on this conf (`ceiling_v4_nop2p_frags.json`) is still
running and must land before its numbers are cited.

## Model `both` (two-sided ownership)

The attacker owns **both endpoints** (bot + C2 server), matching the reality
that a C2 operator runs the server.  Mechanisms may rewrite packets on either
side (`ownership="both"`).  This does **not** relax the verdict bar: the same
strict two-stream byte-equality check
(`c2_semantics.bytes_equal_semantics`, guarding the client **and** the server
stream) filters out any mutation that breaks reassembled-byte equality — 215
of 560 swept cells were rejected this way (evaded but `semantics_ok=False`).

Numbers under this model:
- ceiling sweep v2 (real Snort, 560 cells, `controls/ownership_ceiling_sweep.py`,
  report `snort_validation/reports/ceiling_ownership_both_v2.json`, run after the
  wire-deliverable bar fix): **100 %** (40/40) with `split8` — 16/16 http +
  **24/24 neris**, all `semantics_ok=True`.
- retrained PPO (40 epochs, real-Snort teacher, 3 seeds, honest eval,
  `snort_validation/reports/ppo_both_test_RS64_v2_s{7,1337,42}.json`): **100.0 %**
  (40/40) for **every seed**, `semantics_breaks = 0`, baseline alerted 40/40,
  policy converged to `split8` on all flows.
- The pre-v2 numbers (reports without `_v2`) were produced with a
  `fragment_plan_to_packets` that emitted no Ether/TCP header and 8-byte-unaligned
  offsets — i.e. frames a real link would never carry. They are superseded.

## Wire deliverability (the bar that filters fake evasions)

`bytes_equal_semantics(original, mutated, client_ip)` now runs a **two-tier bar**:
1. **stream tier** — reassembled bytes equal on both streams (unchanged);
2. **wire tier** — `wire_deliverable(original, mutated)`: same linktype, fragments
   are a structurally valid fragmentation of a datagram (Ether wrapper, IP/TCP/UDP
   headers on frag0, 8-byte-aligned reassembly offsets), and the fragments
   reassemble to exactly the datagram that was sent.

The wire tier is what stops an "evasion" from being a broken write: a fragment
that a real NIC/stack could not send, or that no reassembler would rebuild, is
now rejected (`valid_evasion=False`) instead of counted. This is the fix that
produced the `_v2` numbers above.

**D1 probe (same bytes, correct geometry)**: re-cutting the very frames the
bar now requires and replaying them through real Snort gave **branch A** —
TCP `split8`/`split16`/`split24` all `EVADED` (`alerts=0, valid=True`) and UDP
`split8` `EVADED`; the bar did not hand back any flow to the rule. (UDP
`split16`/`split24` and `overlap8` stayed `ALERT`/invalid as measured, matching
the sweep.)

## Wire-through (DRY)

One mutation path, one bar, for both reward and evaluation:
- `apply_mech(pkts, mech, client_ip, ownership)` — env + eval share it.
- `bytes_equal_semantics(original, mutated, client_ip)` — guards both streams;
  `semantics_intact()` in the env delegates to it, so the PPO reward runs under
  the exact same bar the honest eval applies (Fix-3 invariant).

## Severity stratification (plan P2)

The raw 40/40 mixes two very different detections. Grouping each flow by the
`classtype` of the rule that fired on its baseline
(`controls/alert_stratification.py`, report source `ceiling_ownership_both_v2.json`):

| classtype | flows | split8 evaded | split8 valid |
|---|---|---|---|
| policy-violation (DHT/P2P-style) | 24 | 24 | 24 |
| trojan-activity (C2 content rules) | 16 | 16 | 16 |

Only the 16 trojan-activity flows are "the defender saw C2" in the malware sense;
the 24 policy-violation flows fire informational rules. On trojan flows,
`split16` and `split24` are also 16/16 valid — the ceiling is not resting on a
single offset. `prepend*`/`corrupt8`/`overlap8`/`http_header_pad` still show raw
`evaded` counts but **0 valid** (bar rejects them: byte inequality or undeliverable
frames), which is exactly the distinction the wire tier was built to enforce.

## Ruleset tiers — naive vs expert (plan P1)

The naive tier is **measured**, not assumed: `controls/make_naive_ruleset.py`
keeps only SIDs that actually fired on baseline = **4/21,419**
(`2008581, 2008583, 2008585, 2012627`). Sweeping the same 560 cells under
`snort_et_c2_naive.conf` vs the full ET Open set:

| mech | naive evaded/valid | expert evaded/valid |
|---|---|---|
| split8 | 40/40 | 40/40 |
| split16 | 16/16 | 16/16 |
| split24 | 16/16 | 16/16 |
| prepend4/8/12 | 40/0 | 40/0 |
| corrupt8, overlap8 | 24/0 | 24/0 |
| http_header_pad | 16/0 | 16/0 |
| length_wrapper | 15/0 | 15/0 |
| pad16, reorder, ttl, noop | 0/0 | 0/0 |

**The two tiers are identical on this corpus** — and the post-hoc check explains
why: the SID union observed in *mutated* cells under the full ruleset is exactly
those same 4 SIDs. The other ~21,415 rules never fire, so "expert" adds no
detection depth here. Any ceiling number from this repo is therefore
ruleset-depth-independent between these two tiers (reports
`ceiling_naive_v2.json` vs `ceiling_ownership_both_v2.json`).

## Learning curves (plan P3)

`controls/learning_curves.py` → `snort_validation/reports/learning_curves_v2.csv`
(per-seed rows; parser regex pinned by `tests/test_learning_curves.py`).
Flow-valid% during training (mean ± std across seeds 7/1337/42):

| epoch | valid % |
|---|---|
| 1 | 12.5 ± 5.1 |
| 10 | 29.7 ± 1.3 |
| 15 | 70.3 ± 4.4 |
| 20 | 80.2 ± 4.1 |
| 23 (final common epoch) | 90.1 ± 2.0 |

Seeds 7/1337 stop at epoch 23/26 (converged early); seed 42 runs longer.
Final test-set outcome is 40/40 for all three seeds regardless.

## Cross-engine (plan P4)

**SKIP, as allowed by plan R5**: no `suricata` binary on this host (no
`suricata.yaml`, no converted ruleset either). The harness
(`controls/cross_engine_check.py`) is committed and fails gracefully — it
generated the pcaps and recorded `baseline-evaded=0` with per-cell warnings
rather than inventing a comparison. Enable by installing Suricata + converting
the ET rules; the script then reports % agreement cell-by-cell.

## Scope limits

- **TLS**: the corpus is cleartext HTTP/1 C2 sessions (LCN25 scope). Rules like
  the trojan-activity content matchers operate on visible bytes; an
  encrypt-and-inspect deployment (JA3/SNI, decryption) is out of scope and would
  change which flows alert at all.
- Engine = Snort 2.9.x with ET Open rules; cross-engine generalization is
  unmeasured (see Cross-engine above).

## CLI surface

`--ownership client|both` on `train_hidden_defender_ppo.py`,
`eval_fixed_pipeline.py`, and `ownership_ceiling_sweep.py`.  Default is
`client`; nothing changes unless the flag is passed explicitly.
`ownership_ceiling_sweep.py --conf <path>` reruns the sweep against an
alternate ruleset (e.g. `snort_validation/et_open_c2/snort_et_c2_naive.conf`).