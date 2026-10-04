# How the results were produced — presentation notes

Date: 2026-09-30. Every number below is read from a committed JSON report in
`snort_validation/reports/`. Nothing here is estimated.

---

## 1. The claim, and what makes it credible

**Claim:** a policy can mutate real C2 beacon packets so that Snort 2.9.20 with the
ET Open C2 ruleset stops alerting, while the mutated traffic still parses as working C2.

Two things make this more than a number:

1. **The scorer is the real binary**, not a model of it. `snort -c <conf> -r <pcap>
   -l <dir> -q -A fast`, 21374 ET rules loaded, verdict read from the fast-alert file.
2. **A negative control runs every time.** Unmutated flows must alert, or the
   measurement is meaningless. If the control stops alerting, nothing else is trusted.

The control is not decoration. It is what caught the two worst bugs in the project
(§6), both of which had produced confident-looking, completely false results.

---

## 2. Experimental protocol

### Data

Corpus: `snort_validation/reports/hidden_defender_corpus.pkl` (343 KB, committed).
Built by `build_hidden_defender_corpus.py` from two captures, **both represented in
train and test** so a method cannot win by recognising "which capture is this":

- `botnet-capture-20110811-neris` (Stratosphere MCFP, capture 43)
- `botnet-capture-20110819-bot` (CTU-13 capture 12)

Selection rule: keep only flows that the real Snort **does** detect (so there is
something to evade). Split **64 train / 16 test**, stratified by capture.

Two test sets are in play and must not be conflated:

| test set | n | used for |
|---|---|---|
| full test split | **16** | the headline number |
| HTTP-only subset | **8** | per-mechanism matrix and baselines |

The HTTP-only subset exists for a specific reason: on the Neris (binary) flows,
`split8` alone solves everything, which is a degenerate result. Filtering to HTTP
removes that degeneracy and makes the per-mechanism comparison meaningful. Recorded in
`24614e2` and `b24bede`.

### Measurement rules (each one bought with a wrong result)

- **One (flow, mechanism) pair per pcap.** Batching 32 pairs into one pcap made Snort
  emit 4 alerts where isolated scoring found 12 detections — mixed traffic suppressed
  alerts across the whole capture. `score_matrix` runs `batch_size=1`: 224 Snort calls,
  ~80 s, and the only setting whose verdicts are trustworthy.
- **A verdict is only counted when semantics also hold.** `QueryCounter.valid()` returns
  `evaded AND semantics_ok`. A mutation that deletes the C2 channel is not an evasion.
- **Mechanisms a flow's framing cannot carry are skipped, not counted.** The attacker
  knows its own protocol; probing "pad the headers of a binary record chain" is not a
  probe a protocol-aware attacker makes. Skipping avoids inflating query counts and
  handing inapplicable mechanisms free wins.

### Baselines, in increasing strength

| method | what it is | role |
|---|---|---|
| `random_sweep` | random mechanism order, retry until valid | floor |
| `greedy` | reuse the mechanism that worked on the nearest flow by obs distance | strong heuristic |
| `supervised_tree` | decision tree on oracle labels | **ceiling** (what is achievable) |
| `ppo` / `maskable_ppo` | the trained policy | the thing being evaluated |

The ceiling matters: without it, "PPO got 100%" is uninterpretable.

---

## 3. Headline result

From `ppo_masked_test.json` — `eval_masked_ppo_test.py --real-snort`, 16 held-out flows:

| metric | value |
|---|---|
| method | `maskable_ppo` |
| scorer | `real_snort` |
| split | test |
| n_flows | 16 |
| **alerted** | **0** |
| **valid_evasion** | **16 / 16 (100.0%)** |
| negative control (`control_noop_real_snort.json`) | **16 / 16 alerted** |

The policy used exactly two mechanisms: `split8` (on UDP/Neris) and `http_header_pad`
(on HTTP). That is the correct behaviour — one mechanism per framing — and it is
evidence the action masking works.

### Training numbers

| run | scorer | flows | evaded | queries | epochs | report |
|---|---|---|---|---|---|---|
| fast surrogate | `RealRulesReplica` | 64 | 61 (95.3%) | 704 | 11 | `ppo_hidden_defender.json` |
| real Snort | real binary | 64 | 58 (90.6%) | 640 | 10 | `ppo_realsnort_train.json` |

**Both stopped at the ≥90% threshold, not at convergence.** Neither is a ceiling.

---

## 4. Per-mechanism result (real Snort)

From `hidden_defender_matrix_test.json` — HTTP-only test set, 8 flows, 112 cells,
scored one pair per pcap:

| mechanism | evaded | evaded **and** semantics intact |
|---|---|---|
| `split8` | 8/8 | **8/8** |
| `split16` | 8/8 | **8/8** |
| `split24` | 8/8 | **8/8** |
| `http_header_pad` | 8/8 | **8/8** |
| `prepend4` | 8/8 | 0/8 |
| `prepend8` | 8/8 | 0/8 |
| `prepend12` | 8/8 | 0/8 |
| `overlap8` | 8/8 | 0/8 |
| `length_wrapper` | 8/8 | 0/8 |
| `corrupt8` | 1/8 | 0/8 |
| all others | 0/8 | 0/8 |

This table is the single most important slide in the report, because the right-hand
column is where the honest work shows. **Six mechanisms produce 8/8 evasion and zero
valid evasions.** They do not defeat the IDS — they destroy the C2 channel, and a naive
reward would score them as perfect.

`length_wrapper` is a special case: it is 0/8 valid *and* 0/16 applicable on Neris, so
it is dead code. Needs a decision (reverse-engineer the Neris grammar, or drop it).

---

## 5. Does RL actually earn its place? (the finding that complicates the story)

From `hidden_defender_real_snort_test.json` and `hidden_defender_results.md` — 8
HTTP-only flows, real Snort:

| method | queries | evaded |
|---|---|---|
| random_sweep | 25 | 8/8 |
| greedy | 13 | 8/8 |
| supervised_tree | 8 | 8/8 |
| **ppo** | **8** | **8/8** |

On the 64-flow train split the same comparison is starker:

| method | queries | evaded |
|---|---|---|
| random_sweep | 309 | 58/64 |
| **greedy** | **149** | **58/64** |
| supervised_tree | 64 | 63/64 |
| **PPO** | **704** | **58/64** |

**PPO spends 4.7× more queries than greedy for identical evasion.** And on the HTTP-only
set, `split8` / `split16` / `split24` / `http_header_pad` each solve 8/8 — so the optimal
action is essentially constant per framing, not per flow.

**The honest framing for the report:** this is not "RL beats the baselines." It is
"the environment is real, the measurement is sound, and under *this* defender the search
problem is too easy for RL to add value — the winning action is near-constant." That is a
negative result about the framing, not about the agent, and it is defensible.

The path forward (already scoped in `hidden_defender_results.md` §6): make the defender
**heterogeneous or adaptive** — give each flow a ruleset with a different C2 rule
`depth`/`offset`, so the winning fragmentation offset genuinely varies per flow. One-line
ruleset generator, no new data, corpus/env/baselines all carry over.

---

## 6. Why the numbers should be believed: the bugs they caught

Each of these produced plausible-looking wrong results, and was caught by a control or a
cross-check — not by reading the code.

| # | bug | how it showed up | fix |
|---|---|---|---|
| 1 | Unidirectional flow extraction — reverse packets dropped | baseline detection was **0/24**, impossible | keep both directions |
| 2 | Naive packet rewriting — rewrote src on server responses | still 0/24 after fix 1 | direction-aware rewrite |
| 3 | `semantics_intact` accepted substring containment | every method scored 100%; `prepend` was "evading" by deleting the C2 channel | byte-equality of the reassembled stream |
| 4 | Batched scoring suppressed alerts | 32-pair pcap gave 4 alerts where isolated scoring found 12 | `batch_size=1` |
| 5 | ET rules throttle `by_src` | a reused query source address alerts once, then silently nothing | unique `ip:port` per query, never reused |
| 6 | Resident service read window shorter than Snort's buffered flush | `--resident` reported baseline **0/24** | raise floor to 2.5 s (measured flush latency 0.28–1.25 s) |

**Bug 3 is the one to present carefully.** It is the difference between "our agent evades
the IDS" and "our agent evades the IDS *while keeping the malware working*." The earlier
100% result was retracted because of it (`c90a1c8`). The current bar is byte equality.

---

## 7. Surrogate vs reality

From `surrogate_sweep_14mech.json` — 14 mechanisms × 16 flows, 224 real Snort calls,
2359 s:

| metric | value |
|---|---|
| overall agreement | 161/224 (71.9%) |
| agreement on applicable cells only | 103/116 (88.8%) |
| **surrogate false-safe** (says evaded, Snort alerts) | **0** |

`surrogate_vs_real_snort.json` on the eval corpus: 8/8 agree, 0 false-safe.

**Why "0 false-safe" is the number that matters:** a false-safe means the surrogate
tells the agent it evaded when it did not. That is the failure mode that would invalidate
every surrogate-scored experiment. It does not occur here. The 71.9% overall figure is
dominated by inapplicable cells, which is why the 88.8% eligible-only number is the
meaningful one.

Honest caveat, from `README.md`: the surrogate drops **20.6%** of real rules (`pcre`,
`byte_test`, `byte_extract`, `byte_jump`). It happens not to matter on this corpus (only
3 sids fire per capture), but it would on other traffic. And `split8` agreement is only
5/16 (31.2%) — the surrogate is worst exactly where the policy operates.

---

## 8. Scale, cross-capture, and where it breaks

### Scale-up (`final_scale_up_summary.json`, real Snort, neris-20110811, 8 rounds)

| flows | evaded | evasion % | mean corrupt |
|---|---|---|---|
| 24 | 24 | 100.0% | 0.0 |
| 100 | 94 | 94.0% | 8.69 |
| 300 | 287 | 95.7% | 7.71 |
| 323 | 69 | **21.4%** | 0.0 |

**Non-monotonic and unexplained.** The collapse at 323 needs either a diagnosis or an
explicit "we do not know" in the report. Do not smooth over it.

### Cross-capture (`cross_capture_summary.json`, cost 0.6)

**Regenerated 2026-10 from the per-capture reports. The numbers below are lower than
the ones this file used to carry — see the correction note under the table.**

| capture | baseline detected | policy evaded | corrupt-all evaded | verdict | evasion % |
|---|---|---|---|---|---|
| botnet-capture-20110810-neris | 23/24 | 4 | 4 | tie | 16.7% |
| botnet-capture-20110811-neris | 24/24 | 24 | 24 | tie | 100.0% |
| capture-win13 | 24/24 | 0 | 0 | tie | **0.0%** |

mean 38.89%, **std 43.74%**.

**Correction (2026-10).** This section previously reported mean 62.5% / std 44.49%,
with `botnet-capture-20110810-neris` at 87.5% and `botnet-capture-20110811-neris`
at baseline **0/24**. All four numbers were wrong, from one cause: the committed
`cross_capture_summary.json` predated the per-capture reports it summarises, because
`aggregate_results.py` filtered its input glob by the filename substring `"summary"`
only. The glob `cross_capture_*.json` also matched `cross_capture_eval.json`, a
differently-shaped report; that row failed the required-field check, `main()` exited
non-zero **without writing**, and the stale file survived unnoticed. The aggregator now
selects inputs by schema (`is_cross_capture_report`) and `controls/verify_report_claims.py`
asserts the summary agrees with every per-capture report, so a stale summary fails the
verifier instead of being published. The 0811 baseline of 0 was never real: the
per-capture report, the frozen noop control and the PPO eval all measured 24/24.

**Read this as a null result, not a score.** The `corrupt_all_evaded` column is the
point: on all three captures the policy evades exactly as many flows as corrupting
every reachable packet does, and at the same mean corruption. The policy ties the
control 3/3 — it learned nothing that the trivially-optimal "corrupt everything" action
does not already achieve. So the 100% on 0811 is a property of the control being
sufficient, not evidence for the RL agent. `capture-win13` at 0% remains the honest
signal that the policy does not generalise across captures.

### Corrupt-cost sweep (`sweep_corrupt_cost.json`)

100% evasion from cost 0.2 through 2.0, then 0% at cost 4.0. Mean corrupt pinned at 2.88
across every cost — the cost parameter is not shaping the policy, it is just switching it
off. Worth stating plainly rather than presenting as a clean sweep.

---

## 9. Discrepancies to resolve before writing

These are real inconsistencies between committed docs and committed reports. Fix them
first or a reviewer will find them.

1. **`docs/hidden_defender_results.md` §3 says `prepend`-family mechanisms solve 8/8 and
   `split8` solves 16/16.** The current reports say otherwise: the prepend family has
   **0/8** valid evasions, and the matrix runs on 8 HTTP-only flows, not 16. The doc
   predates the HTTP-only filter (`24614e2`) and the strict semantics bar. **It needs a
   correction commit.**
2. **Two test-set sizes coexist (16 vs 8)** without the docs saying why. Add the table
   from §2.
3. **`all_models_comparison.json` is from a superseded system** (Directional 82.5% vs
   Snort-aware 7.5% vs random 93.8% — random beats both, which is its own red flag). Not
   comparable to the current `HiddenDefenderEnv` numbers. Exclude or clearly mark as history.
4. **`mechanism_matrix.json`** (80 flows, 9 mechanisms, different mechanism names
   including `pad16`/`pad64`) is from an earlier generation. Exclude or mark as history.
5. **`docs/thesis/thesis_en.tex` and `thesis_vi.tex` describe the superseded bandit
   system.** Grep for `16/16`, `split8`, `MaskablePPO`, `hidden_defender` returns **0
   matches**. They need rewriting, not patching.

---

## 10. Suggested report structure

1. **Problem** — C2 beacons are detected by signature IDS; can an agent evade without
   breaking the C2 channel?
2. **Threat model** — red team mutates packets; blue team is real Snort 2.9.20 + ET Open
   C2 (21374 rules); attacker knows its own framing but not the ruleset.
3. **Environment** — `HiddenDefenderEnv`, 14 mechanisms, 8 obs features, action masking,
   C2-semantics check. State the reward's semantics bar explicitly.
4. **Measurement discipline** — real binary, one pair per pcap, negative control, oracle
   ceiling. *This section is what makes the rest believable.*
5. **Results** — headline 16/16 + control; per-mechanism table (§4) with both columns;
   baseline comparison (§5).
6. **Negative finding** — RL does not beat greedy under this defender, and why. Then the
   heterogeneous-defender proposal as the next experiment.
7. **Bugs and what they taught** (§6) — present as methodological contribution, not
   confession.
8. **Threats to validity** — n=16/64 single seed; surrogate drops 20.6% of rules;
   no cross-capture generalisation (0% on win13); non-monotonic scaling; single ruleset.
9. **Future work** — heterogeneous/adaptive defender; multi-seed; cross-capture.

---

## 11. Reproduce

```bash
cd /root/.hermes/c2-evasion-rl
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 -m pytest tests/ -q   # 90 passed

# headline
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 ai_agent/eval_masked_ppo_test.py --real-snort
# control
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 controls/control_noop_real_snort.py
# per-mechanism matrix + baselines (real Snort, ~80s)
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 snort_validation/eval_all_real_snort.py
# surrogate audit (224 real Snort calls, ~40 min)
PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 controls/surrogate_sweep_14mech.py
```
