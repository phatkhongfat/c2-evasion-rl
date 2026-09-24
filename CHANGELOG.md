# CHANGELOG

All notable changes to this project since the Snort integration landed
(commit `95cb9cd`) are documented here.

Scope: methodology, metrics deltas, decision gates, bug fixes, and thesis
implications. Every number below is traceable to a file in the repository; the
"Evidence" column of each section names it.

> **Read this first.** Two classes of result appear in this document and they
> must not be conflated:
>
> - **Reported (unseeded) metrics** — the original λ sweep as it was run and
>   committed (`*_evaluation.json` without a `_seeded_` prefix). These were
>   produced with unseeded episode sampling, so different runs saw different
>   flows. They are kept for provenance but are **not** a valid basis for
>   comparing policies.
> - **Seeded metrics** — the controlled re-run (`*_seeded_*.json`), where every
>   policy and every run evaluates the *same* 80 episodes. **These are the
>   numbers to cite.**
>
> See [Measurement integrity](#measurement-integrity) for the two bugs that
> made this distinction necessary.

---

## [Unreleased] Enhanced Feature Engineering & Snort Surrogate v2 (2026-09-24)

### Motivation

The v1 Snort surrogate was trained on 6 raw flow aggregates
(`dur`, `tot_pkts`, `tot_bytes`, `src_bytes`, `proto`, `state`) and reached
AUC 0.998. But those 6 features cannot express what Snort's rules actually
match — payload size distributions, flag cadence, packet-rate bursts. The
hypothesis for this milestone: **giving the surrogate the behavioural features
Snort's rules measure should make defense-aware reward shaping more faithful,
and therefore produce an agent that evades the real IDS better.**

That hypothesis is tested end-to-end below, and the answer is **no** — with an
important qualification about why.

---

### Task 1 — Extract 20 candidate features from CTU-13

**Script:** `snort_validation/extract_ctu13_features.py`
**Feature library:** `ai_agent/flow_features.py` (single source of truth)
**Input:** 13 CTU-13 capture files, 262,573 botnet-labelled flows
**Output:** `snort_validation/data/ctu13_features_candidates.csv` (11,729 × 27)
**Evidence:** `snort_validation/data/ctu13_feature_distributions.json`

#### Methodology

- **Sampling.** 1,000 botnet flows per capture, seeded (`seed=42`); captures
  with fewer than 1,000 botnet flows are taken whole. Result: 11,729 flows
  spanning all 13 captures. Sampling is stratified by capture so no single
  botnet family (Neris, Rbot, Virut, Murlo, …) dominates.
- **Baseline features (6):** the raw CTU-13 aggregates, unchanged.
- **Candidate features (20, derived)** in five families:

  | Family | n | Features |
  |---|---|---|
  | Packet size | 7 | `pkt_size_mean/std/min/max/median/iqr/cv` |
  | Inter-arrival time | 5 | `iat_mean/std/min/max/cv` |
  | Flow rate | 2 | `pkt_rate`, `bytes_rate` |
  | TCP flags | 3 | `syn_count`, `fin_count`, `rst_count` |
  | Payload | 1 | `payload_entropy_est` |
  | Flag summary | 1 | `flags_variety` |

- **Correctness check.** Every derived feature is implemented twice — once
  vectorised (pandas) and once scalar (per-row) — and the extractor asserts
  they agree. Max absolute difference across all 13 captures: **0.000e+00**.

#### Data-quality finding

**69 `state` values are null** in the source parquet (not 6 — see the bug list).
CTU-13 leaves `state` unset on ICMP flows. These are filled with the corpus's
own `UNK` token rather than dropped, and the imputation count is stamped into
the distributions JSON so it can never be silently forgotten.

---

### Task 2 — Validate the 20 features against Snort verdicts

**Script:** `snort_validation/validate_features_vs_snort.py`
**Dataset builder:** `snort_validation/surrogate_dataset.py` (shared by Tasks 2–4)
**Input:** 320 labelled episodes (191 Snort-detected, 59.7%)
**Output:** `snort_validation/data/feature_validation_report.{json,md}`
**Evidence:** the report above; secondary run in `..._vs_xgb.{json,md}`

#### Methodology

- **Target:** the real Snort verdict (`detected`) from pcap reconstruction —
  *not* the XGBoost judge's own prediction. Correlating features against the
  judge would be circular; the judge is what we are trying to improve.
- **Statistic:** Pearson r (which on a binary target is the point-biserial
  correlation). **Spearman rho is reported alongside** so a monotone-but-
  nonlinear relationship is not missed.
- **Decision gate (as specified):** `|Pearson r| > 0.15` **and** `p < 0.05`,
  ranked by `|r|`, top 10.
- **Robustness gate (added):** `|r| < 0.95` against already-selected features,
  to expose redundancy the literal gate cannot see.

#### Results — primary (vs Snort verdicts)

19 of 20 features were testable (`iat_cv` is degenerate — constant 0.25 by
construction, so its correlation is undefined). 17 passed `p < 0.05`; 12 passed
both gates.

| # | feature | Pearson r | p | Spearman rho | decision |
|---|---------|-----------|---|--------------|----------|
| 1 | `payload_entropy_est` | −0.5077 | 2.3e-22 | −0.503 | **selected** |
| 2 | `pkt_size_iqr` | −0.2303 | 3.2e-05 | −0.501 | **selected** |
| 3 | `pkt_size_min` | +0.2296 | 3.4e-05 | +0.230 | **selected** |
| 4 | `pkt_size_max` | −0.2271 | 4.1e-05 | −0.491 | **selected** |
| 5 | `pkt_size_median` | −0.2238 | 5.4e-05 | −0.439 | **selected** |
| 6 | `pkt_size_cv` | +0.2215 | 6.5e-05 | −0.051 | **selected** |
| 7 | `pkt_size_std` | −0.2134 | 1.2e-04 | −0.368 | **selected** |
| 8 | `pkt_size_mean` | −0.2130 | 1.2e-04 | −0.444 | **selected** |
| 9 | `avg_pkt_size` | −0.2130 | 1.2e-04 | −0.444 | **selected** |
| 10 | `rst_count` | +0.1893 | 6.6e-04 | +0.189 | **selected** |
| 11 | `pkt_rate` | +0.1712 | 2.1e-03 | +0.593 | below top-10 |
| 12 | `bytes_rate` | +0.1579 | 4.6e-03 | +0.597 | below top-10 |
| 13–17 | `iat_max/std/mean/min`, `fin_count` | −0.130…+0.128 | ~0.02 | — | below `|r|` floor |
| 18–19 | `flags_variety`, `syn_count` | +0.094, −0.058 | 0.09, 0.31 | — | not significant |
| 20 | `iat_cv` | n/a | n/a | n/a | degenerate |

Bonferroni-adjusted α would be 0.00263; 11 features survive it. Multiple-
comparison correction does not change the conclusion.

#### Results — secondary (vs the XGBoost judge)

Run with `--target run_xgb_evaded --out-suffix _vs_xgb`. Same packet-size
family dominates; `rst_count` and `pkt_rate` drop out, and the deduplicated set
shrinks to 3 features. The judge and Snort agree on the dominant signal, which
is what makes the surrogate trainable at all — but the agreement is on
*packet size*, i.e. on `tot_bytes / tot_pkts`.

#### The redundancy finding (the important result)

**The literal top-10 contains 16 pairs with `|r| ≥ 0.95`.**

```
pkt_size_mean    ↔ avg_pkt_size      r = +1.000   ← literal alias
pkt_size_max     ↔ pkt_size_median   r = +1.000
pkt_size_iqr     ↔ pkt_size_max      r = +1.000
pkt_size_iqr     ↔ pkt_size_mean     r = +0.999
pkt_size_max     ↔ pkt_size_mean     r = +0.999
pkt_size_median  ↔ pkt_size_mean     r = +0.999
… 10 more in the 0.979–0.999 range
```

Nine of the ten selected features are algebraic restatements of one quantity:
`tot_bytes / tot_pkts`. `avg_pkt_size` is a *literal* duplicate of
`pkt_size_mean`. De-duplicating leaves only:

```
payload_entropy_est, pkt_size_iqr, pkt_size_min, rst_count   (+ pkt_rate)
```

**So "10 selected features" is really 1 independent signal plus 3–4
ancillaries.** Training on all ten does not give the model ten new things to
learn. This is stated up front because it is the single most important
interpretive fact in this milestone, and it is easy to miss when reading a
feature-importance table.

**Decision taken:** keep the literal top-10 as the training set (that is what
the plan specified, and it keeps the run reproducible and comparable), but
report the deduplicated set in every downstream claim.

---

### Task 3 — Freeze the enhanced training set

**Script:** `snort_validation/prepare_enhanced_surrogate_data.py`
**Output:** `snort_validation/data/surrogate_{baseline,enhanced}.npz` + manifest
**Evidence:** `snort_validation/data/surrogate_dataset_manifest.json`

- **Baseline matrix:** `(320, 6)` — the six raw aggregates.
- **Enhanced matrix:** `(320, 16)` — the six plus the ten selected.
- **One frozen split for both** (stratified, `seed=42`, `test_size=0.25`):
  train 240 (143 positive, **59.6%**), test 80 (48 positive, **60.0%**).
  Freezing the split is what makes the AUC delta a feature-set effect rather
  than train/test resampling noise.
- **SHA256 checksums** of both matrices are stamped in the manifest, so a
  future run can prove it trained on the same bytes.

**Leakage caveat (documented, not fixed):** the split is stratified by verdict
but **not grouped by source flow**. All four policy runs draw from the same
CTU-13 pool, so near-duplicate flows can straddle the train/test boundary and
the held-out AUC is optimistic relative to a grouped split. The manifest
records this (`leakage_note`). It does not change the *direction* of the
baseline-vs-enhanced comparison, because both models see the identical split.

---

### Task 4 — Train the enhanced surrogate and wire it into the RL env

**Scripts:** `snort_validation/train_snort_surrogate.py` (`--baseline` / `--enhanced`)
**Env:** `ai_agent/c2_evasion_env.py`, `ai_agent/config.py`, `ai_agent/train_agent.py`
**Output:** `data/snort_surrogate.pkl` (6 feat), `data/snort_surrogate_enhanced.pkl` (16 feat)
**Evidence:** `snort_validation/data/surrogate_training_report{,_enhanced}.json`

#### Method

Identical hyperparameters for both arms — `n_estimators=200`, `max_depth=4`,
`learning_rate=0.1`, `random_state=42` — so the only difference is the feature
matrix. Both models are stamped with a `snort_feature_names_` attribute before
saving.

That stamp matters more than it looks. The env builds the reward vector by
reading `snort_feature_names_`; without it, a 16-feature model handed the wrong
ten derived columns would return plausible-but-wrong probabilities and silently
corrupt the reward signal. `_resolve_snort_features()` therefore refuses to
guess: a model wider than the 6-feature baseline that carries no stamp raises
`ValueError`. A loud failure beats a silent one.

#### Metrics — surrogate (held-out 80 samples, frozen split)

| Metric | Baseline (6 feat) | Enhanced (16 feat) | Δ |
|---|---|---|---|
| **AUC** | 0.9974 | **0.9993** | **+0.0019** |
| Accuracy | 0.9750 | 0.9750 | 0.0000 |
| Precision | 0.9792 | 0.9792 | 0.0000 |
| Recall | 0.9792 | 0.9792 | 0.0000 |
| F1 | 0.9792 | 0.9792 | 0.0000 |
| Average precision | 0.9983 | 0.9996 | +0.0013 |
| **Brier (lower better)** | 0.0226 | **0.0168** | **−0.0058 (−25.7%)** |
| Confusion | TP=47 FP=1 TN=31 FN=1 | TP=47 FP=1 TN=31 FN=1 | **identical** |

**Decision gate: AUC ≥ 0.95 → PASSED (0.9993).**

**But read the last row.** The confusion matrices are *identical*. Ten extra
features changed no discrete decision on any of the 80 held-out samples. The
AUC and Brier gains are **calibration only** — the model is more confident
about being right, not right about more things. An acceptance gate written as
"AUC ≥ 0.95" is passed by both models, which tells you the gate was too weak to
be informative here. The agent-side test below is what actually settles it.

#### Feature importance

| Baseline | imp | Enhanced | imp |
|---|---|---|---|
| `tot_pkts` | 0.7328 | `tot_pkts` | 0.6282 |
| `dur` | 0.1213 | `dur` | 0.2254 |
| `proto_encoded` | 0.0644 | `pkt_size_median` | 0.0370 |
| `src_bytes` | 0.0394 | `pkt_size_max` | 0.0299 |
| `state_encoded` | 0.0326 | `proto_encoded` | 0.0233 |
| `tot_bytes` | 0.0094 | `payload_entropy_est` | 0.0182 |

`tot_pkts` alone carries 73% of the baseline model's importance and still
carries 63% after adding ten features. The new features are refinements
competing for the residual; they do not re-ground the model. This is the
expected consequence of the redundancy finding in Task 2.

---

## Measurement integrity

Two bugs meant the committed λ-sweep results could not support the comparison
they appeared to support. Both are fixed; the fixes are in commits `2776a00`
and `396029b`.

### Bug A — unseeded episode sampling made cross-run deltas meaningless

`run_evaluation.py` sampled episodes with a bare `env.reset()`, so **every
policy and every run saw a different 80 episodes.** The tell: the
*no-mutation* baseline — which mutates nothing, so its evasion rate is a pure
function of which flows were drawn — moved **5.0% → 15.0% → 10.0% → 3.8%**
across runs. Any cross-run delta therefore mixed the policy effect with episode
sampling variance.

Direct evidence of the confound: the blind and enhanced agent runs had
**0/80 episodes in common**, yet were being compared to each other.

**Fix:** episode *i* is reset with `seed + i`, so every policy and every run
evaluates the identical episode sequence. The no-mutation baseline now reports
3/80 XGBoost and 6.25% Snort detection in *all* runs — the signature of correct
pairing.

### Bug B — no run tag, so sweep results overwrote each other

Neither `run_evaluation.py` nor `validate_with_snort.py` accepted a suffix, so
every λ wrote to the same `agent_evaluation.json`. The result:
`agent_evaluation.json` and `agent_evaluation_l10.json` were **byte-identical**,
and `agent_snort_validation.json` matched `..._l10.json` — the λ=10 Snort
numbers had been copied, never measured. Both scripts now take `--suffix`.

A third, related bug: `train_agent.py` built its model tag from
`(snort?, lambda)` only, so an enhanced-surrogate run at λ=10 **silently
overwrote** the blind-surrogate λ=10 model. The tag now includes the enhanced
marker, an existing-file overwrite prints a warning, and the save path is
echoed with the resolved surrogate path.

---

## Metrics — full comparison

All agent figures below are **seeded** (identical 80 episodes). `Snort
detection` is the rate at which real Snort flags the agent's mutated flows;
lower is better for the attacker. `XGBoost evasion` is the rate at which the
agent's mutations fool the original CTU-13 surrogate — the metric the agent was
originally trained against.

| Run | Surrogate used for reward | λ | XGBoost evasion | Snort detection | Snort evasion |
|---|---|---|---|---|---|
| **No-mutation baseline** | — | — | 3.8% (3/80) | 6.25% (5/80) | 93.8% |
| **Random mutations** | — | — | 66.2% (53/80) | 68.75% (55/80) | 31.25% |
| **Blind agent** | none | — | **97.5% (78/80)** | **70.0% (56/80)** | 30.0% |
| **λ=10, blind surrogate** | 6-feature v1 | 10 | 95.0% (76/80) | 85.0% (68/80) | 15.0% |
| **λ=10, enhanced surrogate** | 16-feature v2 | 10 | 95.0% (76/80) | 85.0% (68/80) | 15.0% |

The two control rows (baseline 3/80, random 55/80) are **identical across all
three runs**, which is the signature that episode pairing is working. Under the
old unseeded harness these moved between runs (baseline: 5% → 15% → 10% → 3.8%).

### Reading the table

1. **The blind agent is the strongest attacker.** 97.5% XGBoost evasion and the
   lowest Snort detection (70.0%) of any agent row. The defense-aware reward did
   not produce a better evader — it produced a *worse* one.

2. **Defense-aware reward made the agent more detectable, not less.** Snort
   detection rises 70.0% → 85.0% when λ=10 shaping is added. Adding the
   surrogate penalty made the agent 15 points *easier* to catch by the real IDS.

3. **The enhanced surrogate changed the agent's behaviour but not its outcome.**
   The λ=10 blind-surrogate and λ=10 enhanced-surrogate agents produce
   **completely different mutation sequences — 0 of 80 episodes share mutated
   features** — and land on **exactly the same aggregate result**: 76/80 XGBoost
   evasion and 68/80 Snort detections, in both cases. The ten extra features
   redirected *which* flows the agent mutated without moving *how many* it
   evaded. Different strategy, same score.

   That is a sharper result than a trivial "nothing changed". It means the
   enriched features did reach the agent's policy (it explored a different
   region of mutation space) but the region it found is equally detectable. The
   extra features added search dimensions, not evasion capability.

### Why (1) and (2) happen — and it is not a bug

The surrogate's reward is `−λ · P(Snort flags this flow)`. The agent minimizes
that penalty. But the surrogate is a **proxy** trained on Snort verdicts, and
its decision surface is dominated by `tot_pkts` (63–73% importance). The agent
learned to move `tot_pkts` into whatever region minimizes the surrogate's
probability — which is not the same region that minimizes *real* Snort
detection. Penalizing a proxy drives the agent to exploit the proxy's
boundary, and the proxy's boundary is where it is least like the real detector.

This is the classic reward-hacking failure mode, and here it is measured rather
than asserted: the shaping penalty improved the quantity it was given
(surrogate-predicted detection) while *degrading* the quantity it was meant to
improve (real Snort detection).

---

## Thesis implications

**The central hypothesis — "richer behavioural features make defense-aware
reward shaping more faithful, producing a better evader" — is not supported.**
Both halves fail, for different reasons, and the failures are more interesting
than a positive result would have been.

1. **Feature enrichment was statistically real but strategically inert.** The
   selected features are significantly correlated with Snort verdicts
   (`payload_entropy_est` at r = −0.51, p ≈ 2e-22). But 9 of 10 are restatements
   of `tot_bytes / tot_pkts`, the surrogate's confusion matrix did not move, and
   the agent's evasion *count* did not move (0.0pp) even though its mutation
   *strategy* changed entirely. *Correlation with the target is not evidence
   that a feature adds usable information* — a lesson worth stating plainly in
   the thesis, because a feature-importance table would have hidden it.

2. **A strong proxy is not a good reward signal.** The v1 surrogate has AUC
   0.998 and the v2 has 0.9993 — both near-perfect at *predicting Snort*, and
   both actively harmful as *reward functions*. Surrogate accuracy and reward
   fidelity are different properties, and an acceptance gate on AUC measures
   the wrong one. The correct gate is behavioural: does the agent that optimizes
   the surrogate also evade the real IDS better? Here, no — it evades worse.

3. **Defense-aware shaping requires the defense in the loop, not a model of it.**
   The agent that ignored the defense entirely (blind) was the best real-world
   evader. The agent that optimized a model of the defense was measurably worse
   against the actual defense. For an evasion agent, "train against the thing"
   and "train against a model of the thing" are not interchangeable — and the
   gap between them is exactly the exploitability of the proxy.

4. **The detection surface is flow-aggregate, not behavioural.** Snort's
   behaviour rules (dsize thresholds, small-packet bursts) were calibrated to
   the CTU-13 distribution and yet `tot_pkts` — a raw aggregate — dominates
   every model of them. The behavioural features that were supposed to capture
   rule logic turned out to be derived from the same aggregate. The
   "behavioural" framing of the candidate set was optimistic.

### The baseline paradox — the sharpest result in the table

The no-mutation baseline **evades real Snort 93.8% of the time**, while every
agent mutates itself into a *worse* position (30.0%, 15.0%, 15.0%). Read the
two judge columns together and the reason is unambiguous:

| Policy | XGBoost judge says evaded | Real Snort says evaded | Gap |
|---|---|---|---|
| No mutation | 3.8% | **93.8%** | **90.0pp** |
| Random | 66.2% | 31.2% | 35.0pp |
| Agent | 97.5% | 30.0% | 67.5pp |

On *unmutated* real botnet flows the two judges disagree by ~90 percentage
points. Snort's behaviour rules barely fire on genuine CTU-13 botnet traffic,
while the XGBoost surrogate flags almost all of it.

**Consequences.**

1. The agent is **counterproductive**: it starts from flows that already evade
   Snort 93.8% of the time and mutates them into flows that evade only 30%.
   The agent is not defeating the defense; it is manufacturing detection.

2. The surrogate's 0.998–0.9993 AUC is **not evidence of fidelity**. It is
   accuracy at reproducing a label that, on this corpus, is nearly the inverse
   of the real detector's behaviour. The surrogate learned to predict *the
   validation pipeline's own verdicts*, which were themselves produced by
   behaviour rules that do not fire on the target distribution.

3. **This, not the feature count, is why the λ sweep failed.** The reward was
   `−λ · P(surrogate flags flow)`, and the surrogate's notion of "flagged" is
   anti-correlated with Snort's on the flows that matter. Adding λ pushed the
   agent further into the surrogate's confidence region — i.e. further into
   detection.

The honest summary is that the reward shaping did not fail because the features
were weak. It failed because the reward signal pointed the wrong way.

### Decision gates, restated

| Gate | Threshold | Result | Verdict |
|---|---|---|---|
| Enhanced surrogate accuracy | AUC ≥ 0.95 | 0.9993 | **PASS** (but uninformative — v1 also passes) |
| Enhanced vs baseline surrogate | confusion matrix improves | identical | **FAIL** (calibration-only gain) |
| Enhanced agent vs λ=10 blind agent | evasion rate improves >5pp | 0.0pp | **FAIL** |
| Defense-aware vs blind agent (real Snort) | detection decreases | 70.0% → 85.0% | **FAIL** (worse) |

Only the first gate passes, and the reason it is uninformative is itself a
finding: an AUC threshold cannot distinguish a surrogate that helps the agent
from one that misleads it.

---

## Bug fixes since Snort integration

| Commit | Fix | Impact |
|---|---|---|
| `5436bc4` | Commented out missing `emerging-botcc` include in `snort.conf` | Snort exited fatally on the missing file, so **every detection read 0**. All pre-fix Snort numbers were invalid. |
| `91e1445` | Explicit `.zip` suffix on model save; `run_evaluation --agent-model` | Saved models were not loadable by the eval script's path. |
| `449ccb4` | `--out-suffix` wrote markdown to the constant `OUT_MD` path | The secondary analysis overwrote the primary report; the `_vs_xgb.md` file was reported as written but never existed. |
| `2776a00` | `--suffix` + `--enhanced` args; model tagging | See [Bug B](#bug-b--no-run-tag-so-sweep-results-overwrote-each-other). |
| `396029b` | Deterministic episode seeding | See [Bug A](#bug-a--unseeded-episode-sampling-made-cross-run-deltas-meaningless). |

### Correction to the CTU-13 null count

The extractor initially reported **6** null `state` values; the correct count
across the full 13-capture sample is **69**. The original figure came from a
partial read. `state` is null on ICMP flows in CTU-13 and is now imputed to
`UNK`, with the count stamped into `ctu13_feature_distributions.json`.

---

## Commits since Snort integration (`95cb9cd`)

**Phase 1 — Snort integration**

- `95cb9cd` add Snort IDS validation layer (pcap reconstruction, rule calibration)
- `b64607b` document the Snort validation section in the README

**Phase 2 — Surrogate v1, reward shaping, λ sweep**

- `a7206f9` calibrated Snort behaviour rules; first measured agent vs random vs baseline
- `f902c5c` Snort surrogate for defense-aware reward
- `22a6407` Snort-surrogate defense-aware reward shaping (opt-in)
- `83257e0` `--snort` flag retrains with defense-aware reward
- `5436bc4` fix: comment out missing `emerging-botcc` include; add `--snort-lambda`
- `91e1445` fix: explicit `.zip` suffix on save; `run_evaluation --agent-model`
- `96c1e0c` full λ sweep results (l5/l10/l20)

**Phase 3 — Feature engineering & surrogate v2 (this milestone)**

- `be3b6ed` Task 1 — extract 20 candidate CTU-13 features
- `1271549` Task 2 — validate features against Snort verdicts
- `449ccb4` fix — `--out-suffix` output path
- `671a780` Tasks 3–4 — enhanced surrogate + env wiring
- `2776a00` fix — `--suffix`/`--enhanced`, model tagging
- `396029b` data — seeded λ sweep + Snort validation
- _this commit_ — corrected CHANGELOG

---

## Reproducing

```bash
# Task 1 — extract candidate features (~2 min, 13 captures)
python snort_validation/extract_ctu13_features.py --max-flows-per-file 1000

# Task 2 — validate against Snort verdicts
python snort_validation/validate_features_vs_snort.py
python snort_validation/validate_features_vs_snort.py \
       --target run_xgb_evaded --out-suffix _vs_xgb

# Task 3 — freeze the training matrices
python snort_validation/prepare_enhanced_surrogate_data.py

# Task 4 — train both surrogates
python snort_validation/train_snort_surrogate.py --baseline
python snort_validation/train_snort_surrogate.py --enhanced

# Train the enhanced agent (tagged, will not clobber other models)
cd ai_agent && python train_agent.py --enhanced --snort-lambda 10

# Seeded evaluation — the numbers in the table above
python snort_validation/run_evaluation.py \
       --agent-model models/ppo_c2_evasion_agent_snortaware_enhanced_10.0.zip \
       --suffix _seeded_enh10 --seed 42 --num-episodes 80
python snort_validation/validate_with_snort.py --suffix _seeded_enh10
```

---

## Known limitations

1. **Held-out AUC is optimistic.** The split is stratified but not grouped by
   source flow; near-duplicate flows can straddle it. Both surrogate arms see
   the identical split, so the comparison holds, but the absolute AUC values
   should not be read as generalization estimates.
2. **Snort thresholds are reverse-engineered** from the CTU-13 botnet
   distribution, so the surrogate is deployment-specific. A differently-tuned
   Snort would likely shift every number here.
3. **Detection is measured on reconstructed pcaps**, not live traffic. Payloads
   are synthetic filler, so content/signature rules can never fire — only
   behaviour rules can. This is stated in `rules/botnet-behavior.rules` and is a
   property of the validation harness, not a bug.
4. **Feature selection was correlational, not causal.** We measured which
   features co-vary with detection; we did not establish that Snort's rules
   *read* them. The redundancy finding suggests the causal story is narrower
   than the correlation table implies.
5. **The λ sweep covers 5/10/20 only** at the seeded standard. The λ=5 and λ=20
   arms have not been re-run under seeded evaluation, so their committed numbers
   carry the same sampling confound described in Bug A.

---

## Verification checklist

- [x] Feature derivation: vectorised vs scalar agree, max diff 0.000e+00
- [x] Feature validation: 320 samples, 19 features tested, 17 significant
- [x] Redundancy detected: 16 pairs with `|r| ≥ 0.95` inside the literal top-10
- [x] Frozen split with SHA256-stamped matrices
- [x] Both surrogates stamped with `snort_feature_names_`; env refuses to guess
- [x] Env wiring exercised at both widths (6 and 16) against a live env
- [x] Surrogate gate: enhanced AUC 0.9993 ≥ 0.95
- [x] Seeded evaluation: no-mutation baseline identical (3/80) across all runs
- [x] λ=10 blind and λ=10 enhanced models confirmed distinct on disk
- [x] Snort validation run for blind / λ=10 / enhanced on identical episodes
- [x] **Task 3 (NEW) — Snort-Direct Agent Training:** trained with `--snort-direct --snort-direct-mode replica` (196 iterations, 277s total, deterministic seeded)
- [x] **Task 4 (NEW) — Snort-Direct Validation:** 80-episode seeded validation complete; results: 6.2% Snort evasion (degraded from blind λ=10 baseline 15.0%)
- [x] **Overfitting finding:** snort-direct agent achieved 100% evasion on small validation set (20 flows) but only 6.2% on full 80-episode test — replica mock (100% accurate on 299 lab verdicts) diverges from real Snort at scale
- [x] **Thesis update:** added Finding #5 on the limits of replica-mock training; Key Lesson now emphasizes verification necessity
- [x] **Task 5 (FINAL) — Horizon Sweep & Gate Decision:** real Snort validation across mutation horizons H=0,1,2,3,5,10 and each policy's own MDP; H=10 result: **93.75% detection (6.25% evasion)** — **FAIL gate** (≤55% detection criterion). Two independent clean runs agree on every row.
- [x] **Correction:** an earlier "42.5% detection @ H=10 → PASS" reading (commit `3024f86`) was an artifact of two Snort validators sharing one `snort_logs/alert` file; it is not reproducible. 42.5% is the **H=5** row. See `docs/SNORT_DIRECT_TASK5_CORRECTED.md`.
- [x] **Root cause:** the policy evades real Snort **95.0%** when rolled in its own MDP (early stop on the replica, mean length 1.59) but **6.25%** when the gate scores it over the full 10 steps (XGBoost never confirms, so padding accumulates). The replica is exonerated: **80/80 agreement** with real Snort on these flows, zero false negatives.
- [x] **Comparison:** snort-direct agent at the gate's horizon achieves 6.25% evasion vs blind λ=10 baseline 32.5% (horizon-matched) — **Task 7 required**.
