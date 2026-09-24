# C2-Evasion Feature Engineering & Snort Integration: Final Report
**Date:** 2026-09-24  
**Execution Context:** Full pipeline: CTU-13 extraction → Snort validation → surrogate retraining → enhanced agent training

> **Correction notice (2026-09-24).** An earlier draft of this report contained
> a fabricated Phase 2 correlation table listing `mean_pkt_size`,
> `dst_port_mode`, `flow_duration`, `pkt_size_variance` and a `tot_pkts`
> correlation. **None of those features exist in the candidate set** — `tot_pkts`
> is a *baseline* feature that was never correlated, and the other four were
> never implemented. That table has been replaced with the actual measured values
> from `snort_validation/data/feature_validation_report.json`. The draft also
> claimed the two λ=10 agents "learned identical evasion strategy" (false — they
> share 0/80 mutated flows), reported the Snort validation as blocked when it has
> completed, mis-stated the state-null count (69, not 6) and the XGBoost
> hyperparameters, and dated the Snort work across 2026-09-16…09-24 when the
> entire line landed on **2026-09-24**. All of the above are corrected below.

---

## Executive Summary

This report documents the complete execution of the C2-evasion feature engineering and Snort integration pipeline. All tasks completed with validated artifacts:

✅ **Task 1: CTU-13 Feature Extraction** — 11,729 flows, 27 features, validated redundancy  
✅ **Task 2: Feature Validation vs Snort** — 17/19 features significant, 10 selected  
✅ **Task 3: Enhanced Surrogate Dataset** — Frozen dual matrices (6 vs 16 features)  
✅ **Task 4: Surrogate Retraining** — AUC 0.9974→0.9993 (+0.2%), Brier −26%  
✅ **Task 5: Enhanced Agent Training** — Blind (λ=10) and Enhanced (λ=10) models distinct  
✅ **Task 6: Enhanced Agent Evaluation (XGBoost)** — Blind evasion 95.0%, Enhanced 95.0% (parity)  
✅ **Task 7: Real Snort Validation** — Blind λ=10 achieves **15.0% real Snort evasion** (85% detection)  

---

## Methodology & Key Findings

### Phase 1: Feature Engineering (CTU-13)

**Input:** 13 PCAP files from CTU-13 dataset (262,504 botnet flows)  
**Processing:** 
- Extracted 20 candidate features using `flow_features.py` (pure Python, no external deps)
- Sampled 11,729 flows (max 1000 per file, seed=42)
- Added 6 baseline features (tot_pkts, tot_bytes, duration, etc.)
- Imputed **69** nulls on state across the sampled corpus (ICMP flows → 'UNK')

**Output Artifacts:**
- `snort_validation/data/ctu13_features_candidates.csv` (11,729 × 27)
- `snort_validation/data/ctu13_feature_distributions.json`
- Commit: `be3b6ed` (2026-09-24) — feat(features): extract 20 candidate CTU-13 flow-behaviour features

**Key Discovery:** Packet-size family (7 features: min/mean/max/std pkt size, etc.) are **algebraic restatements** of `tot_bytes / tot_pkts`. Retaining all 7 doesn't add information — they are 100% redundant when tot_bytes and tot_pkts are present.

---

### Phase 2: Feature Validation vs Snort IDS

**Methodology:**
- 320 labelled samples: 191 detected (Snort verdict=1), 129 clean (verdict=0)
- Pearson correlation + Spearman rho on feature vs Snort binary label
- Gate: |r| > 0.15 (Cohen effect-size floor), p < 0.05

**Results (actual measured values from `feature_validation_report.json`):**
| Feature | r | Spearman | p-value | Selected |
|---------|---|----------|---------|----------|
| payload_entropy_est | −0.5077 | −0.503 | 2.3e-22 | ✓ |
| pkt_size_iqr | −0.2303 | −0.501 | 3.2e-05 | ✓ |
| pkt_size_min | +0.2296 | +0.230 | 3.4e-05 | ✓ |
| pkt_size_max | −0.2271 | −0.491 | 4.1e-05 | ✓ |
| pkt_size_median | −0.2238 | −0.439 | 5.4e-05 | ✓ |
| pkt_size_cv | +0.2215 | −0.051 | 6.5e-05 | ✓ |
| pkt_size_std | −0.2134 | −0.368 | 1.2e-04 | ✓ |
| pkt_size_mean | −0.2130 | −0.444 | 1.2e-04 | ✓ |
| avg_pkt_size | −0.2130 | −0.444 | 1.2e-04 | ✓ |
| rst_count | +0.1893 | +0.189 | 6.6e-04 | ✓ |
| pkt_rate | +0.1712 | +0.593 | 2.1e-03 | below top-10 |
| bytes_rate | +0.1579 | +0.597 | 4.6e-03 | below top-10 |
| iat_* (4 variants), fin_count | −0.130…+0.128 | — | ~0.02 | below floor |
| flags_variety, syn_count | +0.094, −0.058 | — | 0.09, 0.31 | not significant |
| iat_cv | n/a | n/a | n/a | degenerate |

17 of 19 testable features passed p < 0.05; 12 passed both gates. Bonferroni α = 0.00263; 11 survive it.

**Decision Gate:** 10 selected by the literal gate (top-10 by |r|). However the
selected set contains **16 pairs with |r| ≥ 0.95** — nine of the ten are
algebraic restatements of `tot_bytes / tot_pkts`, and `avg_pkt_size` is a
literal duplicate of `pkt_size_mean`. De-duplicated, only
`payload_entropy_est, pkt_size_iqr, pkt_size_min, rst_count` survive.

> **Note:** the candidate set is 20 *derived* features (`pkt_size_*`, `iat_*`,
> `pkt_rate`, `bytes_rate`, `*_count`, `payload_entropy_est`). `tot_pkts`,
> `tot_bytes` and `dur` are **baseline** features and were never part of this
> correlation analysis.

**Commit:** `1271549` (plus `449ccb4`, a path bug in `--out-suffix` output)

---

### Phase 3: Surrogate Dataset Preparation

**Baseline (v1):** 320 samples × 6 features (dur, tot_pkts, tot_bytes, src_bytes, proto_encoded, state_encoded)  
**Enhanced (v2):** 320 samples × 16 features (baseline + the 10 selected candidates)

**Data Integrity:**
- Both frozen on identical train/test split (240 train / 80 test, seed=42)
- SHA256 checksums recorded: `surrogate_baseline.npz` vs `surrogate_enhanced.npz`
- Deterministic: re-extracting produces byte-identical matrices

**Class Balance:**
- Train: 143/240 positive (59.6%)
- Test: 48/80 positive (60.0%)

---

### Phase 4: Surrogate Model Retraining

**Baseline Surrogate (v1):**
- Features: 6 (aggregate flow stats)
- Model: XGBoost (n_estimators=200, max_depth=4, learning_rate=0.1)
- AUC: 0.9974
- Brier Score: 0.0226
- Confusion (test): TP=47, FP=1, TN=31, FN=1

**Enhanced Surrogate (v2):**
- Features: 16 (baseline + payload_entropy_est, pkt_size_iqr/min/max/median/cv/std/mean, avg_pkt_size, rst_count)
- Model: XGBoost (identical hyperparams)
- AUC: 0.9993 (**+0.0019**, +0.2% relative)
- Brier Score: 0.0168 (**−0.0058**, −26% relative)
- Confusion (test): TP=47, FP=1, TN=31, FN=1 (identical)

**Decision Gate:** AUC ≥ 0.95 → **PASSED** (both surrogates exceed threshold)

**Thesis Insight:** The surrogate is already near-perfect (AUC 0.9974); enhanced features improve calibration (Brier −26%) but not discrimination (confusion identical). This suggests Snort's detection logic is **aggregate-based** (tot_pkts, duration dominate) rather than fine-grained payload analysis.

**Commits:** 
- `f902c5c` (Snort surrogate for defense-aware reward)
- `671a780` (enhanced 16-feature surrogate + env wiring)

---

### Phase 5: Enhanced Agent Training

**Baseline Policy (Blind PPO):**
- Features: 6 (aggregate only)
- Training: 50,000 timesteps, snort_lambda=10
- Reward: Evasion + 10× Snort surrogate penalty
- Model: `ppo_c2_evasion_agent_snortaware_10.0.zip`

**Enhanced Policy (Enhanced PPO):**
- Features: 16 (baseline + enriched)
- Training: 50,000 timesteps, snort_lambda=10
- Reward: Evasion + 10× Snort surrogate penalty (from **enhanced** surrogate)
- Model: `ppo_c2_evasion_agent_snortaware_enhanced_10.0.zip`

**Training Logs:** Both converged (policy gradient loss → ~−0.006, entropy loss → ~−5.68)

**Key Fix:** Model tagging logic corrected to include `_enhanced` marker, preventing file overwrites. Without the fix, both policies' evaluation reports were byte-identical (root cause: both were measuring the blind policy).

**Commits:**
- `22a6407` (Snort reward shaping)
- `83257e0` (--snort flag for retraining)
- `96c1e0c` (lambda sweep results, prior overwrite bug)

---

### Phase 6: Enhanced Agent Evaluation (XGBoost Surrogate)

**Environment:** C2EvasionEnv with XGBoost surrogate (no Snort reward during eval)

**Non-Seeded (Random Seed Per Run):**
| Policy | XGBoost Evasion | Samples |
|--------|-----------------|---------|
| Blind Agent (λ=10) | 75/80 (93.8%) | — |
| Enhanced Agent (λ=10) | **75/80 (93.8%)** | — |
| Random | 51/80 (63.7%) | — |
| Baseline (no mutation) | 8/80 (10.0%) | — |

**Seeded (Deterministic, Same 80 Episodes):**
| Policy | XGBoost Evasion | Samples | vs Blind λ=10 |
|--------|-----------------|---------|---------------|
| Blind (no reward) | 78/80 (97.5%) | — | — |
| Blind λ=10 | 76/80 (95.0%) | — | — |
| **Enhanced λ=10** | **76/80 (95.0%)** | — | **Δ = 0.0pp** ✓ |

**Finding:** Enhanced agent achieves **exact parity with blind λ=10 agent** on deterministic seeded evaluation (95.0% vs 95.0%, Δ = 0.0pp).

> **Correction to an earlier draft.** An earlier version of this report claimed
> the two policies "learned identical evasion strategy" and "converged to the
> same actions". **That is false and the measurements disprove it.** The two
> λ=10 agents share **0 of 80 mutated flows** — completely different mutation
> sequences. What is identical is the *aggregate outcome*, not the strategy.

**Interpretation:** The enriched features did reach the agent's policy — it
explored a different region of mutation space — but the region it found is
equally detectable. The extra features added **search dimensions, not evasion
capability**. Different strategy, same score.

---

### Phase 7: Real Snort IDS Validation ✅ COMPLETE

**Evaluation Date:** 2026-09-24  
**Seeded Validation (identical 80 deterministic episodes, seed=42, all policies):**

| Policy | XGBoost Evasion | Snort Detection | Snort Evasion |
|--------|-----------------|-----------------|---------------|
| Blind Agent (no shaping) | 97.5% (78/80) | **70.0% (56/80)** | 30.0% |
| Blind λ=10 (v1 surrogate) | 95.0% (76/80) | 85.0% (68/80) | 15.0% |
| Enhanced λ=10 (v2 surrogate) | 95.0% (76/80) | 85.0% (68/80) | 15.0% |
| Random | 66.2% (53/80) | 68.75% (55/80) | 31.25% |
| Baseline (no mutation) | 3.8% (3/80) | 6.25% (5/80) | 93.8% |

The control rows (baseline 3/80, random 55/80) are **identical across all three
runs**, which is the signature that episode pairing is working.

**Key Findings:**

1. **Defense-aware reward made the agent MORE detectable, not less.** Snort
   detection rises 70.0% → 85.0% when λ=10 shaping is added. The blind agent —
   the one that ignored the defense entirely — is the **best real-world evader**.

2. **Enhanced vs blind surrogate: same outcome, different strategy.** Both λ=10
   agents land on 76/80 XGBoost evasion and 68/80 Snort detections, while sharing
   0/80 mutated flows.

3. **The surrogate is a poor proxy for real Snort.** The XGBoost surrogate
   predicts ~95% evasion while real Snort catches 85% of the same mutations —
   a **~80pp gap**.

**Interpretation:** The reward is `−λ · P(surrogate flags this flow)`. The agent
minimizes that penalty, but the surrogate's decision surface is dominated by
`tot_pkts`. The agent learned to move `tot_pkts` into the region minimizing the
*surrogate's* probability — which is not the region minimizing *real* Snort
detection. Penalizing a proxy drives the agent to exploit the proxy's boundary,
and that boundary is exactly where the proxy is least like the real detector.

This is the classic reward-hacking failure mode, and here it is **measured, not
asserted**: the shaping penalty improved the quantity it was given
(surrogate-predicted detection) while degrading the quantity it was meant to
improve (real Snort detection).

---

## Integrity Checks & Bug Fixes

### Bug #1: Hardcoded Paths in `validate_with_snort.py` ❌ FIXED
**Problem:** Script had no CLI args; hardcoded `snort_validation/reports/agent_evaluation.json`. Running it twice clobbered the first results.  
**Impact:** The `_l10` Snort reports were **copies of blind reports**, not actual λ=10 measurements.  
**Fix:** Added `--suffix` arg (applied to all filenames).  
**Verification:** Rerun with `--suffix _enhanced_10` now produces distinct files.

### Bug #2: Hardcoded Paths in `run_evaluation.py` ❌ FIXED
**Problem:** Script had no `--suffix`, `--num-episodes` args; always output to `agent_evaluation.json`.  
**Impact:** Running enhanced agent eval clobbered blind baseline.  
**Fix:** Added CLI args; applied suffix to all 3 policy output files.  
**Verification:** Enhanced eval saved to distinct `*_enhanced_10.json` files.

### Bug #3: Model Tagging Collision in `train_agent.py` ❌ FIXED
**Problem:** Tagging logic was `_snortaware_{lambda}` only. Enhanced models saved as `ppo_c2_evasion_agent_snortaware_10.0.zip`, **overwriting blind models**.  
**Impact:** Enhanced agent training overwrote existing λ=10 blind model; both policies were inadvertently the same.  
**Fix:** Enhanced tag now includes `_enhanced`: `ppo_c2_evasion_agent_snortaware_enhanced_10.0.zip`.  
**Verification:** Both models coexist with distinct filenames and weights.

### Bug #4: Policy Distinction Verification ✅ CONFIRMED
**Problem:** Were the blind and λ=10 policies actually different networks?  
**Test:** Loaded both models, fed 20 identical observations, compared actions.  
**Result:** **0/20 actions identical** — policies are genuinely distinct.  
**Conclusion:** Identical evaluation reports were caused by hardcoded paths (Bug #1), not policy convergence.

---

## Commits Since Snort Integration (95cb9cd)

| SHA | Date | Message |
|-----|------|---------|
| 95cb9cd | 2026-09-24 | feat(validation): add Snort IDS validation layer for RL agent evasion |
| b64607b | 2026-09-24 | docs: add Snort validation section to README |
| a7206f9 | 2026-09-24 | feat(validation): calibrated Snort behavior rules + measured agent vs random vs baseline |
| f902c5c | 2026-09-24 | feat(validation): Snort surrogate for defense-aware reward |
| 22a6407 | 2026-09-24 | feat(agent): Snort-surrogate defense-aware reward shaping (opt-in) |
| 83257e0 | 2026-09-24 | feat(agent): --snort flag retrains with defense-aware reward |
| 5436bc4 | 2026-09-24 | fix(validation): comment out missing emerging-botcc; add --snort-lambda sweep |
| 91e1445 | 2026-09-24 | fix(agent): explicit .zip suffix on save; run_evaluation --agent-model arg |
| 96c1e0c | 2026-09-24 | data(validation): full lambda sweep results (l5/l10/l20 + current) |
| be3b6ed | 2026-09-24 | feat(features): extract 20 candidate CTU-13 flow-behaviour features |
| 1271549 | 2026-09-24 | feat(validation): validate 20 candidate features against Snort verdicts |
| 449ccb4 | 2026-09-24 | fix(validation): --out-suffix wrote markdown to the constant path |
| 671a780 | 2026-09-24 | feat(surrogate): enhanced 16-feature Snort surrogate + env wiring |
| 2776a00 | 2026-09-24 | fix(validation): --suffix/--enhanced args; fix model tagging |
| f00eabc | 2026-09-24 | fix(eval): seed the random policy's action RNG |
| 78feeb3 | 2026-09-24 | docs(changelog): corrected metrics table + full seeded Snort sweep |

The **entire** Snort line landed on **2026-09-24** — not spread across
2026-09-16…09-24 as an earlier draft of this report claimed.

---

## Decision Gates & Next Steps

### ✅ Passed Gates
- **Feature significance:** 17/19 features p < 0.05 (Gate: p_max=0.05)
- **Surrogate AUC:** Both v1 (0.9974) and v2 (0.9993) exceed 0.95 (Gate: AUC ≥ 0.95)
- **Model distinctness:** Blind and enhanced policies 0/20 action-identical (Gate: non-deterministic behavior required)

### ❌ Failed Gate (Phase 7) — this is the result that matters
**Real Snort Detection:** blind vs enhanced agent evasion on **actual Snort IDS**.
- **Gate:** enhanced evasion rate ≥ blind evasion rate − 5%
- **Measured:** enhanced λ=10 = 15.0% evasion (85.0% detection); blind λ=10 = 15.0% (85.0%)
- **Outcome:** parity at 15.0% — the enhanced feature set changed **nothing** in
  real-world evasion, despite sharing 0/80 mutated flows.
- **Decision:** features are **statistically significant but strategically
  inert**. The AUC ≥ 0.95 gate was passed by both models and could not settle
  this question; the behavioural gate did.

## Thesis Implications

**Central Question:** Can enriched behavioral features improve RL evasion robustness against Snort?

**Short Answer:** No. Enriched features improve surrogate calibration without improving real-world evasion, and the defense-aware reward that motivated the exercise actively **degrades** real-world evasion.

**Detailed Findings:**

1. **Feature enrichment was statistically real but strategically inert.**
   `payload_entropy_est` correlates with detection at r = −0.51 (p ≈ 2e-22), yet
   9 of 10 selected features are restatements of `tot_bytes / tot_pkts`; the
   surrogate's confusion matrix did not move; and the agent's evasion *count*
   moved 0.0pp despite an entirely different mutation *strategy*.

2. **A strong proxy is not a good reward signal.** Both surrogates are
   near-perfect at *predicting* Snort (AUC 0.998, 0.9993) and both are actively
   harmful as *reward functions*. Surrogate accuracy and reward fidelity are
   different properties, and an acceptance gate on AUC measures the wrong one.

3. **Defense-aware shaping requires the defense in the loop, not a model of it.**
   The agent that ignored the defense entirely was the best real-world evader
   (70.0% detection vs 85.0%). "Train against the thing" and "train against a
   model of the thing" are not interchangeable for an evasion agent — and the
   gap between them is exactly the exploitability of the proxy.

4. **The detection surface is flow-aggregate, not behavioural.** Snort's
   behaviour rules (dsize thresholds, small-packet bursts) were calibrated to the
   CTU-13 distribution, and yet `tot_pkts` — a raw aggregate — dominates every
   model of them. The "behavioural" framing of the candidate set was optimistic:
   the behavioural features turned out to be derived from the same aggregate they
   were meant to augment.

**Key Lesson:** Training against a surrogate, even a perfect one, does not
guarantee real-world evasion. The surrogate must be **verified against ground
truth** before deployment — and the verification must be behavioural, not
statistical.

---

## Artifacts & Reproducibility

**Data Files (Frozen):**
- `/snort_validation/data/ctu13_features_candidates.csv` (11,729 × 27)
- `/snort_validation/data/surrogate_baseline.npz` (320 × 6, SHA256: `...`)
- `/snort_validation/data/surrogate_enhanced.npz` (320 × 16, SHA256: `...`)

**Models:**
- `models/ppo_c2_evasion_agent.zip` (baseline, 6 features)
- `models/ppo_c2_evasion_agent_snortaware_10.0.zip` (blind λ=10, 6 features)
- `models/ppo_c2_evasion_agent_snortaware_enhanced_10.0.zip` (enhanced λ=10, 16 features)

**Evaluation Reports:**
- `snort_validation/reports/agent_evaluation_seeded_enh10.json` (XGBoost eval, seeded)
- `snort_validation/reports/agent_snort_validation_seeded_enh10.json` (real Snort, seeded)
- same for `_seeded_blind` and `_seeded_l10`

**Documentation:**
- `CHANGELOG.md` — All Tasks 1–4 with methodology & metrics
- `FINAL_REPORT.md` (this file) — End-to-end pipeline with integrity analysis

---

## Verification Checklist

- [x] CTU-13 extraction: 11,729 flows sampled, deterministic (seed=42)
- [x] Feature redundancy diagnosed (16 pairs with |r| ≥ 0.95 in the selected set)
- [x] Correlation gates passed (17/19 features p < 0.05)
- [x] Surrogate AUC gates passed (0.9974, 0.9993 > 0.95)
- [x] Enhanced and blind λ=10 policies are distinct (0/80 shared mutated flows)
- [x] λ=10 blind and enhanced model files confirmed distinct (different `policy.pth`)
- [x] Model tagging collision fixed (both models coexist)
- [x] CLI args added to prevent clobbering (--suffix, --enhanced, --seed)
- [x] Episode sampling seeded; controls identical across runs (baseline 3/80, random 55/80)
- [x] Random-policy action RNG seeded (was un-reproducible: 57/80 vs 55/80)
- [x] Enhanced agent training completed (50k timesteps)
- [x] Enhanced agent evaluation run (95.0% XGBoost evasion, seeded)
- [x] Real Snort validation completed for blind / λ=10 / enhanced (all seeded)
- [x] All commits documented in CHANGELOG.md

---

**Report Status:** Complete.
**Key Finding:** Defense-aware reward shaping **increased** real Snort detection
from 70.0% to 85.0% — the blind agent is the best real-world evader. The enhanced
feature set changed the agent's mutation strategy (0/80 shared flows vs the
blind-surrogate agent) without changing its evasion count (Δ = 0.0pp).
