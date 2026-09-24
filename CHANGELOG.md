CHANGELOG
=========

All notable changes since Snort integration (commit 95cb9cd, 2026-09-16) are
documented here. Sections track methodology, metrics, decision gates, and
thesis implications.

## [Unreleased] Enhanced Feature Engineering & Snort Surrogate v2 (2026-09-24)

### Motivation

The baseline Snort surrogate (v1) was trained on only 6 raw flow-aggregate
features: dur, tot_pkts, tot_bytes, src_bytes, proto, state. While it achieved
AUC 0.998 on held-out data, it could not model the behavioral signatures Snort
rules measure (payload size patterns, flag frequencies, packet-rate anomalies).
This milestone extends the surrogate to 16 features, aligning it with Snort's
rule logic and testing whether richer behavioral representations improve
defense-aware RL reward shaping.

### Task 1: Feature Extraction — CTU-13 Derivation Pipeline

**File:** `snort_validation/extract_ctu13_features.py`
**Input:** 13 CTU-13 capture files (binetflow parquet), 262,573 botnet flows
**Output:** `snort_validation/data/ctu13_features_candidates.csv` (11,729 flows × 27 cols)

#### Methodology

- **Sampling:** 1,000 flows per capture (13 total); captures with <1,000 botnet
  flows included entirely. This stratified sample (11,729 rows) is reproducible
  (seed=42) and covers all 13 captures equally.
  
- **Baseline features (6):** dur, tot_pkts, tot_bytes, src_bytes, proto, state.
  These are the raw flow aggregates from the CTU-13 schema.
  
- **Candidate features (20, derived):** Grouped into five families:
  1. **Packet size (7):** pkt_size_mean, std, min, max, median, iqr, cv
     - Derived from tot_bytes, tot_pkts using a bimodal MSS model
  2. **Inter-arrival time (5):** iat_mean, std, min, max, cv
     - Derived from dur, tot_pkts at fixed 0.25 CoV per the pcap emitter
  3. **Flow rate (2):** pkt_rate, bytes_rate
     - Ratios: tot_pkts/dur, tot_bytes/dur (nonlinear, capture burstiness)
  4. **TCP flags (3):** syn_count, fin_count, rst_count
     - Binary indicators from the CTU-13 state string (e.g., "FSPA_FSPA")
  5. **Payload entropy (1):** payload_entropy_est
     - 8 × (1 − header_fraction); header-only flow = 0, bulk transfer ≈ 8

- **Data quality:**
  - Missing values: 6 state nulls on ICMP flows (imputed to 'UNK')
  - Vectorized vs. scalar derivation: max absolute difference 0.000e+00 ✓
  - Distributions captured for all 262,573 botnet rows (100% population coverage)

#### Deliverables

- `ctu13_features_candidates.csv`: 11,729 rows, 27 columns (flow_id + 26 features)
- `ctu13_feature_distributions.json`: Summary statistics, feature ranges, class balance
- Both artifacts are now tracked in git (previously gitignored)

---

### Task 2: Feature Validation — Correlation with Snort Verdicts

**File:** `snort_validation/validate_features_vs_snort.py`
**Input:** 80 agent + 80 random + 80 baseline episodes from prior runs (320 total)
**Output:** `snort_validation/data/feature_validation_report{,_vs_xgb}.json/md`

#### Methodology

- **Target:** Snort-detected (1) vs. evaded (0) from the pcap reconstruction validation
- **Labelling:** 320 samples (191 detected, 59.7%) from three policies:
  - blind_agent (66 detected, 82.5%): the baseline RL policy, defense-unaware
  - random (55 detected, 68.8%): random mutations
  - baseline (4 detected, 5.0%): no mutation (strong evasion baseline)
  
- **Correlations:** Pearson r (point-biserial for binary targets) + Spearman rho
  - Effect-size gate: |r| > 0.15, p < 0.05
  - Collinearity guard: |r| < 0.95 among selected features
  - Top-10 selection: ranked by |r|, capped at top_k

- **Two analyses:**
  1. **Primary (vs Snort verdicts):** Correlation with actual IDS detection
  2. **Secondary (vs XGBoost judge):** Correlation with the surrogate's own
     evasion prediction (validation that features align with the judge, not just Snort)

#### Results

**Primary analysis (vs Snort):**
- Tested: 19/20 candidate features (iat_cv degenerate)
- Passed p < 0.05: 17 features
- Passed both gates (|r| > 0.15, p < 0.05): 12 features
- **Selected (literal top-10):** 10 features
  1. payload_entropy_est      r = −0.5077  (strongest signal)
  2. pkt_size_iqr             r = −0.2303
  3. pkt_size_min             r = +0.2296
  4. pkt_size_max             r = −0.2271
  5. pkt_size_median          r = −0.2238
  6. pkt_size_cv              r = +0.2215
  7. pkt_size_std             r = −0.2134
  8. pkt_size_mean            r = −0.2130
  9. avg_pkt_size (alias)     r = −0.2130
  10. rst_count               r = +0.1893

- **Collinearity (redundancy):** 16 pairs with |r| ≥ 0.95 inside the top-10:
  - pkt_size_mean ↔ avg_pkt_size: r = +1.000 (literal alias)
  - pkt_size_iqr ↔ pkt_size_median: r = +0.999
  - pkt_size_max ↔ pkt_size_median: r = +1.000
  - [13 more packet-size cross-correlations in the 0.97–1.00 range]
  
  **Interpretation:** The packet-size family is 9 algebraic restatements of a
  single signal: `tot_bytes / tot_pkts`. Training on all 10 does not add 10
  independent feature signals; it adds one signal 9 times over. The literal
  gate is kept (per plan) for reproducibility, but the "enhanced" feature
  count is 1 true signal + 4 ancillaries (payload_entropy, pkt_size_iqr,
  pkt_size_min, rst_count).

**Secondary analysis (vs XGBoost judge):**
- Tested: 19 features
- Passed p < 0.05: 13 features
- Passed both gates: 9 features
- **Selected (top-9):** Dominated again by packet-size family (9 selected, 7 redundant)
- Deduped: 3 features (payload_entropy_est, pkt_size_std, pkt_size_min)

**Decision:** Use the literal top-10 from the primary analysis (Snort verdicts)
to train the enhanced surrogate. This keeps the feature set decision grounded
in the defense mechanism (Snort) rather than the judge (which the surrogate
learns to approximate anyway).

#### Deliverables

- `feature_validation_report.json`: Full correlation table, decision audit per feature
- `feature_validation_report.md`: Markdown with redundancy analysis and collinearity pairs
- `feature_validation_report_vs_xgb.json/md`: Secondary analysis on the judge

---

### Task 3: Enhanced Dataset Preparation — Frozen Matrices for Training

**File:** `snort_validation/prepare_enhanced_surrogate_data.py`
**Input:** 320 labelled samples + feature-selection report from Task 2
**Output:** `snort_validation/data/surrogate_{baseline,enhanced}.npz`

#### Methodology

- **Baseline matrix (6 features):**
  - dur, tot_pkts, tot_bytes, src_bytes, proto_encoded, state_encoded
  - Shape: (320, 6)
  
- **Enhanced matrix (16 features):**
  - 6 baseline + 10 selected candidates (in order per feature_validation_report.json)
  - Shape: (320, 16)
  
- **Frozen split:** Both matrices use the same train/test indices (stratified, seed=42):
  - Train: 240 samples (143 positive, 47.9%)
  - Test:  80 samples (48 positive, 60.0%)
  
  **Why frozen:** Ensures AUC deltas are pure feature-set effects, not train/test variance.

- **Determinism proof:** SHA256 checksums stamped in manifest:
  - baseline: efa67d5723958114...
  - enhanced: 96bea4c582ee84f5...

#### Deliverables

- `surrogate_baseline.npz`: (320, 6) matrix, frozen split
- `surrogate_enhanced.npz`: (320, 16) matrix, frozen split
- `surrogate_dataset_manifest.json`: Metadata, checksums, feature order

---

### Task 4: Enhanced Surrogate Training & RL Integration

**Files:**
- `snort_validation/train_snort_surrogate.py` (trainer, --baseline / --enhanced)
- `ai_agent/c2_evasion_env.py` (environment, Snort reward wiring)
- `ai_agent/train_agent.py` (agent trainer, --enhanced flag)
- `ai_agent/config.py` (SNORT_SURROGATE_ENHANCED_PATH)

#### Methodology

**Surrogate Training:**
- **Baseline model:** XGBoost on 6 raw features (control, v1)
- **Enhanced model:** XGBoost on 16 features (v2)
- **Hyperparameters (both):** n_estimators=200, max_depth=4, lr=0.1, random_state=42
- **Feature stamping:** Both models are stamped with `snort_feature_names_`
  attribute before saving. This is critical: the RL environment reads this
  attribute to build the reward vector in the correct order. Without it, a
  16-feature model fed the wrong 10 derived columns would produce plausibly
  wrong reward values that silently corrupt learning.

**Acceptance gate (enhanced only):** AUC ≥ 0.95

**RL Integration:**
- Environment method `_snort_features()`: builds a variable-width feature
  vector by reading the loaded model's `snort_feature_names_` attribute.
- Environment method `_resolve_snort_features()`: resolves the feature order
  with this priority:
  1. Explicit caller-provided `snort_feature_names` (for tests)
  2. Model's stamped `snort_feature_names_` attribute (authoritative)
  3. Model's `n_features_in_` width (baseline only; raises if wider)
  
  **Guard:** A wide model without stamped names raises ValueError instead of
  guessing. This is intentional: silent misconfiguration is worse than a
  loud failure.

#### Metrics

**Baseline (v1, 6-feature model):**
- Held-out test (80 samples):
  - AUC: 0.9974
  - Accuracy: 0.9750
  - Precision: 0.9792
  - Recall: 0.9792
  - F1: 0.9792
  - Brier: 0.0226
  - Confusion: TP=47, FP=1, TN=31, FN=1

**Enhanced (v2, 16-feature model):**
- Held-out test (80 samples):
  - AUC: 0.9993  (delta: +0.0019, +0.2%)
  - Accuracy: 0.9750  (delta: 0.0000)
  - Precision: 0.9792  (delta: 0.0000)
  - Recall: 0.9792  (delta: 0.0000)
  - F1: 0.9792  (delta: 0.0000)
  - Brier: 0.0168  (delta: −0.0058, −25.7%)
  - Confusion: TP=47, FP=1, TN=31, FN=1  (identical)

**Decision gate result:** AUC 0.9993 ≥ 0.95 ✓ PASSED

#### Feature Importance (Top 10)

**Baseline:**
1. tot_pkts (0.7328) — packet count is the strongest signal
2. dur (0.1213)
3. proto_encoded (0.0644)
4. src_bytes (0.0394)
5. state_encoded (0.0326)
6. tot_bytes (0.0094)

**Enhanced:**
1. tot_pkts (0.6282) — still dominant, but weighted less
2. dur (0.2254) — elevated (now 2nd)
3. pkt_size_median (0.0370) — new, packet-size family contribution
4. pkt_size_max (0.0299)
5. proto_encoded (0.0233)
6. src_bytes (0.0204)
7. payload_entropy_est (0.0182)
8. pkt_size_std (0.0095)
9. tot_bytes (0.0050)
10. rst_count (0.0030)

**Observation:** Adding 10 features did not shift tot_pkts importance (still
0.6–0.73) — the new features are refinements, not fundamental regrounding.

#### Deliverables

- `data/snort_surrogate.pkl`: Baseline model (retrained on frozen split)
- `data/snort_surrogate_enhanced.pkl`: Enhanced model (16 features, AUC 0.9993)
- `snort_validation/data/surrogate_training_report.json`: Baseline metrics
- `snort_validation/data/surrogate_training_report_enhanced.json`: Enhanced metrics

---

## Thesis Implications & Decision Gates

### Central Question

**Can enriched behavioral features improve the robustness of an RL evasion agent
trained against a Snort-surrogate defense?**

### Findings So Far

1. **Feature correlation is weak** (|r| < 0.5 for the strongest candidate):
   - payload_entropy_est shows the strongest correlation (r = −0.5077),
   - but 9 of the top-10 features are redundant packet-size restatements.
   - This suggests Snort's detection logic is not primarily behavioral
     (packet sizes / inter-arrival times), but flow-aggregate-based (tot_pkts,
     duration).

2. **The surrogate is already near-perfect** (AUC 0.9974 → 0.9993):
   - Adding 10 features improves AUC by +0.2% and Brier by −25.7%, but
   - confusion matrix is identical (TP=47 FP=1 TN=31 FN=1 in both).
   - The gains are in calibration (Brier), not discrimination.

3. **The defense mechanism (Snort) may be simpler than the RL agent assumes:**
   - The baseline model relies almost entirely on tot_pkts (73% importance).
   - An attacker that understands this dominance might exploit it directly,
     bypassing the surrogate's reward signal entirely.

### Decision Gate: Proceed to Agent Training?

**Gate:** Enhanced surrogate must reach AUC ≥ 0.95 on held-out data.
**Result:** PASSED (AUC 0.9993).

**But the practical gate should be agent-centric:**
- Train an agent with the enhanced surrogate (--enhanced flag).
- Measure its Snort evasion rate in re-evaluation.
- If evasion rate improves > 5% vs. baseline, the features are strategically
  useful for the agent.
- If evasion rate is flat or worse, the features are statistically significant
  but strategically inert (a common ML pitfall).

---

## Commits Since Snort Integration

### Phase 1: Data Foundation

- **95cb9cd** (2026-09-16): feat(validation): add Snort IDS validation layer
  - First Snort integration: pcap reconstruction, Snort rule calibration

### Phase 2: Surrogate v1 & Lambda Sweep

- **b64607b** (2026-09-18): docs: add Snort validation section
- **a7206f9** (2026-09-18): feat(validation): calibrated Snort behavior rules
- **f902c5c** (2026-09-20): feat(validation): Snort surrogate for defense-aware reward
- **22a6407** (2026-09-20): feat(agent): Snort-surrogate defense-aware reward shaping
- **83257e0** (2026-09-21): feat(agent): --snort flag retrains with defense-aware reward
- **5436bc4** (2026-09-22): fix(validation): comment out emerging-botcc (was killing detections)
- **91e1445** (2026-09-23): fix(agent): explicit .zip suffix on save
- **96c1e0c** (2026-09-24): data(validation): full lambda sweep (l5/l10/l20)

### Phase 3: Feature Engineering & Surrogate v2 (This Milestone)

- **be3b6ed** (2026-09-24): feat(features): extract 20 candidate CTU-13 features
  - Task 1: 11,729 flows × 27 features from 262,573 botnet rows
  
- **1271549** (2026-09-24): feat(validation): validate features vs Snort verdicts
  - Task 2: correlation analysis, redundancy detection, decision gates
  
- **449ccb4** (2026-09-24): fix(validation): --out-suffix output path bug
  - Markdown report was overwritten by secondary analysis
  
- **671a780** (2026-09-24): feat(surrogate): enhanced 16-feature surrogate + env wiring
  - Task 3 & 4: data prep, training, RL integration
  - Baseline AUC 0.9974 → Enhanced AUC 0.9993 (gate PASSED)

---

## Known Limitations & Future Work

1. **Feature selection was correlational, not causal:**
   - Snort's true decision boundary is unknown; we inferred it from
     detection patterns on synthetic pcaps.
   - The features we selected correlate with detection, but may not causally
     drive Snort's rule engine.

2. **Packet-size redundancy not exploited:**
   - 9 of the top-10 features are algebraically dependent (r > 0.97).
   - Future work could use PCA or sparsity regularization to reduce this.

3. **No adversarial feature testing:**
   - We selected features that correlate with Snort detection, but did not
     test whether an agent can *exploit* those feature selections to evade
     better.
   - This is the next milestone: train agent(s) with the enhanced surrogate
     and measure real evasion gains vs. baseline.

4. **Snort rule calibration assumed static thresholds:**
   - Snort's dsize thresholds (e.g., >800 bytes) were reverse-engineered from
     CTU-13 botnet traffic.
   - Real-world Snort deployments may use different threshold tunings, making
     the surrogate domain-specific.

---

## Testing & Verification

- ✓ Feature extraction: vectorized vs. scalar derivation (max diff 0.000e+00)
- ✓ Feature validation: 320 labelled samples, 17/19 features significant
- ✓ Data prep: frozen train/test split, SHA256 checksums recorded
- ✓ Surrogate training: both models stamped with feature order
- ✓ RL env wiring: tested both 6-feature and 16-feature models
- ✓ Safety guard: model without stamped names raises ValueError (not silent)
- ✓ Acceptance gate: Enhanced AUC 0.9993 ≥ 0.95 (PASSED)

---

## Summary

This milestone extended the Snort surrogate from 6 to 16 features, grounded in
a rigorous validation study of 20 candidate behavioral features derived from
CTU-13 botnet traffic. The enhanced surrogate improves calibration (Brier −26%)
while maintaining discrimination (AUC +0.2%). Feature selection revealed strong
redundancy in the packet-size family, suggesting Snort's detection logic is
flow-aggregate-dominated (tot_pkts: 73% importance).

The real test is agent-side: in the next phase, we train an RL agent with the
enhanced surrogate and measure whether the richer behavioral representation
actually improves evasion performance. If agent evasion rate plateaus, the
features were statistically significant but strategically inert.

**Next milestone:** Enhanced agent training, re-evaluation, and thesis insights.

