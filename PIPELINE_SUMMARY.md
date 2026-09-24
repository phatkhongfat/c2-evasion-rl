# Pipeline Execution Summary

**Status:** ✅ Tasks 1–6 Complete | 🔄 Task 7 In Progress

---

## What Was Built

### Task 1: CTU-13 Feature Extraction
- **Input:** 13 PCAP files (262,504 botnet flows)
- **Output:** 11,729 sampled flows × 27 features
- **Key Finding:** 7 packet-size features are algebraic restatements of `tot_bytes / tot_pkts` (100% redundant)

### Task 2: Feature Validation vs Snort IDS
- **Method:** Pearson correlation on 320 labelled samples (191 detected)
- **Gate:** |r| > 0.15, p < 0.05
- **Result:** 17/19 features significant; **10 selected** (top-9 + baseline tot_pkts)
- **Strongest Feature:** payload_entropy_est (r = −0.5077, p = 2.2e-16)

### Task 3: Enhanced Surrogate Dataset
- **Baseline (v1):** 320 × 6 features (aggregate stats only)
- **Enhanced (v2):** 320 × 16 features (baseline + top-9 selected)
- **Deterministic:** Both frozen on identical train/test split (240/80, seed=42)

### Task 4: Surrogate Model Retraining
| Metric | Baseline | Enhanced | Delta |
|--------|----------|----------|-------|
| AUC | 0.9974 | 0.9993 | +0.0019 ✓ |
| Brier | 0.0226 | 0.0168 | −0.0058 (−26%) |
| Confusion | TP=47, FP=1 | TP=47, FP=1 | Identical |

**Gate:** AUC ≥ 0.95 → **PASSED** (both models)

### Task 5: Enhanced Agent Training
- **Blind Policy (λ=10):** 50k timesteps, 6 features, Snort reward shaping
- **Enhanced Policy (λ=10):** 50k timesteps, 16 features, **enhanced** Snort reward shaping
- **Verification:** 0/20 actions identical → policies genuinely distinct
- **Models:** `ppo_c2_evasion_agent_snortaware_10.0.zip` (blind) vs `ppo_c2_evasion_agent_snortaware_enhanced_10.0.zip` (enhanced)

### Task 6: Enhanced Agent Evaluation (XGBoost Surrogate)
| Policy | XGBoost Evasion | Samples |
|--------|-----------------|---------|
| Blind Agent (λ=10) | 75/80 (93.8%) | — |
| Enhanced Agent (λ=10) | **75/80 (93.8%)** | — |
| Random | 51/80 (63.7%) | — |
| Baseline | 8/80 (10.0%) | — |

**Finding:** Enhanced agent achieves **parity** with blind agent on surrogate (93.8% both).

### Task 7: Real Snort IDS Validation (In Progress)
- Running: `python snort_validation/validate_with_snort.py --suffix _enhanced_10`
- Expected: Detection rates for blind vs enhanced on **actual Snort IDS**, not XGBoost
- Decision Gate: Enhanced evasion ≥ blind evasion − 5% (allow natural variance)

---

## Critical Bugs Fixed

### Bug #1: Hardcoded Paths in `validate_with_snort.py` ✅
**Problem:** No CLI args; always overwrote `snort_validation_summary.json`  
**Impact:** All λ=10 Snort reports were byte-identical (same data measured twice)  
**Fix:** Added `--suffix` arg; now produces distinct filenames

### Bug #2: Hardcoded Paths in `run_evaluation.py` ✅
**Problem:** No `--suffix` arg; clobbered previous policy evals  
**Fix:** Added `--suffix`, `--num-episodes` args

### Bug #3: Model Tagging in `train_agent.py` ✅
**Problem:** Enhanced models saved as `ppo_c2_evasion_agent_snortaware_10.0.zip`, overwriting blind models  
**Fix:** Tag now includes `_enhanced`: `ppo_c2_evasion_agent_snortaware_enhanced_10.0.zip`

### Bug #4: Policy Distinction Verification ✅
**Test:** Loaded both λ=10 models, compared actions on 20 identical observations  
**Result:** 0/20 actions identical → policies are genuinely different

---

## Thesis Implications

**Central Question:** Can enriched behavioral features improve RL evasion robustness?

**Evidence:**
1. Strongest feature correlation r = −0.51 (weak); 90% of selected features derived from tot_pkts
2. Surrogate near-perfect with baseline (AUC 0.9974); enhanced gain (+0.2%) is calibration only
3. Enhanced and blind agents achieve identical XGBoost evasion (93.8%)

**Hypothesis:** Snort's detection logic is **aggregate-based** (flow volume, duration, packet count dominate). Fine-grained payload features (entropy, packet size variance) are statistically significant but **strategically inert** for evasion.

**Real Test:** Snort validation in progress. If enhanced agent evasion on real Snort ≤ blind agent (±5%), hypothesis confirmed.

---

## Artifacts & Reproducibility

**Data Files (Frozen):**
- `snort_validation/data/ctu13_features_candidates.csv` (11,729 × 27)
- `snort_validation/data/surrogate_baseline.npz` (320 × 6)
- `snort_validation/data/surrogate_enhanced.npz` (320 × 16)

**Models:**
- `models/ppo_c2_evasion_agent_snortaware_10.0.zip` (blind λ=10)
- `models/ppo_c2_evasion_agent_snortaware_enhanced_10.0.zip` (enhanced λ=10)

**Reports:**
- `snort_validation/reports/agent_evaluation_enhanced_10.json` (XGBoost eval)
- `snort_validation/reports/*_snort_validation_enhanced_10.json` (Snort IDS, in progress)

**Documentation:**
- `CHANGELOG.md` — Tasks 1–4 with full methodology
- `FINAL_REPORT.md` — End-to-end pipeline with integrity analysis

---

## Commits (Tasks 1–6)

| Task | Commits |
|------|---------|
| 1 (CTU-13) | `be3b6ed` (extraction pipeline) |
| 2 (Validation) | `2abd844` (CHANGELOG.md) |
| 3–4 (Surrogate) | `a7206f9`, `f902c5c` |
| 5 (Training) | `22a6407`, `83257e0`, `96c1e0c` |
| 6–7 (Bug Fixes) | `2776a00` (CLI args, model tagging) |

---

## Next Steps

1. **Await Snort Validation (Task 7):** Expected completion <10 min
2. **Merge Snort Reports:** Update `FINAL_REPORT.md` with real IDS results
3. **Decision Gate:** If enhanced evasion ≥ blind − 5%, features are valuable. Otherwise, inert.
4. **Thesis Chapter:** Document findings on aggregate-based detection and feature redundancy

---

**Generated:** 2026-09-24 14:20 UTC+7  
**Pipeline Status:** 85% complete (awaiting Snort validation)
