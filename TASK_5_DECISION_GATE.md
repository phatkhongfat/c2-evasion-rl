# Task 5 Decision Gate Report

## Real Snort Validation Results (Task 5 Prescribed Measurement)

### Plan Task 5 Requirement
- **Objective:** Measure actual Snort evasion rate on the snort-direct agent via 80 seeded episodes (seed=42) + real Snort validation
- **Decision gate:** if detection ≤ 55%, commit and proceed to Task 6. Otherwise, recommend Task 7 hyperparameter sweep.

### Measured Results

**Using plan-prescribed run_evaluation.py harness (DEFAULT env):**
```
Agent | Snort Detection | Snort Evasion | Status
----- | --------------- | ------------- | ------
snort-direct | 93.8% (75/80) | 6.2% (5/80) | FAIL — detection > 55%
```

**Decision gate verdict: FAIL.** Detection = 93.8% (>55% threshold). Per plan Task 5, recommend Task 7 hyperparameter sweep.

---

## Root Cause Analysis (Not Prescribed, But Critical)

The policy/horizon mismatch reveals the true failure mode:

### Evidence A: Policy in its own training MDP (snort-direct=True, replica terminator)
```
Episode length: mean=1.59 steps (95% complete within 2 steps)
REAL SNORT evasion: 95.0% (4 detected / 80 total)
```
✓ The policy learned a functional low-mutation strategy that evades real Snort.

### Evidence B: Policy in DEFAULT eval MDP (no snort_direct flag, XGBoost terminator)
```
Episode length: mean=9.04 steps (89% run to 10-step limit)
REAL SNORT evasion: 6.2% (75 detected / 80 total)
```
✗ Same policy, different terminator → catastrophic failure.

### Root Cause
The snort-direct policy was trained to solve this problem: *"Stop mutating as soon as the Snort replica says evaded."* It learned early-termination strategies (mean 1.59 steps, 95% < 2 steps).

But the eval harness (run_evaluation.py) uses a different terminator (XGBoost evasion verdicts), which the policy almost never satisfies (XGBoost evasion: 11.2%). So the harness runs every episode to the 10-step limit, where accumulated mutations overwhelm any early evasion the policy found.

**The policy is not broken—it was trained for a different terminator than it was evaluated on.**

---

## Implications for Task 6/7

### If Task 6 Proceeds (Detection ≤ 55%):
- Not applicable; gate not met.

### Task 7 Recommendation (Detection > 55%):
The current failure is not a learning problem—it's a **MDP mismatch**. Hyperparameter sweeps (Task 7: larger nets, longer training, SAC) will not fix this because:
1. The policy already learns near-optimal behavior for its training MDP (95% evasion in training, only 5% detected)
2. The eval harness measures a different MDP (no snort_direct terminator)
3. More capacity or iterations will not change the terminator dynamics

**Alternative approach (Task 7 pivot):**
- Retrain with `--snort-direct` AND configure eval harness to use `snort_direct=True` terminator
- Or: train without snort_direct but accept that the policy will maximize XGBoost evasion (not real Snort evasion)
- Or: accept that blind agent (15% Snort evasion) is the current best real-world evader

---

## Evidence Artifacts
- `/tmp/c2scratch/t5_decisive.txt` — Real Snort binary validation, both MDPs, 80 flows each
- Plan goal: ≥45% evasion (≤55% detection)
- Achieved: 6.2% evasion (93.8% detection) — fails gate
- Horizon sweep (in progress): fixed-step analysis to confirm MDP mismatch

---

## Recommendation
**Report FAIL to Task 5 gate. Before Task 7, diagnose whether the goal is:**
1. Improve real Snort evasion on the eval harness → requires retraining + eval harness change
2. Improve XGBoost-evading mutations that also fool Snort → different architecture needed
3. Accept blind agent baseline → no further work needed
