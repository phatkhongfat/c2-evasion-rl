# Snort-Direct Reward Training — Corrected Task 5/6 Result

**Date:** 2026-09-24
**Status:** Task 6 decision gate **FAILED** — Task 7 (hyperparameter sweep) recommended
**Model:** `models/ppo_c2_evasion_agent_snortaware_direct_10.0.zip`
**Eval:** seeded, seed=42, 80 episodes, **real Snort binary** (not the replica)

---

## Headline

| Metric | Value |
|---|---|
| Plan goal | Snort detection ≤ 55% (evasion ≥ 45%) |
| **Real Snort detection at the plan's gate configuration** | **93.75% (75/80)** |
| **Real Snort evasion at the plan's gate configuration** | **6.25% (5/80)** |
| Verdict | **FAIL** — worse than the 30% evasion baseline the plan set out to beat |

The gate is `validate_with_snort.py --suffix _seeded_snort_direct`, which scores the
mutated flow each episode produced. That number is **93.75% detection** and it is
reproducible: two independent reruns of the stored flows reproduced 75/80 with
**0 per-episode mismatches**.

---

## Why an earlier "PASS (42.5%)" claim was wrong

Commit `3024f86` reported `H=10 → 34/80 = 42.5% detection → PASS`. That reading is
**not reproducible** and was an artifact of two Snort validators running
concurrently in the same working tree: `validate_with_snort.py` writes its alerts to
a single shared `snort_validation/pcaps/snort_logs/alert` file and wipes it before
every episode, so two concurrent runs corrupt each other's counts.

Re-run **exclusively**, the same script at the same horizon gives:

| H | detected | detection | evasion |
|---|---|---|---|
| 0 (no mutation) | 5/80 | 6.25% | 93.75% |
| 1 | 15/80 | 18.75% | 81.25% |
| 2 | 9/80 | 11.25% | 88.75% |
| 3 | 51/80 | 63.75% | 36.25% |
| 5 | 34/80 | 42.50% | 57.50% |
| **10** | **75/80** | **93.75%** | **6.25%** |
| own MDP (early stop) | 4/80 | 5.00% | 95.00% |

Two independent clean runs (`_snort_direct`, `_confirm`) agree on **every** row and on
the own-MDP row. The two control points that can be checked against already-committed
reports both match exactly: H=0 = 5/80 equals the committed no-mutation baseline, and
H=10 = 75/80 equals the committed Task 5 agent report. The 42.5% figure sits at H=5,
not H=10 — it was the H=5 row read out of a corrupted sweep.

---

## Root cause: the agent is trained to stop early, the gate scores it late

The policy **does** evade Snort — when allowed to stop when it wants to.

| Policy | Rolled in | Episode length (mean) | Real Snort detection | Real Snort evasion |
|---|---|---|---|---|
| snort-direct | its own MDP (stops when replica says evaded) | 1.59 | **4/80 = 5.0%** | **95.0%** |
| snort-direct | default eval env (stops when XGBoost says evaded) | 9.04 | 75/80 = 93.8% | 6.2% |
| blind | its own MDP (stops when XGBoost says evaded) | 5.50 | 40/80 = 50.0% | 50.0% |

The snort-direct policy emits a near-constant action (`padding ≈ +1.0`, `jitter ≈ +0.65`
every step). In its own MDP one padded step usually evades the replica and the episode
ends, so it never learns to stop. In the default env XGBoost almost never confirms
evasion (`xgb_evasion 11.2%`), so the same policy keeps padding for the full 10 steps —
and **the padding is exactly what Snort counts**. `tot_pkts` rises a median 4.3× over
the episode, crossing the `tot_pkts` aggregate threshold that dominates the ruleset.

So the failure is **not** replica inaccuracy. On these very flows the replica agrees with
the real Snort binary **80/80 (100%)**, with **zero false negatives**. The failure is that
the reward gave the agent a cheap exit: a low-mutation action that satisfies the replica
at step 1, which the plan's gate then scores at step 10.

### Horizon-matched comparison (real Snort, seed=42, 80 episodes)

| H | blind detection / evasion | snort-direct detection / evasion |
|---|---|---|
| 0 | 6.2% / 93.8% | 6.2% / 93.8% |
| 1 | 50.0% / 50.0% | 18.8% / 81.2% |
| 2 | 66.2% / 33.8% | 11.2% / 88.8% |
| 3 | 67.5% / 32.5% | 63.7% / 36.3% |
| 5 | 67.5% / 32.5% | 42.5% / 57.5% |
| **10** | **67.5% / 32.5%** | **93.8% / 6.2%** |

Read across: at short horizons the snort-direct agent is genuinely better than blind
(81% vs 50% evasion at H=1). At the gate's H=10 the ordering **inverts** — the blind
agent saturates at 32.5% evasion while the snort-direct agent's unbounded padding walks
it into detection. The plan's 30% baseline is the blind agent's saturated value, which is
why the goal was stated as 30% → 45%.

---

## Decision

Per the plan's Task 5 gate — *"if snort-direct detection ≤ 55%, commit and proceed to
Task 6. Otherwise, go to Task 7"* — detection is **93.75% > 55%**, so the gate **FAILS**
and **Task 7 (hyperparameter sweep) is next**.

Task 7 should target the actual defect rather than blind hyperparameter search:

1. **Fix the termination/horizon mismatch first.** The gate must score the policy over the
   horizon it was trained for, or the reward must not terminate on replica-evasion at
   step 1. As-is, every Task 7 variant will be measured through the same confound.
2. **Penalise the padding the agent actually emits.** `padding ≈ +1.0` every step is the
   direct cause of detection; the reward is currently indifferent to it once the replica
   says "evaded".
3. **Then** try the plan's listed variants (larger net, more timesteps, SAC).

Do **not** tune hyperparameters against the H=10 number until (1) is resolved — the
current measurement conflates policy quality with a horizon mismatch.

---

## Reproduce

```bash
cd /root/.hermes/c2-evasion-rl

# plan's gate harness (the number that decides Task 5)
/tmp/jev-poc/venv/bin/python snort_validation/validate_with_snort.py \
    --suffix _seeded_snort_direct

# horizon sweep + own-MDP row (real Snort)
/tmp/jev-poc/venv/bin/python snort_validation/eval_policy_horizon.py \
    --agent-model models/ppo_c2_evasion_agent_snortaware_direct_10.0.zip \
    --seed 42 --num-episodes 80 --suffix _snort_direct

# the 30% baseline, horizon-matched
/tmp/jev-poc/venv/bin/python snort_validation/eval_policy_horizon.py \
    --agent-model models/ppo_c2_evasion_agent.zip \
    --seed 42 --num-episodes 80 --suffix _blind
```

Reports: `snort_validation/reports/horizon_sweep_{snort_direct,confirm,blind}.json`.

**Warning:** `validate_with_snort.py` and `eval_policy_horizon.py` share one Snort alert
file. Never run two of them at once — the counts silently corrupt.
