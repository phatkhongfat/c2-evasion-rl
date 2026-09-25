# Investigation: Baseline Paradox

## Finding

Real Snort validation reveals a critical discovery:

| Policy | Snort Detection | Snort Evasion |
|--------|-----------------|---------------|
| **Baseline** (zero mutations) | 6.2% | **93.8%** |
| **Agent** (learned policy) | 70.0% | 30.0% |
| **Random** (random mutations) | 68.8% | 31.2% |

**The agent's learned mutations actively *harm* evasion by 63.8 percentage points.**

The agent performs worse than random action and vastly worse than inaction.

## Root Cause

The agent was trained to fool the XGBoost surrogate. The surrogate assigns high evasion probability to:
- Large `tot_pkts` (packet count)
- Large `tot_bytes` (total bytes)
- Long flows

These are exactly the features that **trigger Snort detection**:
- Snort sid 3000003/3000004: detect on `tot_pkts >= 5–8`
- Snort sid 3000001: detect on large payload (`tot_bytes` concentrated)
- Window thresholds detect sustained high-rate flows

The agent optimized for the wrong objective.

## Implication for the Improvement Plan

The current plan (commit to `/root/.hermes/plans/2026-09-24_151448-improve-snort-evasion.md`) proposes:
> Replace the XGBoost surrogate with Snort verdicts as the training reward.

**This will not solve the problem.** The agent will learn a new set of mutations optimized for Snort evasion instead of XGBoost evasion. But:

1. **The optimal policy is to do nothing.** Zero mutations = 93.8% evasion.
2. **Any mutation the agent learns will likely be sub-optimal**, because the action space is adversarial: to evade Snort you must avoid the very mutations that fool XGBoost.
3. **RL is the wrong tool.** The agent is learning to trade off between contradictory objectives (fool XGBoost vs. evade Snort), and the optimal solution is at a corner: take zero action.

## Path Forward

### Option 1: Constrain the action space
Train the agent to output *minimal* mutations only (e.g., small perturbations to duration or packet timing, not packet count inflation). This requires redesigning the action space.

### Option 2: Reframe as a constraint satisfaction problem
Instead of RL, solve: "Find the minimal mutation that evades Snort *and* fools XGBoost." This is a search problem, not an optimization problem.

### Option 3: Accept that the baseline is the best we can do
If the unmodified flow already evades Snort at 93.8%, then the C2 agent's only job is to avoid mutation entirely—not to mutate intelligently.

### Option 4: Investigate the Snort ruleset
The ruleset may be too strict. If real botnet traffic evades at 93.8% without trying, the rules may not reflect actual threat detection. Verify that the rules are representative.

## Next Step

Before executing the improvement plan, clarify the actual goal:
- **Is the goal to raise evasion above the 93.8% baseline?** If so, we need mutations that evade Snort better than no mutation—unlikely without domain knowledge of Snort evasion techniques.
- **Is the goal to show that Snort-direct training improves over the current agent?** Achievable (70% → higher), but will still be worse than the baseline.
- **Is the goal to find an RL policy that evades both XGBoost and Snort simultaneously?** This requires a Pareto frontier search, not a single reward function.

## Files

- Baseline validation: `snort_validation/reports/snort_validation_summary_seeded_blind.json`
- Decision boundaries: `docs/SNORT_DECISION_BOUNDARIES.md` (section 4: "Why the blind agent evades only 30%")
