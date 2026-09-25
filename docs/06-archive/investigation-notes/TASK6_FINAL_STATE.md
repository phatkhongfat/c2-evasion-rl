# Task 6: Final State — Snort-Direct Experiment Outcome

## Execution Path

**Our evaluation sequence (this session):**
1. Task 4: Trained `ppo_c2_evasion_agent_snortaware_direct_10.0.zip` with:
   - `--snort-direct` flag enabled (snort=True)
   - Fixed 10-step environment (no early termination on replica evasion)
   - Padding penalty after evasion: -10 per byte
   - 50,176 PPO steps

2. Task 5: Seeded eval on 80 episodes (seed=42) against replica
   - XGBoost evasion: 11.2%

3. Task 6: Real Snort validation on same model
   - **Real Snort detection: 93.8%**
   - **Real Snort evasion: 6.2%**
   - **Result: BLOCKER** (exceeds 55% detection threshold)

## Background Note

A sibling subagent also ran training (`ppo_c2_evasion_agent_snortaware_direct.zip`, 20:48 UTC+7) with `snort=False` (non-snort-direct). This is **separate** from our main evaluation path and was not tested against real Snort. Our decision gate is based on the `_10.0` model only.

## Decision Gate Result

| Criterion | Value | Status |
|-----------|-------|--------|
| Real Snort Detection | 93.8% | **EXCEEDS** 55% threshold |
| Real Snort Evasion | 6.2% | **BELOW** 45% target |
| Target | ≥45% evasion | ❌ NOT MET |

**Decision: BLOCKER**

The snort-direct training approach failed to improve evasion. The replica-based training resulted in worse performance than the baseline.

## Recommendation

Per plan: halt at Task 6 gate and report findings. Do not proceed to Task 7 (hyperparameter sweep) — the fundamental issue is architectural (replica-reality gap), not hyperparameter tuning.

---

**Model evaluated:** `ppo_c2_evasion_agent_snortaware_direct_10.0.zip`
**Commit:** 0ee1d57 (final report committed)
**Decision:** BLOCKER — close task, document as negative result
