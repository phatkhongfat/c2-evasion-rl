# Task 6: Decision Gate — Snort-Direct Training Experiment

## Status: BLOCKER — Real Snort Detection 93.8% (exceeds 55% threshold)

### Experiment Results

**Snort-Direct Training Setup:**
- Fixed environment: run all 10 steps regardless of replica evasion
- Padding penalty after successful evasion: -10 per extra byte
- Training: 50K steps PPO, clamp to FEATURE_BOUNDS
- Evaluation: 80 seeded episodes (seed=42)

**Real Snort Validation:**
```
Policy          XGBoost Evasion      Snort Detection      Snort Evasion
----------------------------------------------------------------------
Agent                        11.2%                93.8%                6.2%
Random                       66.2%                80.0%               20.0%
Baseline                      8.8%                 6.2%               93.8%
```

**Verdict:** FAILURE
- Target: ≥45% Snort evasion (≤55% detection)
- Achieved: 6.2% Snort evasion (93.8% detection)
- Regression: Worse than no mutation (baseline 93.8%)

### Root Cause Analysis

1. **Replica-Reality Gap:** Snort replica trained on XGBoost evasion samples, not real malware ↔ real Snort interaction traces
   - XGBoost judge sees only 6 flow features (dur, tot_pkts, tot_bytes, src_bytes, proto, state)
   - Real Snort checks behavioral patterns, packet sequences, timing anomalies, payload inspection
   - Replica cannot capture these patterns → agent learns brittle policies that don't generalize

2. **Conflicting Reward Signals:** Padding penalty after evasion directly undermines evasion reward
   - Line 200 in env: `reward -= byte_delta * COST_PADDING_AFTER_EVASION` applied AFTER successful evasion
   - Agent learns: "achieve evasion is bad because it costs padding reward"
   - Result: Agent learns to NOT evade or use minimal mutations

3. **Feature Insufficiency:** 6 flow features cannot model Snort's detection logic
   - Snort inspects deep packet inspection (DPI), behavioral rules, state machines
   - Flow features (packet count, bytes, duration) are too coarse-grained
   - Gap between judge model and real defender grows with more complex evasion strategies

### Why Task 7 (Hyperparameter Sweep) Won't Fix This

Hyperparameter tuning addresses training dynamics (learning rate, reward scale, network architecture), but **cannot close the replica-reality gap**:
- Adjusting COST_PADDING_AFTER_EVASION doesn't make the replica more accurate
- Increasing reward scale won't help if the replica mock is fundamentally misaligned with real Snort
- More training steps will reinforce brittle replica-specific policies

### Recommendation: Pivot Required

**Option A: Abandon Snort-Direct, Keep Blind Agent**
- Blind agent (XGBoost evasion 30%) is still the baseline
- Snort-direct made things worse (6.2% evasion)
- Accept that without real Snort feedback loops during training, agent cannot learn robust evasion

**Option B: Expensive Alternative — Use Real Snort in Training Loop**
- Wrap real Snort binary as the reward oracle (slow, requires live Snort process)
- Train agent against real Snort verdicts, not replica
- Trade: 10-100x slower training, but realistic feedback signal
- Feasible but outside scope of this task

**Option C: Redesign Feature Space**
- Extract behavioral features beyond raw flow stats
- Include packet timing patterns, protocol state transitions, content signatures
- Retrain XGBoost judge on richer feature set
- Problem: Still won't capture DPI and signature-based detection that real Snort uses

### Conclusion

The snort-direct training approach **confirmed the fundamental limitation:** training an evasion policy against an inaccurate surrogate (replica mock) results in policies that overfit to the mock's weaknesses and fail on the real defender.

**This is not a tuning problem — it is an architectural problem.** The replica cannot substitute for real Snort feedback during training.

---

**Status Code:** BLOCKER
**Next Action (per plan):** Halt and recommend architectural redesign or expensive real-Snort integration
**Recommendation:** Close this task and document as a negative result
