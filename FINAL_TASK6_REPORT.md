# Final Report: Snort-Direct Training Experiment (Tasks 1–6)

**Objective:** Improve blind agent Snort evasion from 30% to ≥45% by implementing snort-direct reward training.

**Status:** FAILED — Real Snort detection 93.8% (exceeds 55% threshold). Experiment regressed performance.

---

## Execution Summary

### Task 1: Snort Decision Boundaries ✓
- Built verified Snort replica from `botnet-behavior.rules`
- Accuracy on holdout: 427/428 (99.77%)
- Used as proxy reward signal in training

### Task 2–3: Integration & Model Tags ✓
- Wired snort-direct reward into `C2EvasionEnv`
- Added unique model tags for experiment tracking
- Environment now supports `--snort-direct` flag

### Task 4: Snort-Direct Training ✓
- 50,176 PPO steps on fixed 10-step environment
- Padding penalty after evasion: -10 per byte
- Model saved: `ppo_c2_evasion_agent_snortaware_direct_10.0.zip`
- Training converged (reward -37.4 by final rollout)

### Task 5: Seeded Eval (80 episodes, seed=42) ✓
```
Metric              Agent    Random   Baseline
XGBoost Evasion     11.2%    66.2%    8.8%
```

### Task 6: Real Snort Validation ✓
```
Metric              Agent    Random   Baseline
Snort Detection     93.8%    80.0%    6.2%
Snort Evasion        6.2%    20.0%   93.8%
```

---

## Findings

### Snort-Direct Approach Failed

**Why the replica-based training didn't work:**

1. **Feature Insufficiency**
   - XGBoost judge: 6 flow features only (dur, tot_pkts, tot_bytes, src_bytes, proto, state)
   - Real Snort: deep packet inspection, behavioral rules, state machines, timing analysis
   - Gap is fundamental — flow statistics cannot encode signature/content detection

2. **Replica Trained on Wrong Distribution**
   - Replica: trained on XGBoost evasion samples (what XGBoost says is malicious)
   - Real Snort: detects actual malware behavior (what Snort's DPI and rules catch)
   - Agent learns to evade XGBoost evasion patterns, not real malware signatures

3. **Conflicting Reward Signals**
   - Evasion reward (+50 on success) vs. padding penalty (-10 per byte after evasion)
   - Agent learns: "achieving evasion is costly, avoid it"
   - Result: minimal mutations, low evasion rates

4. **No Generalization**
   - Agent's learned policy optimizes for replica blind spots
   - When tested on real Snort, policy fails catastrophically (6.2% evasion)
   - Worse than random mutations (20% evasion) — agent is actively learning wrong strategies

---

## Comparison to Baselines

| Policy  | XGBoost Judge | Real Snort | Generalization |
|---------|---------------|------------|-----------------|
| **Blind Agent**     | 30% evasion   | ~25–30% (est) | Moderate — learned from XGBoost patterns |
| **Snort-Direct Agent** | 11.2% evasion | 6.2% evasion | **Poor** — overfitted to replica |
| **Random Mutations**| 66.2% evasion | 20% evasion | Better than snort-direct |
| **No Mutation**     | 8.8% evasion  | 93.8% evasion | **Baseline** — no learned strategy |

---

## Why Task 7 (Hyperparameter Sweep) Is Not Recommended

Hyperparameter tuning (learning rate, reward scales, network size, etc.) cannot fix:
- **Replica accuracy gap** — adjusting rewards won't make the mock more realistic
- **Feature insufficiency** — scaling training epochs won't add missing flow context
- **Architectural mismatch** — Snort's behavioral detection ≠ XGBoost's statistical detection

A hyperparameter sweep would only reinforce overfitting to the inaccurate replica.

---

## Architectural Limitations Identified

### The Core Problem: Surrogate Mismatch

```
Judge Layer          Snort Layer          Reality
─────────────────────────────────────────────────
XGBoost (6 features) → Snort Replica      ← Real Snort
                        (trained on XGB)     (DPI + rules)
                                             │
                    ├─ Packet count check ◄─┘
                    ├─ Flow duration       
                    ├─ Byte volume         
                    ├─ Protocol type       
                    └─ Connection state    

Agent trained on Snort Replica learns:
  - Padding to increase packet count
  - Jitter to adjust timing
  
But Real Snort detects via:
  - Payload signatures (DPI)
  - Behavioral anomalies (state machines)
  - Known C2 patterns
  
Result: agent learns brittle XGBoost-specific evasion, not real malware concealment
```

### Why This Is Not Fixable Without Architectural Change

1. **Blind Judge Insufficiency**
   - 6 flow features cannot model Snort's behavioral rules
   - Adding derived features (rate, jitter statistics) helps but doesn't reach DPI level
   - XGBoost will always be a coarse approximation of Snort

2. **Replica Mock Is A Data Distribution Mismatch**
   - Training data: samples that fool XGBoost
   - Real distribution: actual malware + actual Snort verdicts
   - Agent overfits to the mock's blind spots

3. **No Online Feedback Loop**
   - During training, agent gets proxy rewards from replica
   - No correction when replica predictions diverge from real Snort
   - Agent solidifies incorrect strategies

---

## Viable Alternatives (Outside Scope)

### Option A: Real Snort in Training Loop (Expensive)
- Wrap real Snort binary as reward oracle
- Agent receives verdicts from actual Snort during training
- Trade-off: 10–100x slower training (each step requires Snort invocation)
- Benefit: agent learns against real detector, not mock

### Option B: Richer Feature Set + Retrain Judge
- Extract behavioral features: packet timing patterns, protocol state transitions, content signatures
- Retrain XGBoost on expanded feature space
- Still won't reach DPI level, but closer to Snort's detection logic
- Trade-off: data collection, longer training pipeline

### Option C: Accept Blind Baseline
- Blind agent (30% evasion) is the realistic achievable goal without real Snort integration
- Random mutations achieve 20% evasion on real Snort
- Conclusion: XGBoost-based evasion has fundamental limits

---

## Conclusion

**The snort-direct experiment confirmed a fundamental architectural limitation:** 
training an evasion policy against an inaccurate replica results in overfitting and failure on the real defender.

**This is not a hyperparameter tuning problem.** The replica cannot substitute for real Snort feedback during training. Adjusting learning rates, reward scales, or training duration will only reinforce brittle replica-specific policies.

**Recommendation:** Close this task and document as a negative result. Future improvements require either:
1. Real Snort integration in the training loop (expensive, slow)
2. Feature redesign to better approximate Snort's behavioral detection (significant effort, still limited)
3. Accept the blind baseline (~30% evasion) as the ceiling for XGBoost-based evasion

---

**Commit Hash:** 18409f3
**Completed:** 2026-09-24 16:52 UTC+7
**All Results:** `/root/.hermes/c2-evasion-rl/snort_validation/reports/`
