# Questions for Advisor: C2 Evasion RL Task Saturation

## Context
Real Snort evaluation (ET Open C2 ruleset, 21,374 rules) on 8 HTTP flows reveals:
- **4 mechanisms work** (split8/16/24, http_header_pad) — each solves 8/8 flows (100%)
- **9 mechanisms fail** (prepend, pad, reorder, ttl, noop, corrupt, overlap, length_wrapper) — each solves 0/8
- **RL vs baselines**: all methods (PPO, greedy, supervised tree, random) hit 100% evasion; PPO collapses to `split24` only
- **Strict semantics bar**: endpoint-model parser (HTTP path, Neris record chain) rejects byte-prepend variants that earlier surrogate version accepted

---

## Core Questions

### 1. **Task Design & Feasibility**
- Is 100% evasion on 8 flows the *intended* outcome, or does it reveal the test set is too weak?
- Should we scale to more flows (16 → 64?), or does that defeat the evaluation goal (show RL beats baselines)?
- The 9 failing mechanisms (prepend, pad, noop, reorder, ttl): are these *expected* to fail on real IDS, or did we model them wrong?

### 2. **Semantic Correctness vs. Evasion Tradeoff**
- Is byte-level prepending (prepend4/8/12) a valid evasion if the C2 protocol handler knows to skip it?
  - Current: strict — endpoint-model rejects it (0/16).
  - Alternative: loose — allow if C2 can parse around it.
- Which is correct for the paper?

### 3. **Protocol Coverage**
- Corpus has 2 protocols: HTTP (text, well-modeled) + Neris (binary record chain, partially modeled).
- **HTTP is saturated** (4 mechanisms work, each 100%; RL cannot distinguish them).
- **Neris is unexplored** — we don't have a full grammar, so `length_wrapper` is inapplicable (0/8).
  - Should we reverse-engineer Neris to make `length_wrapper` work, or drop it?
  - Or focus on fragmentation alone (works on both)?

### 4. **RL Evaluation Metrics**
- When baseline (single mechanism) already solves 100%, how do we show RL adds value?
  - Current PPO: picks `split24`, ties with greedy (both 8/8, 8 queries).
  - Does "fewer queries" count as learning, or is that random luck on small test set?
- Should we measure *robustness* (e.g., against adaptive defender, per-flow heterogeneous strategies) instead?

### 5. **Academic Framing**
- You mentioned mapping to 3 papers (NOP insertion, instruction subst, traffic morphing).
- **Real Snort results**: only traffic morphing (fragmentation + protocol-aware padding) works.
- Does this match your prior research, or should we question whether the other mechanisms are fundamentally incompatible with text-protocol IDS?

### 6. **Next Phase: Heterogeneous Defender**
- Plan mentions "per-flow adaptive defender" to make progress.
- Should that be a more sophisticated *attacker* (learns flow fingerprints, mutates action patterns)?
- Or a smarter *defender* (per-flow per-mechanism rules instead of static ET Open)?
- Both? Neither?

### 7. **Publication Strategy**
- Current state: honest results (4 mechanisms work, RL ≈ baselines on 8 flows).
- Acceptable for a paper, or do we need either:
  - (A) Larger, harder test set?
  - (B) Novel insight from RL that baselines miss?
  - (C) Focus on protocol-aware design (Neris grammar, adaptive padding) rather than RL?

---

## Immediate Blockers (need decision to proceed)

1. **Neris grammar**: Reverse-engineer to unlock `length_wrapper`, or treat as byte-opaque (fall back to fragmentation only)?
2. **Prepend validity**: Strict endpoint-model (current), or loose (allow if C2 can skip it)?
3. **Test set size**: Evaluate on 8 HTTP flows (current, saturated), or expand to 64 mixed (harder, slower)?
4. **Phase after mechanisms A/B**: Heterogeneous defender, or pivot to something else?

---

## Supporting Evidence
- Commit `0b5680f`: real Snort HTTP-only eval, mechanism discrimination matrix
- Commit `6620342`: endpoint_model with protocol detection (HTTP path, Neris record chain)
- `/root/.hermes/c2-evasion-rl/snort_validation/reports/hidden_defender_real_snort_test.json`: full results
