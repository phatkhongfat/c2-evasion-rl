# Email Draft to Advisor: C2 Evasion Surrogate → Real Snort Issues

---

Dear [Advisor],

We are writing to report significant findings from transitioning our C2 evasion RL project from a **surrogate IDS** (Python replica of ~20 Snort rules) to **real Snort binary** (ET Open C2 ruleset, 21,374 rules). The transition revealed multiple critical gaps between our training environment and ground truth, which fundamentally change the problem landscape.

## Executive Summary

**Surrogate version results** (what we trained on):
- Prepend, pad, reorder, ttl variants: each solves 4–8/16 flows
- PPO agent: 90.6% evasion (comparable to baselines)
- Action space: 14 mechanisms all applicable to all flows

**Real Snort results** (ground truth):
- Only 4 mechanisms work: `split8`, `split16`, `split24` (100%), `http_header_pad` (100%)
- 9 mechanisms fail: `prepend`, `pad`, `reorder`, `ttl`, `noop`, `corrupt`, `overlap`, `length_wrapper` (all 0/8)
- PPO agent: collapses to `split24` only, 8/8 evasion (identical to greedy)
- **Task is saturated:** RL cannot outperform heuristic greedy search

---

## Key Findings: 9 Transition Issues

### 1. **Semantics Bar Tightened**
- **Surrogate**: "preserve semantics" = payload still present after prepend → prepend4 accepted
- **Real Snort**: "preserve semantics" = byte-equality via protocol parser (HTTP path, Neris record chain)
  - Prepend 4/8/12: breaks parsing → **0/16 all variants** (was 4/16 each)
- **Root cause**: Surrogate matched rules independently; real Snort enforces protocol-level semantics

### 2. **Protocol Applicability Not Enforced**
- **Surrogate**: all 14 mechanisms applicable to all flows
- **Real Snort**: 
  - `http_header_pad` only on HTTP flows (8/16)
  - `length_wrapper` only on length-prefixed protocol (0/16 in our corpus)
- **Impact**: Effective action space per flow: 12–13 actions, not 14

### 3. **Batch Size & Query Counting Bug (Fixed)**
- **Surrogate**: 1 query = 1 mechanism-flow pair
- **Real Snort**: Initial harness batched 32 pairs into 1 Snort call but counted as 32 queries
- **Fix applied** (commit 57252e1): batch_size=1 → accuracy restored, speed penalty (0.1 sec → 10.6 sec/query)

### 4. **Protocol Framing Mislabeled**
- **Surrogate**: assumed all flows HTTP (per corpus metadata)
- **Real Snort with `endpoint_model.py`**: detected framing via regex
  - Result: **41 "unparseable" flows are Neris** (bittorrent-style `<tag><len>:<data>` records), not HTTP
  - Corpus actually 50/50 HTTP/Neris, not 80/20 HTTP as assumed
- **Impact on prepend**: fails on Neris (cannot parse around junk bytes in binary protocol)

### 5. **Action Space Collapse**
- **Surrogate**: 4–8 mechanisms work per flow → RL has diversity to exploit
- **Real Snort (HTTP-only eval so far)**:
  - `split24` solves all 8 HTTP flows alone → 8/8 evasion
  - Greedy, PPO, supervised tree: all pick `split24`, all reach 8/8 queries
- **Problem**: No signal for RL to outperform baseline heuristic

### 6. **Test Set Homogeneity**
- **Surrogate**: 16 mixed flows (some "easy" with prepend, some "hard")
- **Real Snort HTTP-only**: 8 flows, all 4 mechanisms work on each
  - Neris subset (8 flows): untested, likely harder (only fragmentation works)
- **Blocker**: Cannot claim RL superiority on single-protocol saturated test set

### 7. **Semantics Integrity Bugs (TDD Found & Fixed)**
- **Surrogate**: didn't rebuild checksums → Snort dropped packets → spurious "evasion"
- **Real Snort fixes**:
  - Commit f7a23e0: `fix_checksums()` recalculates IP.len, TCP.len, checksums after payload rewrite
  - Commit 6620342: rebuild packet stack from `pkt.__class__` to preserve Ethernet header
  - Commit 6620342: fixed junk HTTP headers to not double-terminate (`\r\n\r\n`)
- **TDD found 3 real bugs** in mechanism implementations

### 8. **Evaluation Speed vs Accuracy Tradeoff**
- **Surrogate**: ~0.1 sec/query, 224 queries = 22 sec total (fast, inaccurate)
- **Real Snort** (batch_size=1): ~10.6 sec/query, 112 queries = 20 min total (slow, accurate)
- **Problem**: Cannot run large-scale training loops; must choose between speed and correctness

### 9. **Length Wrapper Dead on Arrival**
- **Surrogate**: `length_wrapper` applicable to all 16 flows
- **Real Snort**: requires protocol = "length2" (2-byte length prefix)
  - Corpus has HTTP + Neris, no "length2" flows
  - `mech_applicable()` returns False for all 16 → **0/16 applicable**
- **Decision needed**: Reverse-engineer Neris grammar (hard), or drop from action space (simplifies, reduces diversity)

---

## Comparison Table

| Aspect | Surrogate | Real Snort | Impact |
|--------|-----------|-----------|--------|
| **Semantics check** | Loose (prepend ok) | Strict (parser-based) | Prepend fails; task harder |
| **Protocol validation** | None (all 14 applicable) | Per-protocol filter | Effective action space ≤ 12 |
| **Batch counting** | 1 query always | Buggy → fixed | Speed & accuracy tradeoff |
| **Framing detection** | Assumed 100% HTTP | Detected 50/50 HTTP/Neris | Prepend works only on HTTP |
| **Neris model** | Ignored | Partial (record chain) | Prepend inapplicable on Neris |
| **Mechanism diversity** | 4–8 work per flow | 4 work (all 100%) | RL cannot distinguish |
| **Test size** | 16 mixed (diverse) | 8 HTTP (homogeneous) | Saturated; needs full 16-flow eval |
| **Eval speed** | 22 sec | 20 min | Cannot scale training loops |
| **Length wrapper** | 16/16 applicable | 0/16 applicable | Wasted action |

---

## Current Blockers & Questions

1. **Full corpus evaluation**: Should we eval on all 16 flows (8 HTTP + 8 Neris)? Will Neris show RL > greedy due to being "harder"?

2. **Semantics bar**: Is byte-equality (current) too strict, or is it correct? Should prepend be valid if the C2 handler can parse around it?

3. **Length wrapper**: Should we:
   - Reverse-engineer Neris grammar to unlock this mechanism?
   - Drop it from action space to avoid dead actions?
   - Leave as-is and document the limitation?

4. **Task saturation**: If split24 solves 100% on any protocol subset, how do we demonstrate RL learns something meaningful? Should we:
   - Move to heterogeneous defender (adaptive per-flow)?
   - Focus on protocol-aware design instead of RL?
   - Expand test set to scale difficulty?

5. **Publication direction**: Are these 4 working mechanisms (split8/16/24, http_header_pad) + endpoint-model design sufficient for a paper, or do we need RL to show empirical improvement?

---

## Recommended Next Steps

1. **Complete full 16-flow eval** (currently HTTP-only) to determine if Neris subset reveals RL advantage
2. **Resolve length_wrapper** — decide on reverse-engineering vs. removal
3. **If task remains saturated**: design heterogeneous defender (adaptive strategy per flow, harder baseline)
4. **Document findings** in paper/report: what works, why others fail, why RL cannot outperform greedy on this problem formulation

---

We have detailed these issues in attached documents:
- `docs/surrogate_to_real_snort_issues.md`: 9-issue breakdown with examples
- `docs/questions_for_advisor.md`: specific technical questions and decision matrix

We believe the real Snort results are more honest and publishable, but the task now requires either:
- A harder problem (heterogeneous defender, larger corpus)
- A different angle (protocol-aware design insights instead of RL performance)

Would you like to discuss the direction in our next meeting?

Best regards,
[Student names]

---

## Attachments
- Commit 188679c: `docs: surrogate vs real snort transition issues and advisor questions`
- Commit 57252e1: `eval: batch_size=1, fix query counting`
- Commit 6620342: `endpoint model: neris binary framing + corpus framing report`
- Commit f7a23e0: `fragment_ops: fix_checksums for payload rewrites`
