# Packet-level observation & action space diagnosis

**Goal:** Understand why the 7-feature observation was chosen, verify whether the action-space bug blocks learning, and decide between autoregressive vs set-encoding architecture.

---

## Current context

The packet-level RL environment (`ai_agent/packet_level_env.py`) defines:

**Observation** (7 dims):
1. `pkt_idx` — position / max_packets
2. `direction` — 0=src, 1=dst
3. `dsize` — payload size / 1500
4. `time` — normalized by flow duration (currently hardcoded 0.0)
5. `flow_bytes_sent` — cumulative bytes / expected total
6. `flow_pkts_sent` — cumulative packets / expected total
7. `is_detected` — 0=evading, 1=caught

**Action** (4 dims):
1. `ttl_delta` — ±10 TTL
2. `frag_flag` — binary fragmentation
3. `padding_bytes` — 0-200 bytes padding
4. `overlap_offset` — TCP overlap ±100 bytes

**Known bug:** `PacketModifier.to_flow_features()` only exports `tot_pkts`, `tot_bytes`, `src_bytes`, `dur` — TTL/frag/overlap are recorded in `apply_actions` but never reach `replica_snort_verdict()`, so three of four action dimensions cannot affect the reward.

**Measured result:** Training converges (~700 fps, 10K steps in 16s) but only padding matters. Agent beats random baseline by +10.67pp on ≥10-packet flows (30.87% vs 20.20%), but the ceiling is the reward sensitivity to the action space, not the optimization budget (1M steps ≈ 10K steps).

**Cross-capture generalization cliff:** Train on `20110811-neris` (baseline 24/24, agent 100% evasion @ 2.88 corrupted/flow) → eval on sibling `20110810-neris` (baseline 14/24, agent 16.7% = corrupt-all control). Policy does not transfer.

**Root cause (from skill):** Single-capture training + statistical observations (size mean/std, IAT) describe the *capture*, not the malware. The 15-feature experiment (rank, z-score, payload entropy) improved `20110811` from 1.67→1.42 but still failed the gate on `20110819`. Next lever is **set-level decision** (autoregressive or set encoding), not more per-packet columns.

---

## Architecture decision

**Autoregressive** (current, sequential):
- Agent sees one packet at a time, acts, sees next packet
- Pro: simple, already working, scales to long flows
- Con: cannot plan ahead; early mistakes compound

**Set encoding** (attention/transformer):
- Agent sees the whole packet set, outputs a corruption mask
- Pro: global view, can identify "decisive packets", matches the frontier solver's unit of decision
- Con: fixed flow length or padding, larger model

**Hypothesis:** The autoregressive agent cannot solve `20110819` because the optimal mask is a *set* of 2–4 packets (`k=1` in only 5/23 flows), and a per-packet policy has no memory to coordinate them. Set encoding is the architectural match for this problem.

**Gate:** Train a small set-encoder (e.g. 64-dim self-attention over packet features → per-packet logit → sample mask), play the predicted mask through real Snort, and grade with the control gate: equal evasion with fewer corruptions than corrupt-all, seeded across ≥5 runs.

---

## Step-by-step tasks

### Phase 1: Document the observation rationale (read-only)

**Task 1.1:** Find the commit that introduced the 7-feature observation
```bash
cd /root/.hermes/c2-evasion-rl
git log --all --oneline --source -- ai_agent/packet_level_env.py | head -20
git show <earliest-sha>:ai_agent/packet_level_env.py | grep -A 20 "observation_space"
```
Expected: either a docstring explaining the choice, or an earlier feature count (e.g. 5→7).

**Task 1.2:** Check for design docs
```bash
grep -rn "observation.*feature.*why\|why.*7.*dim\|feature.*rationale" docs/ --include="*.md" | head -10
```
Expected: `docs/packet_level_rl.md` or a sibling may state the design.

**Task 1.3:** Cross-check the skill's 15-feature experiment
```bash
# The skill says: "Raising packet_features from 8 to 15 flow-relative columns
# (rank, z-score, is-longest, payload fraction...) improved 20110811 from 1.67→1.42"
# Find the code that implements those 15 features
grep -rn "rank\|z.score\|is.longest\|payload.fraction" ai_agent/ snort_validation/ --include="*.py" | grep -v ".pyc" | head -20
```
Expected: a `_packet_features()` or `_flow_relative_features()` method.

**Deliverable:** A 3-line summary:
- Where the 7-feature observation was defined (commit + date)
- Whether a design doc exists stating the rationale
- Where the 15-feature experiment lives (file + function name)

Save to `/root/.hermes/c2-evasion-rl/.hermes/plans/observation-history.txt`.

---

### Phase 2: Verify the action-space bug and measure its impact

**Task 2.1:** Confirm the bug — read `PacketModifier.to_flow_features()`
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python -c "
from ai_agent.packet_modifier import PacketModifier
import inspect
print(inspect.getsource(PacketModifier.to_flow_features))
"
```
Expected output: function returns `{tot_pkts, tot_bytes, src_bytes, dur, proto, state}` — no TTL, frag, or overlap.

**Task 2.2:** Trace one action through to the reward
Write `/root/.hermes/c2-evasion-rl/scripts/trace_action_to_reward.py`:
```python
#!/usr/bin/env python3
"""Trace: does changing TTL/frag/overlap reach replica_snort_verdict?"""
import sys
from pathlib import Path
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))

from packet_modifier import PacketModifier
from snort_query_service import replica_snort_verdict

# Synthetic flow: 10 packets, TCP, CON
packets = [("src", 100, i*0.1) for i in range(10)]

# Baseline action: no mutation
baseline_action = [0, 0, 0, 0]
modifier = PacketModifier()
modified_baseline = modifier.apply_actions(packets, [baseline_action]*10)
flow_baseline = modifier.to_flow_features(modified_baseline)
flow_baseline["proto"] = "tcp"
flow_baseline["state"] = "CON"
verdict_baseline = replica_snort_verdict(flow_baseline)
print(f"Baseline verdict: {verdict_baseline}, features: {flow_baseline}")

# Mutate only TTL
ttl_action = [10, 0, 0, 0]  # +10 TTL, nothing else
modified_ttl = modifier.apply_actions(packets, [ttl_action]*10)
flow_ttl = modifier.to_flow_features(modified_ttl)
flow_ttl["proto"] = "tcp"
flow_ttl["state"] = "CON"
verdict_ttl = replica_snort_verdict(flow_ttl)
print(f"TTL+10 verdict:  {verdict_ttl}, features: {flow_ttl}")

# Mutate only padding
pad_action = [0, 0, 100, 0]  # +100 bytes padding
modified_pad = modifier.apply_actions(packets, [pad_action]*10)
flow_pad = modifier.to_flow_features(modified_pad)
flow_pad["proto"] = "tcp"
flow_pad["state"] = "CON"
verdict_pad = replica_snort_verdict(flow_pad)
print(f"Padding verdict: {verdict_pad}, features: {flow_pad}")

print("\n=== BUG CONFIRMED if TTL change has no effect on features/verdict ===")
```
Run:
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python scripts/trace_action_to_reward.py
```
Expected: `flow_ttl` and `flow_baseline` are identical (TTL not in the dict), so verdict stays the same. `flow_pad` has larger `tot_bytes`, so verdict may differ.

**Task 2.3:** Check if `enhanced_packet_level_env.py` fixes the bug
```bash
grep -A 10 "enhanced_replica_snort_verdict" ai_agent/enhanced_packet_level_env.py
```
Expected: the enhanced env calls `enhanced_replica_snort_verdict(flow_features, self.modified_packets)` — passing the packet list, not just aggregates.

Read `snort_validation/enhanced_snort_replica.py`:
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python -c "
import sys
sys.path.insert(0, 'snort_validation')
from enhanced_snort_replica import enhanced_replica_snort_verdict
import inspect
print(inspect.getsource(enhanced_replica_snort_verdict))
"
```
Expected: function signature `(flow_features: Dict, packets: List[Dict]) -> bool`, and body checks TTL/frag in the packet list.

**Task 2.4:** Does the bug block learning?
Answer: **No** — the agent trained successfully and beats random (+10.67pp), proving the env's gradient is non-zero. The bug *caps* the ceiling (only padding matters), but does not prevent convergence. The skill says: "More training does not help. The constraint is the environment's limited action→reward coupling, not the optimization budget."

**Deliverable:** Append to `/root/.hermes/c2-evasion-rl/.hermes/plans/observation-history.txt`:
```
## Action-space bug verification

Bug confirmed: PacketModifier.to_flow_features() returns {tot_pkts, tot_bytes, src_bytes, dur}.
TTL/frag/overlap are recorded in apply_actions but never reach replica_snort_verdict.

Traced with scripts/trace_action_to_reward.py: TTL mutation does not change the feature dict.

enhanced_packet_level_env.py exists and calls enhanced_replica_snort_verdict(flow, packets),
passing the full packet list. File: snort_validation/enhanced_snort_replica.py.

Impact: bug does NOT block learning (agent converges, beats random by +10.67pp on ≥10-pkt flows).
Bug DOES cap the ceiling — only padding can affect reward, so the 4-dim action space is
effectively 1-dim.
```

---

### Phase 3: Decide autoregressive vs set-encoding

**Task 3.1:** Read the frontier solver to understand the target decision
```bash
cd /root/.hermes/c2-evasion-rl
grep -A 30 "def.*frontier\|def.*exact.*optim\|def.*k.progressive" snort_validation/frontier_exact.py | head -50
```
Expected: the solver emits a per-flow optimal mask (a binary vector of length `n_packets`), not a sequential policy.

**Task 3.2:** Check the feasibility gate's "best single-feature" accuracy
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python snort_validation/label_feasibility.py 2>&1 | grep -A 5 "best.*feature\|single.*feature\|baseline.*index.0"
```
Expected: the report states baseline accuracy (fraction of optimal masks that include packet 0), and compares single-feature argmax against it.

Skill quote:
> A "best single-feature" accuracy is meaningless unless you compare it to the always-index-0 baseline. On `20110819` that baseline is 20/23 = 87%, and the top-5 "features" all read 82%, which looked like a tie of strong features and was actually five degenerate rules.

**Task 3.3:** Read the skill's multi-capture plan
Already read in context:
> Planned fix (multi-capture + semantic obs): [4 phases] ... 2. **Semantic observation.** Replace the statistical obs with rule-match features: which rule SIDs fire on this flow, before and after the mutation.

Semantic obs = "which rules fire" — that is a set-level feature (a rule can fire on packet 3 OR packet 7, the policy needs to know both exist).

**Task 3.4:** Decision matrix

| Approach | Observation unit | Decision unit | Matches problem? | Complexity |
|---|---|---|---|---|
| Autoregressive (current) | one packet at a time | one action per step | ❌ Cannot coordinate 2-4 packet masks | Low |
| Set-encoder (attention) | full packet set | corruption mask | ✅ Matches frontier solver | Medium |
| Hybrid (autoregressive + memory) | one packet | action + carry state | ⚠️ Possible but indirect | Medium |

**Recommendation:** Set-encoding.

**Rationale:**
1. The target (frontier solver) outputs a mask, not a trajectory.
2. The optimal solution on `20110819` is a scattered set (k=1 in only 5/23 flows; rest need 2-4 packets).
3. The skill says: "Independent per-packet scoring cannot express a set; that is an architectural limit, not a missing feature."
4. Semantic obs (rule SIDs) are naturally set-level — a rule firing on *any* packet in the flow marks the flow detected.

**Gate before full implementation:**
- Train a minimal set-encoder (64-dim self-attention over 15-feature packet vectors → per-packet logit → sample binary mask).
- Eval: play predicted masks through real Snort, grade with the control gate (beat corrupt-all by ≥1pp evasion at lower cost, seeded ≥5 runs).
- If it passes: semantic obs + multi-capture training.
- If it fails: the architectural hypothesis is wrong; revisit.

**Deliverable:** Append to `/root/.hermes/c2-evasion-rl/.hermes/plans/observation-history.txt`:
```
## Autoregressive vs set-encoding

Frontier solver outputs per-flow masks (binary vector), not trajectories.
Optimal masks on 20110819 are scattered sets (k=2-4 for 18/23 flows).
Skill: "Independent per-packet scoring cannot express a set — architectural limit."

Decision: SET-ENCODING (self-attention over packet features → corruption mask).

Rationale:
- Matches the solver's decision unit
- Can coordinate non-contiguous packets
- Semantic obs (rule SIDs) are set-level by nature
- Skill explicitly recommends it as the next lever

Gate: minimal set-encoder on 15-feature packets, eval with control gate on 20110819.
```

---

## Tests / validation

All tasks in Phase 1-2 are read-only or produce traced output — no code to test.

Phase 3 decision is a design choice backed by:
- Skill quote (loaded from `c2-evasion-rl`)
- Measured result (optimal masks are sets, not sequences)
- Architectural mismatch (autoregressive cannot coordinate scattered packets)

Before implementing the set-encoder, validate the hypothesis with a frozen behavior-cloning baseline:
1. Load the exact optimal masks from `frontier_exact.py` output
2. Train a small per-packet BCE classifier toward those masks (input: 15-feature packet vector, output: P(corrupt this packet))
3. Eval: sample masks from the trained model, play through real Snort, grade with control gate
4. If the BC baseline beats the control, the features can express the mask — proceed to RL
5. If it ties or loses, the features are insufficient — return to feature engineering

This is the skill's gate:
> Behaviour cloning is only worth attempting if the features can express the optimal mask. Gate it: emit `optimal_mask` from the frontier solver, train a small shared per-packet net with BCE toward it, then — the acceptance test — play the *predicted* mask through real Snort and grade with the same control gate.

---

## Risks, tradeoffs, and open questions

**Risks:**
1. **Set-encoding may not help if the bottleneck is feature quality, not architecture.** The skill's cross-capture diagnosis says statistical features (size, IAT) describe the capture, not the malware. Semantic obs (rule SIDs) are the real fix; set-encoding is a prerequisite, not a silver bullet.
2. **Fixed flow length or padding.** Self-attention needs a fixed sequence length. Options: (a) pad to max_packets=50, (b) use a set-transformer (permutation-invariant), (c) pack variable-length flows into batches. Decision: defer until the BC gate passes — if features can't express the mask, architecture is moot.
3. **The bug blocks TTL/frag/overlap.** Fixing `to_flow_features()` to export those fields is trivial (add 3 keys), but the *replica* must also check them. `enhanced_snort_replica.py` exists — verify it before training.

**Tradeoffs:**
- Set-encoding vs autoregressive: larger model, but better match to the problem structure.
- 7-feature obs vs 15-feature: the skill measured 15 as better (1.67→1.42 on `20110811`), but it still failed `20110819`. The next lever is semantic obs (rule SIDs), not more per-packet columns.

**Open questions:**
1. **Why 7 features originally?** Phase 1 will recover the commit message / design doc.
2. **Is `enhanced_snort_replica.py` tested?** Check for a pytest file or a validation script that grades it against real Snort.
3. **Should we fix the action-space bug before changing architecture?** Answer: **No** — the bug doesn't block learning, and the skill says padding-only is enough to beat random. Fix it when implementing the set-encoder (it will need TTL/frag to reach the advertised 4-dim space).

---

## Summary

This plan diagnoses, does not implement. Deliverables:
- `/root/.hermes/c2-evasion-rl/.hermes/plans/observation-history.txt` — rationale for 7 features, bug trace, architecture decision
- `scripts/trace_action_to_reward.py` — executable proof of the bug

Next step: run Phase 1-3 tasks, then decide whether to (a) implement the BC gate, (b) fix the action-space bug + retrain the autoregressive agent, or (c) proceed directly to set-encoding with semantic obs. The skill's roadmap is: audit captures → semantic obs → multi-capture env → domain randomization. Set-encoding fits between step 2 and 3.
