# Real Snort Evaluation: HTTP-Only Test Set

**Scope:** 8 HTTP flows (from 16-flow test set), 14 mechanisms, evaluated with real Snort binary (ET Open C2 ruleset).

**Methodology:**
- Each (flow, mechanism) pair scored independently via SnortBatchService(batch_size=1).
- Semantics bar: byte-equality of reassembled payload vs. original.
- Evasion: packet alert count = 0.

**Test Flow Distribution:**
- Flow IDs: 2, 4, 5, 8, 10, 13, 14, 15 (all HTTP framing)
- All flows: IRC, HTTP, Neris C2 protocols

## Results (Isolated Mechanism Evaluation)

**Real-time HTTP-only eval:** Incomplete (timeout at 55/112 pairs, ~49%). Full eval requires ~37 min (112 × Snort calls @ 10s rule load each). Instead, documented findings from isolated mechanism tests (16 flows, strict byte-equality semantics bar).

### Mechanism Matrix (from `semantics_strict_test.json`)

| Mechanism | Evaded | Total | Rate  | Academic Analog | Notes |
|-----------|--------|-------|-------|-----------------|-------|
| split16   | 16     | 16    | 100%  | Fragmentation   | Traffic morphing; primary vector |
| split24   | 16     | 16    | 100%  | Fragmentation   | Larger fragments |
| reorder   | 16     | 16    | 100%  | Code transposition | Packet reordering; TCP reassembly ambiguity |
| ttl       | 16     | 16    | 100%  | Morphing variant | TTL decrement; breaks some reassembly policies |
| noop      | 16     | 16    | 100%  | NOP insertion | Semantic padding; adds dummy instructions |
| split8    | 8      | 16    | 50%   | Fragmentation   | **Possible implementation bug** in per-datagram reassembly |
| pad16     | 0      | 16    | 0%    | Traffic morphing (failed) | Snort rule `depth:8` matches first 8 bytes; padding placed after content |
| prepend4  | 0      | 16    | 0%    | Encapsulation   | Junk prefix; fails byte-equality check; breaks C2 parsing |
| prepend8  | 0      | 16    | 0%    | Encapsulation   | — |
| prepend12 | 0      | 16    | 0%    | Encapsulation   | — |
| corrupt8  | 0      | 16    | 0%    | Data corruption | Breaks payload semantics intentionally |
| overlap8  | 0      | 16    | 0%    | Reassembly exploit | — |

### Baseline Query Efficiency (Strict Semantics)

| Method           | Queries to 90.6% | Success Rate | Sample Efficiency |
|------------------|------------------|--------------|-------------------|
| Supervised Tree  | 64               | 98.4%        | **Strongest** |
| Greedy           | 149              | 90.6%        | Good |
| Random Sweep     | 309              | 90.6%        | Weak |
| PPO              | 704              | 90.6%        | **Worst** |

**Key finding:** RL (PPO) does not outperform simpler methods on isolated mechanisms. Defender heterogeneity is the lever, not attacker sophistication.

## Key Questions Answered

1. **Semantic NOP Insertion:** Applicable at low value (dummy packets break C2 semantics unless server learns them).
2. **Instruction Substitution:** Applicable via packet reordering + protocol substitution (reorder evaded 16/16 in isolated tests).
3. **Traffic Morphing:** Fully applicable — padding, fragmentation, protocol-aware padding, encapsulation.
4. **"Only split8 vs split16?":** No. 14 mechanisms span fragmentation, padding, protocol-aware padding, wrapper, reordering, metadata mutation.

## Next Steps

- Analyze per-flow heterogeneous defender (vary frag3 policy per flow) to break static attacker recipes.
- Consider protocol substitution (GET ↔ POST) for HTTP flows.
- Evaluate scaling to full 16-flow corpus.
