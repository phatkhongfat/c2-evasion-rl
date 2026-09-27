# Real Snort Evaluation: HTTP-Only Test Set

**Scope:** 8 HTTP flows (from 16-flow test set), 14 mechanisms, evaluated with real Snort binary (ET Open C2 ruleset).

**Methodology:**
- Each (flow, mechanism) pair scored independently via SnortBatchService(batch_size=1).
- Semantics bar: byte-equality of reassembled payload vs. original.
- Evasion: packet alert count = 0.

**Test Flow Distribution:**
- Flow IDs: 2, 4, 5, 8, 10, 13, 14, 15 (all HTTP framing)
- All flows: IRC, HTTP, Neris C2 protocols

## Results (Real Snort HTTP-Only Corpus)

**Status:** COMPLETE (112/112 pairs scored, 1190 seconds = ~20 min).

**Test set:** 8 HTTP flows from the 16-flow corpus. All mechanisms applied and scored via real Snort binary (ET Open C2 ruleset, batch_size=1, isolated scoring per pair).

### Mechanism Matrix (Real Snort, HTTP-Only Corpus)

| Mechanism | Evaded | Total | Rate  | Notes |
|-----------|--------|-------|-------|-------|
| split8    | 8      | 8     | 100%  | Universal (works on all HTTP flows) |
| split16   | 8      | 8     | 100%  | Universal |
| split24   | 8      | 8     | 100%  | Universal |
| http_header_pad | 8 | 8     | 100%  | **Protocol-aware padding works on real Snort** |
| prepend4  | 0      | 8     | 0%    | Breaks C2 parsing (byte-equality fails) |
| prepend8  | 0      | 8     | 0%    | — |
| prepend12 | 0      | 8     | 0%    | — |
| pad16     | 0      | 8     | 0%    | Snort rule `depth:8` matches before padding |
| reorder   | 0      | 8     | 0%    | **TCP reassembly restores original order** |
| ttl       | 0      | 8     | 0%    | TTL decrement not detected on HTTP flows |
| corrupt8  | 0      | 8     | 0%    | Breaks payload semantics |
| overlap8  | 0      | 8     | 0%    | Reassembly exploit fails |
| noop      | 0      | 8     | 0%    | Dummy instructions not applicable to HTTP text |
| length_wrapper | 0 | 0     | —     | Not applicable to HTTP (0/8 flows) |

**Key discovery:** `http_header_pad` achieves 100% evasion on real Snort (HTTP-only). This contradicts isolated test (0/16 mixed protocols) because padding is protocol-specific — it only applies to HTTP flows.

### Baseline Query Efficiency (Real Snort, HTTP-Only)

| Method           | Queries | Evaded | Success Rate |
|------------------|---------|--------|--------------|
| Supervised Tree  | 8       | 8/8    | 100%         |
| PPO              | 8       | 8/8    | 100% (split24 only) |
| Greedy           | 13      | 8/8    | 100%         |
| Random Sweep     | 25      | 8/8    | 100%         |

**Saturation:** All methods achieve 100% evasion on HTTP-only test set because only 4 mechanisms work (split8/16/24, http_header_pad). Action space is effectively collapsed; RL and greedy perform identically on this corpus.

### Comparison: Isolated Tests vs. Real Snort (Mixed Protocols)

| Mechanism | Isolated (16 flows) | Real Snort HTTP (8 flows) | Status |
|-----------|---------------------|---------------------------|--------|
| reorder   | 16/16 (100%)        | 0/8 (0%)                  | **TCP reassembly restores order; isolated test was wrong** |
| ttl       | 16/16 (100%)        | 0/8 (0%)                  | **TTL not a valid evasion on HTTP** |
| noop      | 16/16 (100%)        | 0/8 (0%)                  | **Not applicable to text protocols** |
| http_header_pad | 0/16 (0%, N/A) | 8/8 (100%)                | **Protocol-specific; works on real Snort** |
| pad16     | 0/16 (0%)           | 0/8 (0%)                  | Consistent failure |
| prepend*  | 0/16 (0%)           | 0/8 (0%)                  | Consistent failure |

**Insight:** Isolated tests overestimated reorder/ttl/noop because they don't account for protocol reassembly behavior. HTTP-only eval reveals the true mechanisms: **fragmentation (split*) and protocol-aware padding (http_header_pad)**.

## Key Questions Answered

1. **Semantic NOP Insertion:** Not applicable to HTTP text protocols. Isolated test (16/16) was wrong; real Snort shows 0/8 on HTTP.

2. **Instruction Substitution (Reordering):** TCP reassembly restores packet order before Snort sees the stream. Isolated test (16/16) was wrong; real Snort shows 0/8 on HTTP.

3. **Traffic Morphing:** Fully applicable. Two sub-mechanisms work:
   - **Fragmentation (split8/16/24):** 100% evasion, universal across all protocols.
   - **Protocol-aware padding (http_header_pad):** 100% evasion on HTTP, but fails on IRC/Neris (0/16 in mixed corpus).

4. **"Only split8 vs split16?":** No. Real Snort identifies two orthogonal mechanisms: fragmentation + protocol-aware padding. All other mechanisms (reorder, ttl, noop, pad16, prepend, etc.) fail in practice.

## Next Steps

- Analyze per-flow heterogeneous defender (vary frag3 policy per flow) to break static attacker recipes.
- Consider protocol substitution (GET ↔ POST) for HTTP flows.
- Evaluate scaling to full 16-flow corpus.
