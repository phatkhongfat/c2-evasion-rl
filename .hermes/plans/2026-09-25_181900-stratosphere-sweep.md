# Plan: Cross-Capture Validation, Corrupt-Cost Sweep, and Flow Scale-Up

**Goal**: Validate agent evasion generalization across Stratosphere IPS captures, trace the evasion-vs-payload-damage frontier via corrupt-cost sweep, and scale training from 24 to 200 flows.

## Current Context / Assumptions

- **Codebase**: c2-evasion-rl with resident Snort service (fixed alert-read window, now correct).
- **Dataset**: Currently uses CTU-13 (`botnet-capture-20110819-bot`). Must add/switch to Stratosphere IPS Datasets.
- **Bandit**: `ai_agent/snort_bandit.py` trains PPO policy via REINFORCE with real Snort verdicts (batch=96, corrupt-cost=0.6 fixed).
- **Ponytail**: Installed globally; use for code audit + simplification without breaking functionality.
- **Output format**: JSON numbers/tables only (no prose).

## Architecture / Proposed Approach

1. **Stratosphere dataset integration**: Fetch available Stratosphere captures, parse metadata, integrate into the existing flow loader (parallel to CTU-13).
2. **Corrupt-cost sweep**: Parameterize bandit to run with multiple `--corrupt-cost` values (0.2, 0.4, 0.6, 0.8, 1.0); collect deterministic evasion % for each.
3. **Flow scale-up**: Modify bandit to accept `--flows N` and train with 24, 48, 96, 200 flows; measure learning curves.
4. **Code simplification** (Ponytail): Audit `snort_bandit.py` for redundancy, reduce LOC without changing logic, verify tests still pass.
5. **Aggregation**: Final report: table of (capture, corrupt_cost, n_flows) → (argmax_evasion%, mean_corruption).

## Step-by-Step Tasks

### Phase 0: Setup Stratosphere Dataset

**Task 0.1: Fetch Stratosphere metadata**
- List available Stratosphere IPS captures (name, packets, flows, malware family).
- Save to `data/stratosphere_captures.json` with schema: `{name, url, packets, flows, family}`.
- Command:
  ```bash
  # Manually list from https://www.stratosphereips.org/datasets
  # Expected: ~12-15 captures (Botnet, Ransomware, DNS-Tunneling, etc.)
  ```
- Verification: File exists, contains ≥10 captures with all fields.

**Task 0.2: Create Stratosphere flow loader**
- File: `ai_agent/stratosphere_loader.py`
- Function: `load_stratosphere_capture(capture_name: str) -> Dict[str, List]` 
  - Downloads PCAP from Stratosphere URL (or reads from local `data/stratosphere/`).
  - Extracts flows using existing flow extraction logic.
  - Returns dict keyed by flow 5-tuple, value = packet list.
- Reuse existing `pool_loader.py` patterns (minimize new code via Ponytail audit first).
- Test: Load one capture, verify 100+ flows extracted.

**Task 0.3: Update RealPacketEnv to accept Stratosphere captures**
- File: `ai_agent/real_packet_env.py` line 120 (`__init__`)
- Add parameter: `dataset: str = "ctu13"` (default) or `"stratosphere"`.
- Route to appropriate loader in `_load_flows()`.
- Verify: `RealPacketEnv(..., dataset="stratosphere", capture="botnet-zeus")` loads correctly.

### Phase 1: Corrupt-Cost Sweep

**Task 1.1: Add sweep loop to snort_bandit.py**
- File: `ai_agent/snort_bandit.py` line 150 (main)
- Wrap existing bandit in a loop over `corrupt_cost_values = [0.2, 0.4, 0.6, 0.8, 1.0]`.
- For each cost:
  - Re-initialize policy (`PacketPolicy()`) and optimizer.
  - Run 10 rounds (keep rounds fixed).
  - Collect argmax deterministic evasion % and mean corruption.
- Output: Append to `sweep_results = []` list of `{cost, evasion_pct, mean_corrupt}`.
- Command to test:
  ```bash
  /tmp/jev-poc/venv/bin/python ai_agent/snort_bandit.py \
    --flows 24 --rounds 10 --batch 96 \
    --sweep-cost 0.2,0.4,0.6,0.8,1.0 --resident \
    --out snort_validation/reports/sweep_corrupt_cost.json
  ```
- Verification: Report has 5 entries, evasion % is 0-100 for each, corruption increases with cost.

**Task 1.2: Write sweep_corrupt_cost.json schema**
- Structure:
  ```json
  {
    "capture": "botnet-capture-20110819-bot",
    "flows": 24,
    "sweep_results": [
      {"corrupt_cost": 0.2, "deterministic_evaded": N, "evasion_pct": X, "mean_corrupt": Y},
      ...
    ]
  }
  ```
- Verification: File is valid JSON, has 5 results.

### Phase 2: Flow Scale-Up

**Task 2.1: Add flows scaling to snort_bandit.py**
- File: `ai_agent/snort_bandit.py` line 152 (after sweep loop)
- Add option: `--scale-flows 24,48,96,200` (or auto-generate).
- For each flow count:
  - Reload env with `n_flows=N`.
  - Re-initialize policy.
  - Run 10 rounds at fixed corrupt_cost=0.6.
  - Collect: argmax evasion %, mean reward per round (learning curve).
- Output: Append to `scale_results = []` list of `{n_flows, rounds_data[], final_evasion_pct}`.
- Command:
  ```bash
  /tmp/jev-poc/venv/bin/python ai_agent/snort_bandit.py \
    --flows auto --rounds 10 --batch 96 --corrupt-cost 0.6 --resident \
    --scale-flows 24,48,96,200 \
    --out snort_validation/reports/scale_flows.json
  ```
- Verification: Report has 4 entries (one per flow count), evasion % trends upward or stabilizes.

**Task 2.2: Write scale_flows.json schema**
- Structure:
  ```json
  {
    "capture": "botnet-capture-20110819-bot",
    "corrupt_cost": 0.6,
    "scale_results": [
      {"n_flows": 24, "deterministic_evaded": N, "evasion_pct": X, "mean_corrupt": Y, "history": [...]},
      ...
    ]
  }
  ```
- Verification: Valid JSON, 4 results, evasion_pct in [0, 100].

### Phase 3: Cross-Capture Validation

**Task 3.1: List Stratosphere captures**
- Read `data/stratosphere_captures.json` (from Task 0.1).
- Select 3-5 representative captures (different malware families).
- For each capture:
  - Run bandit with `--flows 24 --rounds 10 --batch 96 --corrupt-cost 0.6 --resident`.
  - Collect argmax evasion %, mean corruption.
  - Save to individual files: `reports/cross_capture_{capture_name}.json`.
- Command:
  ```bash
  for cap in botnet-zeus botnet-dnp3 ransomware-cryptowall; do
    /tmp/jev-poc/venv/bin/python ai_agent/snort_bandit.py \
      --flows 24 --rounds 10 --batch 96 --corrupt-cost 0.6 --resident \
      --dataset stratosphere --capture "$cap" \
      --out "snort_validation/reports/cross_capture_${cap}.json"
  done
  ```
- Verification: 3+ files exist, each has deterministic_evaded + evasion_pct fields.

**Task 3.2: Aggregate cross-capture results**
- File: `snort_validation/aggregate_results.py` (new)
- Read all `cross_capture_*.json` files.
- Produce `snort_validation/reports/cross_capture_summary.json`:
  ```json
  {
    "summary": [
      {"capture": "botnet-zeus", "deterministic_evaded": N, "evasion_pct": X, "mean_corrupt": Y},
      ...
    ],
    "mean_evasion_pct": Z,
    "std_evasion_pct": W
  }
  ```
- Command:
  ```bash
  /tmp/jev-poc/venv/bin/python snort_validation/aggregate_results.py \
    --input-dir snort_validation/reports/cross_capture_*.json \
    --output snort_validation/reports/cross_capture_summary.json
  ```
- Verification: Summary file has mean/std computed, no missing fields.

### Phase 4: Ponytail Code Audit & Simplification

**Task 4.1: Audit snort_bandit.py with Ponytail**
- Run Ponytail audit (before any modifications):
  ```bash
  # Ponytail audit skill (check for over-build, duplication)
  # Expected: Identify 2-3 redundant patterns or over-engineered sections
  ```
- Document findings in `.hermes/plans/ponytail_audit.md`.

**Task 4.2: Refactor based on Ponytail findings**
- Simplify identified patterns (e.g., consolidate sweep/scale loops into one parameterized loop).
- Reduce LOC by 10-20% without changing logic.
- Verify: All existing tests pass.
- Command:
  ```bash
  /tmp/jev-poc/venv/bin/python -m pytest snort_validation/test_snort_batch_service.py -v
  ```

### Phase 5: Final Aggregation & Report

**Task 5.1: Create master results table**
- File: `snort_validation/reports/final_results_table.json`
- Combine all sweep, scale, and cross-capture results into a single table:
  ```json
  {
    "results": [
      {"dataset": "ctu13", "capture": "botnet-capture-20110819-bot", "n_flows": 24, "corrupt_cost": 0.2, "evasion_pct": X, "mean_corrupt": Y},
      {"dataset": "ctu13", "capture": "botnet-capture-20110819-bot", "n_flows": 24, "corrupt_cost": 0.4, "evasion_pct": X, "mean_corrupt": Y},
      ...
      {"dataset": "stratosphere", "capture": "botnet-zeus", "n_flows": 24, "corrupt_cost": 0.6, "evasion_pct": X, "mean_corrupt": Y},
      ...
    ]
  }
  ```
- Verification: Table has ≥20 rows, all fields populated, no NaN values.

## Tests / Validation

**Per-task TDD cycle:**

1. **Task 0.2 test**: `tests/test_stratosphere_loader.py`
   - Test: Load a capture, assert ≥100 flows, keys are 5-tuples, values are packet lists.

2. **Task 1.1 test**: `tests/test_sweep_corrupt_cost.py`
   - Test: Run sweep with 3 costs (0.2, 0.4, 0.6), assert evasion % increases with cost, no crashes.

3. **Task 2.1 test**: `tests/test_scale_flows.py`
   - Test: Run scale with 2 sizes (24, 96), assert both complete, evasion % is in [0, 100].

4. **Task 3.2 test**: `tests/test_aggregate_results.py`
   - Test: Create 3 mock cross-capture files, run aggregator, assert summary has mean/std.

**Integration test**:
```bash
# Run full pipeline
bash snort_validation/run_full_sweep.sh  # (new script)
# Expected output: all report files exist, no Snort crashes, all JSON valid.
```

## Risks, Tradeoffs, and Open Questions

### Risks
- **Stratosphere dataset size**: Some captures may have >1000 flows; loading all may exceed memory. **Mitigation**: Cap at 200 flows per capture, downsample if needed.
- **Snort concurrency**: Multiple bandit runs on `lo` corrupt each other (observed in Task 5). **Mitigation**: Use sequential runs or per-run temp interface (requires elevated privileges).
- **Training time**: 4 flow scales × 5 cost values × 3+ captures = 60+ bandit runs; at ~3-5 min/run = 3-4 hours. **Mitigation**: Run in parallel on separate GPUs if available, or overnight.

### Tradeoffs
- **Code simplification vs. feature creep**: Ponytail audit may suggest abstractions; resist them if not needed for current sweep (YAGNI).
- **Dataset mixing**: CTU-13 + Stratosphere in same report complicates comparison. **Decision**: Keep separate tables initially; combine only if patterns are identical.

### Open Questions
1. Which 3-5 Stratosphere captures to prioritize? (Recommend: one per malware family, 200+ flows each.)
2. Should corrupt-cost sweep re-train policy fresh each time, or load previous weights? (Recommend: fresh train for fairness.)
3. Is 200 flows the max available in Stratosphere, or should we test higher? (Check dataset docs.)

## Commits Strategy

- **Task 0**: Add Stratosphere loader, update RealPacketEnv. Commit: `feat(data): add Stratosphere IPS dataset support`.
- **Task 1**: Add corrupt-cost sweep. Commit: `feat(bandit): sweep corrupt-cost frontier`.
- **Task 2**: Add flow scale-up. Commit: `feat(bandit): scale training to 200 flows`.
- **Task 3**: Add cross-capture validation. Commit: `feat(validation): cross-capture Stratosphere eval`.
- **Task 4**: Ponytail refactor. Commit: `refactor(bandit): simplify via Ponytail audit (-X% LOC)`.
- **Task 5**: Final aggregation. Commit: `results: sweep + scale + cross-capture (final)`.

## Implementation Notes

- Use Ponytail **before** implementation to identify patterns to eliminate.
- All sweep/scale/cross-capture loops must handle Snort crashes gracefully (retry once, then skip).
- Write JSON output atomically (write to temp file, rename) to avoid partial corruption.
- Test on small dataset first (e.g., 1 sweep value, 2 flow sizes, 1 capture) before full run.
