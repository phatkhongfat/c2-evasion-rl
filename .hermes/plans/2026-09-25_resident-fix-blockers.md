# Plan: Fix Resident/Bandit + Clear Blockers for Report

**Goal:** Fix the resident-service integration so bandit results are correct, then clear any remaining blockers (test failures, missing data, etc.) so reporting can begin.

## Current Context

- **Resident service (standalone):** Verified correct (12/12 agreement). Runs Snort once on loopback, replays frames, reads alerts from file.
- **Resident + bandit:** Broken. Reports impossible baseline (0/24 unmutated detected), implausible round-to-round swings. Root cause: all rounds share one alert stream; uid stride doesn't isolate batches.
- **File-mode reference:** 100% argmax at 5.17/32 packets (per-batch service, trusted).
- **Known issues:** Only the resident integration is broken; everything else works.

## Architecture / Approach

**Fix 1 (Resident isolation):** Restart the service between each bandit round. Simplest approach: call `resident.stop()` → `resident.start()` after each round's eval. No frame generation changes needed; just isolates state.

**Fix 2 (Clear blockers):** Run the full test suite, check for failures. Fix any that block reporting.

## Step-by-Step Tasks

### Task 1: Patch snort_bandit.py to restart resident between rounds
**File:** `ai_agent/snort_bandit.py` (lines 140–297)
**What:** After each round's verdicts are collected, if `resident` is not None, call `resident.stop()` and `resident.start()` to reset the alert stream.

**Exact change:**
- Find the loop that iterates rounds (around line 190–240, inside the training loop).
- After the round completes (after verdicts are read, before the next round starts), add:
```python
if resident is not None:
    resident.stop()
    if not resident.start():
        print(f"[!] resident restart failed: {resident.error}"); exit(1)
```

**Verification:** Run with `--resident --flows 24 --rounds 3 --batch 96 --corrupt-cost 0.6`. Expect:
- baseline detected: 9/24 (matching file mode)
- round-to-round evasion rates to be stable (not 100% → 0% → 100%)
- random control = 0%, corrupt-all = 100%
- agent should show sensible learning (evasion ↓ as rounds progress)

Exact command:
```bash
cd /root/.hermes/c2-evasion-rl && \
  pkill -x snort 2>/dev/null; sleep 1; \
  /tmp/jev-poc/venv/bin/python ai_agent/snort_bandit.py \
    --flows 24 --rounds 3 --batch 96 --corrupt-cost 0.6 \
    --resident --out /tmp/test_resident_fix.json
```

Expected output pattern:
```
[*] using RESIDENT snort (no per-batch rule reload)
[*] 24 real positive flows from botnet-capture-20110819-bot
[*] baseline detected: 9/24
[round 0] evaded X/24 (Y%)  mean_reward=... (should be sensible, not 100%)
[round 1] evaded ...
[round 2] evaded ...
[*] DETERMINISTIC (argmax): evaded Z/24 (W%)  mean_corrupt=0.00
[*] random control:        evaded 0/24 (0.0%)
[*] corrupt-all control:   evaded 24/24 (100.0%)
```

### Task 2: Run full test suite
**Command:**
```bash
cd /root/.hermes/c2-evasion-rl && \
  /tmp/jev-poc/venv/bin/python -m pytest snort_validation/ -v 2>&1 | tee /tmp/test_suite.log
```

**Expected:** All tests pass, or clearly identify which ones fail.
**Action:** If failures, read them carefully. Most are likely environment-specific (missing data files, network issues). Fix only if they block report writing.

### Task 3: Verify data artifacts exist
**Command:**
```bash
ls -lh snort_validation/reports/
```

Expected files:
- `snort_bandit.json` (file-mode baseline, reference)
- `snort_bandit_resident.json` (broken; will be replaced after Task 1)
- `random_evaluation.json`, `baseline_evaluation.json` (surrogate cross-capture)
- `generalization_diagnosis.json` (CTU-13 feature analysis)

**Action:** If any are missing and needed for the report, note them as blockers.

### Task 4: Commit the resident fix
**After Task 1 passes:**
```bash
cd /root/.hermes/c2-evasion-rl && \
  git add ai_agent/snort_bandit.py && \
  git commit -m "fix(defense): resident Snort restart between bandit rounds (alert stream isolation)"
```

### Task 5: Run the fixed resident bandit on full config
**Command:**
```bash
pkill -x snort 2>/dev/null; sleep 1; \
  cd /root/.hermes/c2-evasion-rl && \
  /tmp/jev-poc/venv/bin/python ai_agent/snort_bandit.py \
    --flows 24 --rounds 10 --batch 96 --corrupt-cost 0.6 \
    --resident --out snort_validation/reports/snort_bandit_resident_fixed.json
```

Expected: Baseline = 9/24, sensible learning curve, correct controls.

Commit:
```bash
git add snort_validation/reports/snort_bandit_resident_fixed.json && \
  git commit -m "results: resident bandit (fixed isolation) — baseline 9/24, argmax TBD"
```

---

## Tests / Validation

- **Selftest** (Task 1): Baseline must be 9/24 (matching file mode). If it's 0/24, isolation failed.
- **Controls** (Task 1): Random = 0%, corrupt-all = 100%. If not, something is still wrong.
- **Learning stability** (Task 1): Round 0–9 evasion rates should be monotonic-ish or at least not wild swings like 100% → 0% → 100%.
- **Suite** (Task 2): Identify test failures. Skip if they don't block reporting.

---

## Risks, Tradeoffs, Open Questions

**Risk:** Restart overhead. Each restart = 1-2 sec (rule load + readiness probe). 10 rounds = 20 extra seconds. Acceptable for correctness.

**Tradeoff:** Restart is simple but not elegant. A cleaner fix (per-batch interface, generation marker) exists but takes longer. Restart unblocks reporting now.

**Open:** After fix works, should we also run cross-capture (like the surrogate did)? Plan assumes single-capture (bot) for now. Recommend cross-capture as part of report validation, not blocker.

---

## Deliverables

1. `ai_agent/snort_bandit.py` patched (resident restart between rounds).
2. Test suite run log (`/tmp/test_suite.log`).
3. Data artifacts verified.
4. New report: `snort_bandit_resident_fixed.json`.
5. Two commits: fix + results.
6. Blockers (if any) identified and documented.
