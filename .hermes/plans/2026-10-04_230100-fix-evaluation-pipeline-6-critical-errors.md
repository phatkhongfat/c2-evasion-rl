# Plan: Fix 6 Critical Evaluation Pipeline Errors & Verify RL Learning

**Goal:** Identify and fix evaluation pipeline bugs causing 40/40 vs 38.89% discrepancy, then rerun eval with strict semantics (byte-equality, per-flow scoring, bidirectional flows) to measure true evasion % and verify RL learned >2 actions.

**Current Context / Assumptions:**
- Current model: `ai_agent/hidden_defender_ppo.py` (MaskablePPO, 300K timesteps, trained on 1113 flows)
- Current results: `ppo_masked_test.json` shows 40/40 valid evasion; `cross_capture_summary.json` shows 38.89% mean
- Mismatch hypothesis: evaluation pipeline has loose semantics (naive byte checking, batch PCAP scoring, per-IP rate limiting)
- Policy hypothesis: agent may only learn 2 actions (split8, split16) instead of all 14 mechanisms
- Risk: 38.89% could be false positive; real evasion could be much lower with strict validation

**Architecture / Approach:**
1. **Audit phase**: Trace evaluation logic end-to-end (ppo_masked_test.json → cross_capture_summary.json) to find source of 40/40 vs 38.89% discrepancy
2. **Fix phase**: Implement 6 fixes in sequence (bidirectional flows, client-only mutations, byte-equality, per-flow PCAP, dynamic IP, I/O sync)
3. **Reeval phase**: Run fixed evaluation on current trained model; measure corrected evasion % and mechanism diversity
4. **Validation**: Verify RL learned >2 actions; confirm byte-equality constraints reduce false positives

---

## Phase 1: Audit Current Evaluation Pipeline

### Task 1.1: Trace evaluation flow & identify discrepancy source
**File:** `snort_validation/aggregate_results.py`  
**Command:**
```bash
cd /root/.hermes/c2-evasion-rl
python3 -c "
import json
with open('snort_validation/reports/ppo_masked_test.json') as f:
    per_flow = json.load(f)
print('ppo_masked_test.json stats:')
print(f'  Total rows: {len(per_flow[\"rows\"])}')
print(f'  Evaded (detected=False): {sum(1 for r in per_flow[\"rows\"] if not r[\"detected\"])}')
print(f'  Detected (detected=True): {sum(1 for r in per_flow[\"rows\"] if r[\"detected\"])}')
print(f'  All semantics_ok: {all(r[\"semantics_ok\"] for r in per_flow[\"rows\"])}')
print(f'  Mechanisms used: {set(r[\"mechanism\"] for r in per_flow[\"rows\"])}')

with open('snort_validation/reports/cross_capture_summary.json') as f:
    summary = json.load(f)
print('\ncross_capture_summary.json stats:')
print(f'  mean_evasion_pct: {summary.get(\"mean_evasion_pct\")}')
print(f'  std_evasion_pct: {summary.get(\"std_evasion_pct\")}')
print(f'  Calculation: (40 - X) / 40 * 100 = 38.89% → X = {40 - (38.89 * 40 / 100):.2f} detected')
"
```
**Expected output:** Shows 40 evaded in per_flow but summary calculates ~1.55 detected (or clarifies where 38.89% comes from)

**Task 1.2: Check semantics_ok flag definition**
**File:** `snort_validation/snort_bandit.py` (search `semantics_ok`)  
**Command:**
```bash
grep -n "semantics_ok" /root/.hermes/c2-evasion-rl/snort_validation/snort_bandit.py | head -20
```
**Expected output:** Shows how `semantics_ok` is computed (byte-equality check, or naive containment?)

**Task 1.3: List all evaluation entry points**
**File:** `snort_validation/` directory  
**Command:**
```bash
find /root/.hermes/c2-evasion-rl/snort_validation -name "*.py" -type f | grep -E "(eval|score|aggregate)" | xargs ls -lh
```
**Expected output:** Lists all eval/scoring scripts; identifies which ones write to `cross_capture_summary.json`

---

## Phase 2: Implement 6 Fixes (Sequential)

### Fix 1: Bidirectional Flow Extraction

**Task 2.1: Add bidirectional flow capture to PCAP loader**
**File:** `ai_agent/hidden_defender_env.py` (method `load_pcap_flow`)  
**What to check:**
- Current code: Does it extract both directions (client→server + server→client)?
- Current limitation: If it only captures outbound packets, Snort never sees TCP handshake

**Action:**
```bash
grep -A 30 "def load_pcap_flow\|def load_corpus" /root/.hermes/c2-evasion-rl/ai_agent/hidden_defender_env.py | head -50
```
**Expected output:** Shows packet loading logic; note if it's unidirectional

**Decision tree:**
- If current code filters packets one-way → fix needed
- If bidirectional already present → skip to Fix 2

**Fix implementation placeholder (do not code yet):**
- Use Scapy's `IP.src / IP.dst` + `TCP.sport / TCP.dport` to group bidirectional pairs
- Store both directions in flow state; pass to Snort
- Add test: `tests/test_bidirectional_flows.py`

### Fix 2: Client-Only Mutation Constraint

**Task 2.2: Add client-packet validation**
**File:** `snort_validation/snort_bandit.py` (method that writes mutated PCAP)  
**What to check:**
- Current code: Does it allow mutations on both client and server packets?
- Required: Agent only modifies packets where `pkt[IP].src == flow_src_ip` (client)

**Action:**
```bash
grep -B 5 -A 15 "def mutate_flow\|wrpcap\|write.*pcap" /root/.hermes/c2-evasion-rl/snort_validation/snort_bandit.py | head -60
```
**Expected output:** Shows where PCAP is written; identifies if server packets are protected

**Fix implementation placeholder:**
- Before writing PCAP: validate all mutations have `pkt[IP].src == flow_client_ip`
- Add assertion: raise error if server packet modified
- Reject action: if any server packet touched, return `semantics_ok=False, reward=-10`

### Fix 3: Byte-Equality Semantics (CRITICAL)

**Task 2.3: Replace naive byte checking with exact byte-match**
**File:** `snort_validation/snort_bandit.py` (method `check_semantics` or `validate_payload`)  
**What to check:**
```bash
grep -B 5 -A 20 "semantics_ok\|payload\|bytes\|extract.*command" /root/.hermes/c2-evasion-rl/snort_validation/snort_bandit.py | head -80
```
**Expected output:** Shows current semantics validation logic

**Current issue hypothesis:**
- Naive check: `if original_command in mutated_payload` (substring match) → too loose
- Required: `mutated_payload_after_deserialize == original_command` (exact byte match)

**Fix implementation placeholder:**
- Extract original C2 command bytes from input PCAP
- After mutation → deserialize mutated payload (reverse framing)
- Compare byte-for-byte: `original_bytes == recovered_bytes`
- If mismatch: `semantics_ok=False, reward=-10`
- Add test case with 1-byte corruption → must fail

### Fix 4: Per-Flow PCAP Scoring (batch_size=1)

**Task 2.4: Isolate each flow into separate PCAP + Snort run**
**File:** `snort_validation/snort_bandit.py` (method `score_flow` or main eval loop)  
**What to check:**
```bash
grep -B 2 -A 10 "batch\|pcap.*write\|snort.*run\|subprocess" /root/.hermes/c2-evasion-rl/snort_validation/snort_bandit.py | head -60
```
**Expected output:** Shows if multiple flows are written to one PCAP or separate PCAPs

**Current issue hypothesis:**
- Current: write N flows to single PCAP, run Snort once
- Problem: cross-flow interference (one flow's alerts shadow another's)
- Required: one flow = one PCAP file, one Snort subprocess call per flow

**Fix implementation placeholder:**
- Loop: for each (flow, action) pair:
  - Write to `/tmp/snort_eval_{flow_id}_{action_hash}.pcap`
  - Run Snort on that PCAP only
  - Parse alerts from stdout/log
  - Clean up PCAP
  - Record result to `ppo_masked_test.json`

### Fix 5: Dynamic Flow Translation (Unique IP per attempt)

**Task 2.5: Assign globally unique source IP + port per evasion attempt**
**File:** `snort_validation/snort_bandit.py` (PCAP mutation step)  
**What to check:**
```bash
grep -n "src.*ip\|IP.*src\|source.*ip" /root/.hermes/c2-evasion-rl/snort_validation/snort_bandit.py
```
**Expected output:** Shows if source IP is reused or varies

**Current issue hypothesis:**
- Current: mutated PCAP keeps original source IP (e.g., 192.168.1.100)
- Problem: Snort's `track by_src` threshold fires after 3-4 attempts from same IP
- Required: each attempt gets new `(src_ip, src_port)` pair globally unique

**Fix implementation placeholder:**
- Add counter: `global_attempt_id = 0` (incremented per Snort call)
- Generate unique IP: `new_src_ip = f"10.0.{attempt_id // 256}.{attempt_id % 256}"`
- Generate unique port: `new_src_port = 30000 + (attempt_id % 35535)`
- Before writing PCAP: translate all client packets: `pkt[IP].src = new_src_ip; pkt[TCP].sport = new_src_port`
- Keep server IP/port unchanged

### Fix 6: I/O Synchronization (Snort Exit + Flush)

**Task 2.6: Wait for Snort process + file flush before reading alerts**
**File:** `snort_validation/snort_bandit.py` (method that reads Snort output)  
**What to check:**
```bash
grep -B 3 -A 10 "subprocess\|popen\|run\|fast-alert\|read.*alert" /root/.hermes/c2-evasion-rl/snort_validation/snort_bandit.py | head -60
```
**Expected output:** Shows Snort subprocess handling

**Current issue hypothesis:**
- Current: Python reads `snort.log` immediately after `subprocess.run()` returns
- Problem: Snort buffered in-memory; hasn't flushed to disk yet
- Required: explicit wait for Snort exit code 0 + file sync

**Fix implementation placeholder:**
```python
# Before reading alerts:
proc = subprocess.run(
    ['snort', '-c', snort_conf, '-r', pcap_file, '-l', log_dir],
    capture_output=True,
    text=True
)
if proc.returncode != 0:
    raise RuntimeError(f"Snort failed: {proc.stderr}")

# Force filesystem sync
os.fsync(open(alert_log_path).fileno())
time.sleep(0.5)  # Give filesystem time to write

# Now safe to read
with open(alert_log_path) as f:
    alerts = f.read()
```

---

## Phase 3: Verification & Reeval

### Task 3.1: Write test for each fix
**File:** `tests/test_evaluation_fixes.py` (create new)  
**TDD cycle for each fix:**

1. **Test 1 — Bidirectional flows:**
   ```bash
   pytest tests/test_evaluation_fixes.py::test_bidirectional_flow_complete -v
   ```
   Expected: FAIL (server packets not extracted yet)

2. **Test 2 — Client-only mutations:**
   ```bash
   pytest tests/test_evaluation_fixes.py::test_server_packets_immutable -v
   ```
   Expected: FAIL (server packets can be modified currently)

3. **Test 3 — Byte-equality:**
   ```bash
   pytest tests/test_evaluation_fixes.py::test_exact_byte_match_semantics -v
   ```
   Expected: FAIL (naive substring match passes corrupted payloads)

4. **Test 4 — Per-flow PCAP:**
   ```bash
   pytest tests/test_evaluation_fixes.py::test_one_pcap_per_flow -v
   ```
   Expected: FAIL (current code batches flows)

5. **Test 5 — Dynamic IP:**
   ```bash
   pytest tests/test_evaluation_fixes.py::test_unique_source_ip_per_attempt -v
   ```
   Expected: FAIL (reused IPs currently)

6. **Test 6 — I/O sync:**
   ```bash
   pytest tests/test_evaluation_fixes.py::test_snort_flush_before_read -v
   ```
   Expected: FAIL (race condition on alert file)

### Task 3.2: Rerun full evaluation after all fixes
**File:** `snort_validation/eval_fixed_pipeline.py` (wrapper script)  
**Command:**
```bash
cd /root/.hermes/c2-evasion-rl
python3 snort_validation/eval_fixed_pipeline.py \
  --model ai_agent/ppo_masked_latest.zip \
  --test-set snort_validation/reports/ppo_masked_test.json \
  --output snort_validation/reports/ppo_masked_test_FIXED.json \
  --batch-size 1 \
  --dynamic-ip \
  --byte-equality
```
**Expected output:** New report with:
- Per-flow results (1 PCAP per flow)
- Unique source IPs
- Byte-equality validation
- Mechanism diversity (count how many actions agent used)

### Task 3.3: Compare results
**Command:**
```bash
python3 -c "
import json
with open('snort_validation/reports/ppo_masked_test.json') as f:
    old = json.load(f)
with open('snort_validation/reports/ppo_masked_test_FIXED.json') as f:
    new = json.load(f)

old_evaded = sum(1 for r in old['rows'] if not r['detected'])
new_evaded = sum(1 for r in new['rows'] if not r['detected'])
old_mech = set(r['mechanism'] for r in old['rows'])
new_mech = set(r['mechanism'] for r in new['rows'])

print(f'Old evasion: {old_evaded}/40 ({old_evaded*100/40:.1f}%)')
print(f'New evasion: {new_evaded}/40 ({new_evaded*100/40:.1f}%)')
print(f'Old mechanisms used: {sorted(old_mech)}')
print(f'New mechanisms used: {sorted(new_mech)}')
print(f'Overfit fix: {\"YES\" if len(new_mech) > 2 else \"NO - still using ≤2 actions\"}')
"
```
**Expected output:** Shows true evasion % and whether RL learned diversity

### Task 3.4: Commit fixes
```bash
cd /root/.hermes/c2-evasion-rl
git add snort_validation/snort_bandit.py ai_agent/hidden_defender_env.py tests/test_evaluation_fixes.py snort_validation/eval_fixed_pipeline.py
git commit -m "fix(eval): implement 6 critical pipeline fixes (bidirectional, byte-equality, per-flow, dynamic-ip, I/O-sync)"
```

---

## Risks, Tradeoffs & Open Questions

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **Evasion % drops significantly** (e.g., 38.89% → 5%) | RL may not have learned; report invalid | Document honestly in thesis; consider retraining with fixed eval |
| **Per-flow scoring 10× slower** | Eval takes hours instead of minutes | Run in background; accept longer runtime for correctness |
| **Byte-equality too strict** | Legitimate framing offsets penalized | Test with known-good mutations; adjust `-10` penalty if needed |
| **Dynamic IP breaks reproducibility** | Results vary across runs | Use fixed seed for IP counter; document in methodology |
| **I/O sync not foolproof** | Still rare race conditions | Add retry logic; verify Snort wrote to disk via `stat()` |

| Tradeoff | Choose | Reason |
|----------|--------|--------|
| **Rollback training?** | No; reeval current model | See if fixes alone expose overfit; retrain only if needed |
| **Archive old results?** | Yes; move to `archive/reports_old/` | Keep audit trail; don't overwrite 38.89% until verified |
| **New corpus needed?** | No; use existing 40 test flows | Bidirectional extraction applies retroactively |

| Open Question | Resolution |
|---------------|-----------|
| Why 40/40 vs 38.89% discrepancy? | Will be found during Phase 1 audit |
| Can evasion survive byte-equality? | Will be measured in Phase 3 reeval |
| Did RL learn >2 actions? | Will be measured by mechanism diversity in reeval |
| Is 5-10% evasion viable for thesis? | Depends on user's goal; document honestly either way |

---

## Expected Deliverables After Plan Execution

1. **Fixed evaluation pipeline** (`snort_validation/snort_bandit.py` + helpers)
2. **6 test cases** (all pass after fixes)
3. **New eval report** (`snort_validation/reports/ppo_masked_test_FIXED.json`)
4. **Ground-truth evasion %** (replaces 38.89% with verified number)
5. **Mechanism diversity check** (action distribution, >2 or overfit?)
6. **Thesis appendix update** (corrected numbers + methodology note)
7. **Commit** documenting all 6 fixes

---

## Estimated Effort

- **Phase 1 (audit):** 5 min
- **Phase 2 (implement fixes):** 40 min (10 min per fix + testing)
- **Phase 3 (reeval):** 60 min (40 min eval run + 20 min analysis)
- **Total:** ~2 hours wall time (eval runs in background; implementer idle)

---

**Plan saved at:** `/root/.hermes/c2-evasion-rl/.hermes/plans/2026-10-04_230100-fix-evaluation-pipeline-6-critical-errors.md`
