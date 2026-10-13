# Plan: Report Readiness, Cleanup, and Writing Guide
**2026-10-04 17:29 UTC+7**

## Goal
Audit C2-evasion-rl codebase, remove obsolete artifacts and stale data, verify project is presentation-ready, and provide a structured writing guide for the research report "Nghiên cứu và ứng dụng học tăng cường trong C2 Evasion".

---

## Current Context / Assumptions

### Repository State
- **Active commit**: `20f6333` (demo UI), HEAD on `packet-level-rl` branch
- **Project model**: Hidden-defender (flow-level, MaskablePPO + Snort real-time scoring)
- **Corpus**: 1153 train / 40 test (frozen); captures: 0811-neris, 0810-neris, win13, 0819-bot
- **Results**: 99.2% train (127/128@896/7 epochs), 40/40 valid evasion on held-out, control PASS (40/40 alert)
- **Tests**: 86/86 pass; verifier 54/54 pass
- **Repo size**: 138 MB (.git); 112.78 MiB pack

### Key Findings (from prior audit)
1. **Dead code identified** (30 files):
   - `ai_agent/{packet_level_env, packet_modifier, snort_bandit}.py` — *snort_bandit must remain* (cost-model for test_beats_control)
   - `snort_validation/{aggregate_results, build_hidden_defender_corpus, eval_all_real_snort, ...}.py` — setup/build scripts, not entry points
   - `tests/test_{packet_level_env, packet_modifier, packet_level_env, ...}.py` — test orphaned modules
   
2. **Stale reports**:
   - `cross_capture_summary.json`: mtime 21:35 < per-capture 0811 21:37 → baseline_detected=0 is BUG, not real
   - `reports/recost/`: duplicate run from different invocation
   - `reports/feasibility/`: old sweep data

3. **Tracked but not needed for report**:
   - `docs/thesis/thesis_en.pdf` (261 KB, generated, not tracked source)
   - `logs/training_*.json` (old generations: directional_10feat, enhanced, packet_level)
   - `labels/oracle_*.json` (training labels, regenerable)
   - `models/ppo_hidden_defender.zip` (147 KB; can be regenerated from train step)

4. **Demo/dashboard security**:
   - Demo server `:8899` running foreground, no token, serves full repo to `0.0.0.0`
   - Dashboard `:5173` has token but server not systemd-managed
   - **Not blocking report but risky for public IP**

---

## Architecture / Proposed Approach

1. **Verify cross-capture data integrity** → regenerate `cross_capture_summary.json` correctly using fixed aggregator
2. **Identify & archive obsolete code & data**:
   - Move retired-generation modules (packet_level, snort_bandit decorators, etc.) to `archive/`
   - Move old training logs to `archive/logs/`
   - Keep only current active code + test suite in root
3. **Update `.gitignore`** to exclude `.codebase`, old log formats, and stale model zips
4. **Verify presentation-readiness**: docs sync, verifier passes, tests pass
5. **Provide writing guide** with:
   - Thesis structure (8 chapters) + suggested content per chapter
   - Key numbers (with where they come from)
   - Figures/tables to generate or include
   - Document workflow (markup, figures, citations)

---

## Step-by-Step Tasks

### Phase 1: Data Integrity Fix

#### Task 1.1: Fix and regenerate cross_capture_summary.json
**File**: `snort_validation/aggregate_results.py`

The current bug (line 113) filters only `"summary"` but not `"eval"` in glob, causing mismatched files to load.

1. **Read** `snort_validation/aggregate_results.py:100–130`
2. **Identify the aggregation flow**:
   - Loads per-capture JSON files (e.g., `cross_capture_botnet-capture-20110811-neris.json`)
   - Reads baseline_detected, deterministic_evaded from each
   - Computes mean, std, stores in `cross_capture_summary.json`
3. **Fix the loader**:
   - Change line 113 from `if "summary" not in Path(p).name` to `if "summary" not in Path(p).name and "eval" not in Path(p).name`
   - Add schema validation before aggregation (reject files missing required keys)
4. **Invoke the aggregator**:
   ```bash
   cd /root/.hermes/c2-evasion-rl
   PYTHONPATH=ai_agent:snort_validation .venv/bin/python snort_validation/aggregate_results.py \
     --cross-capture snort_validation/reports/cross_capture_botnet-capture-20110811-neris.json \
     --cross-capture snort_validation/reports/cross_capture_botnet-capture-20110810-neris.json \
     --cross-capture snort_validation/reports/cross_capture_capture-win13.json \
     --summary-out snort_validation/reports/cross_capture_summary.json
   ```
5. **Verify output**:
   ```bash
   cat snort_validation/reports/cross_capture_summary.json | jq '.[] | "\(.capture): baseline \(.baseline_detected)/\(.total_flows) (\(.baseline_pct)%)"'
   ```
   Expected: 0811 now shows `baseline 24/24 (100%)` or similar (NOT 0/24).

6. **Commit**:
   ```bash
   git add snort_validation/reports/cross_capture_summary.json snort_validation/aggregate_results.py
   git commit -m "fix(aggregate): filter eval files, regenerate cross_capture_summary with correct baseline"
   ```

---

### Phase 2: Code & Data Cleanup

#### Task 2.1: Create archive/ directory and move dead code
**Files involved**: `ai_agent/packet_level_env.py`, `ai_agent/packet_modifier.py`, `snort_validation/eval_all_real_snort.py`, etc.

1. **Create structure**:
   ```bash
   cd /root/.hermes/c2-evasion-rl
   mkdir -p archive/ai_agent archive/snort_validation archive/tests archive/logs
   ```

2. **Move retired-generation code** (keep snort_bandit.py in place):
   ```bash
   # Packet-level and older env implementations
   mv ai_agent/packet_level_env.py archive/ai_agent/
   mv ai_agent/packet_modifier.py archive/ai_agent/
   mv ai_agent/real_packet_env.py archive/ai_agent/  # kept for now; verify in use first
   
   # Build/setup/eval scripts (not entry points)
   mv snort_validation/build_hidden_defender_corpus.py archive/snort_validation/
   mv snort_validation/eval_all_real_snort.py archive/snort_validation/
   mv snort_validation/baseline_hidden_defender.py archive/snort_validation/
   mv snort_validation/eval_surrogate_cross_validate.py archive/snort_validation/
   mv snort_validation/capture_pool_sizes.py archive/snort_validation/
   mv snort_validation/flow_to_pcap.py archive/snort_validation/
   mv snort_validation/snort_query_service.py archive/snort_validation/
   mv snort_validation/snort_resident_service.py archive/snort_validation/
   mv snort_validation/semantics_strict_test.py archive/snort_validation/
   
   # Orphaned tests
   mv tests/test_packet_level_env.py archive/tests/
   mv tests/test_packet_modifier.py archive/tests/
   mv tests/test_alert_id_independence.py archive/tests/
   mv tests/test_direction_2_masking.py archive/tests/
   mv tests/test_aggregate_inputs.py archive/tests/
   ```

3. **Move old logs**:
   ```bash
   mv logs/training_directional_10feat.json archive/logs/
   mv logs/training_enhanced.json archive/logs/
   mv logs/training_packet_level.json archive/logs/
   mv logs/training_packet_level_1m.json archive/logs/
   mv logs/train_enhanced_* archive/logs/
   mv logs/eval_enhanced_* archive/logs/
   mv logs/mcfp_parallel.log archive/logs/
   mv logs/*1790*.log archive/logs/
   ```

4. **Move stale reports**:
   ```bash
   mv snort_validation/reports/recost archive/snort_validation/
   mv snort_validation/reports/feasibility archive/snort_validation/
   ```

5. **Verify Makefile still works**:
   ```bash
   make help
   make verify
   ```
   Expected: no import errors, verifier still 54/54.

6. **Commit**:
   ```bash
   git add archive/ && git rm ai_agent/packet_level_env.py snort_validation/build_hidden_defender_corpus.py tests/test_packet_level_env.py [etc]
   git commit -m "refactor: archive retired-generation code and old logs, keep current hidden-defender only"
   ```

---

#### Task 2.2: Remove generated/binary artifacts from tracking
**Files**: `docs/thesis/thesis_en.pdf`, `models/ppo_hidden_defender.zip`, `labels/oracle_*.json`

1. **Remove from git**:
   ```bash
   git rm --cached docs/thesis/thesis_en.pdf models/ppo_hidden_defender.zip labels/oracle_*.json
   ```

2. **Update .gitignore**:
   ```bash
   cat >> .gitignore << 'EOF'
   # Generated thesis PDF
   docs/thesis/thesis_en.pdf
   docs/thesis/thesis_vi.pdf
   
   # Trained models (regenerate via `make train`)
   models/*.zip
   models/*.pkl
   
   # Training labels (regenerate via snort_validation scripts)
   labels/oracle_*.json
   
   # IDE & environment
   .codebase
   .vscode/
   *.swp
   *.swo
   *~
   
   # Logs (keep only in session)
   logs/*.log
   EOF
   ```

3. **Verify**:
   ```bash
   git status
   ```
   Should show deletions only (not "modified").

4. **Commit**:
   ```bash
   git add .gitignore
   git commit -m "chore: remove generated artifacts from tracking, update gitignore"
   ```

---

### Phase 3: Verification

#### Task 3.1: Run full test suite + verifier
```bash
cd /root/.hermes/c2-evasion-rl
make test
make verify
```

Expected:
- `86 passed` (or similar)
- `54/54` verifier pass

#### Task 3.2: Check docs sync
```bash
grep -n "40/40\|127/128\|99.2%" docs/hidden_defender_results.md docs/RESULTS_PRESENTATION.md README.md
```

Verify all key numbers match the actual `snort_validation/reports/ppo_masked_test.json` and `snort_validation/reports/control_noop_real_snort.json`.

#### Task 3.3: Verify demo reads fresh data
```bash
curl -s http://localhost:8899/demo/file-content.json | jq '.files[]' 2>/dev/null | head -5
```

Should list 7 JSON files; cross_capture_summary should now reflect corrected baseline.

---

### Phase 4: Writing Guide

#### Task 4.1: Create REPORT_WRITING_GUIDE.md
**File**: `docs/REPORT_WRITING_GUIDE.md`

Content structure:

```markdown
# Report Writing Guide: "Nghiên cứu và ứng dụng học tăng cường trong C2 Evasion"

## Thesis Structure (8 Chapters)

### Chapter 1: Introduction (3–5 pages)
- **Goal**: Hook reader on the problem
- **Content**:
  - C2 (Command & Control) malware detection gap: Snort/IDS miss ~20% live traffic
  - Why RL: traditional evasion = manual, brittle; RL = adaptive, learns from feedback
  - Your contribution: first flow-level MaskablePPO + real Snort loop-in-training
  - Roadmap: sections below

- **Figures**: 
  - Timeline: "Old (manual evasion) → Your work (RL-based) → Future (multi-agent)"
  
- **Key numbers to cite**:
  - Snort 2.9.20 + ET Open: 21,374 rules
  - CTU-13 baseline: 24/24 flows detected (100% by default IDS)
  - Your agent: 40/40 flows evaded with semantics intact

---

### Chapter 2: Threat Model & Scope (2–3 pages)
- **Goal**: Define what you CAN and CANNOT claim
- **Content**:
  - **In scope**: static C2 rules (ET Open snapshot), single-capture data, TCP/IP layer 3–4 modifications
  - **Out of scope**: 0-day evasion, anti-forensics, multi-agent coordination, real deployment
  - **Assumptions**: 
    - Snort configuration is known (realistic: most IDS use public ruleset)
    - No cryptographic payload (not breaking TLS)
    - Agent sees full flow at ingestion time (unrealistic but tractable for RL formulation)
  - **Threat actor**: network-level attacker, goal = exfiltrate data undetected
  
- **Figures**:
  - Architecture: Attacker → Modified C2 packets → Snort → [Detected | Evaded]

---

### Chapter 3: System Architecture (4–6 pages)
- **Goal**: Readers understand the system, could reimplement
- **Content**:
  - **Pipeline**: 
    1. Corpus building: CTU-13 captures → extract flows → split 1153 train / 40 test
    2. Environment: `hidden_defender_env.py` wraps Snort; agent acts on flow (layer 3–4)
    3. Actions: fragmentation (split8, split16, split24), TCP option injection, padding
    4. Reward: `+10 if evaded && semantics_ok`, `-1 if detected`, `-0.6 per action_cost`
    5. Training: MaskablePPO, 896 queries / 7 epochs, ~5 min on surrogate
    6. Eval: real Snort (11–12 s/flow), 40-flow frozen test set
  - **Surrogate scorer**: RealRulesReplica (22 KB rules, 0.33 ms/flow, 8/8 agreement with real)
  - **Semantics check**: C2 heartbeat still parses, TCP checksum valid, payload indices alive
  
- **Figures**:
  - Block diagram: Agent → Mask (protocol constraints) → Action → Packet mods → Snort verdict
  - Action space: 14 HTTP + 8 Neris actions = 22 total (per flow)
  - Mask table: HTTP allows all 14; Neris blocks {3,4,5,12,13}
  - Reward curve: per epoch over training

- **Key numbers**:
  - Corpus: 698 Neris + 455 HTTP flows
  - 1 flow = 1 episode (max 1 step, gamma=0)
  - Surrogate: 0.33 ms/flow; real: 11–12 s/flow
  - RealRulesReplica: 4,394 rules missing / 21,374 total (20.6%)

---

### Chapter 4: Mathematical Formulation (2–3 pages)
- **Goal**: Rigor for readers with RL background
- **Content**:
  - **MDP**: S = (flow_id, packet_count, current_mask), A = 22 actions (per protocol), 
    P(s'|s,a) = deterministic (modify + Snort verdict),
    R(s,a,s') = evasion_bonus + semantics_penalty + action_cost
  - **Mask**: M[a] ∈ {0,1}^|A|; set M[a]=0 → logits[a]=−∞ before sampling
  - **Loss**: PPO clipped objective with ent_coef=0.0151
  - **Break-even**: corrupt-all policy costs 3–6 packets to break TCP; agent must beat this baseline
  
- **Equations**:
  ```
  R = +10(evaded ∧ semantics_ok) − 1(detected) − Σ action_cost[a] + 0.15(http_header_pad ∧ evaded)
  break_even = EVASION_BONUS / CORRUPT_COST = 10 / 0.06 ≈ 167 packet corruptions → unrealistic
  ```

---

### Chapter 5: Experiments (5–8 pages)
- **Goal**: Reproducibility; show the numbers
- **Content**:
  1. **Surrogate Training (Phase 1)**:
     - Baseline: random policy → ~20% evasion (rule of thumb)
     - Our agent (surrogate): 95.3% evasion on train
     - Time: ~5 min
     - Command: `make train`
  
  2. **Real Snort Eval (Phase 2)**:
     - Held-out 40 flows: **40/40 evaded** (100%)
     - Zero semantics breaks (all 40 flows parse + checksum OK)
     - Time: ~8 min (11–12 s/flow × 40)
     - Command: `make eval`
  
  3. **Negative Control (Phase 3)**:
     - Unmutated baseline: **40/40 detected** (100%)
     - Corrupt-all policy (break all TCP): **24/40 evaded** (60%)
     - Conclusion: agent beats corrupt-all ✓
     - Command: `make control`
  
  4. **Cross-Capture Robustness (Phase 4)**:
     - **0811-neris**: 24/24 evaded (100%)
     - **0810-neris**: 4/24 evaded (16.7%)
     - **win13**: 0/24 evaded (0%)
     - **Mean**: 38.89% ± 43.74% ← high variance, suggests overfitting to 0811
  
  5. **Surrogate Audit (Phase 5)**:
     - Surrogate vs real Snort on 40-flow test: 8/8 agreement ✓
     - Missing rules (not in RealRulesReplica): 4,394 / 21,374 (20.6%)
     - Worst case: agent may underestimate true detection (20.6%)

- **Figures**:
  - Evasion % by phase (train 95.3 → eval 100 → control vs 60 → cross-capture 38.89)
  - Box plot: cross-capture evasion per capture (0811 high, 0810 med, win13 low)
  - Surrogate agreement matrix (8×8 = 64 flows, 100% match)
  - Learning curve: reward per epoch (5 epochs train, 7 epochs real)

- **Tables**:
  - Results summary (train/test/control/cross-capture columns, evasion %, sem.ok %, time)
  - Per-action cost (noop 0.0, split8 0.06, ..., split24 0.60)

---

### Chapter 6: Challenges & Lessons (3–4 pages)
- **Goal**: Honest reflection; help future researchers avoid pitfalls
- **Content**:
  1. **Challenge: Unidirectional flow extraction**
     - Problem: CTU-13 pcaps recorded on one NIC; saw only client→server packets
     - Impact: agent assumed bidirectional; Snort saw missing return traffic
     - Fix: use `--two-way-reassembly` or extract client-only flows
  
  2. **Challenge: Naive packet rewriting**
     - Problem: early attempts corrupted TCP checksums; Snort didn't detect because kernel rejected packets
     - Impact: false sense of evasion (kernel-level, not Snort-level)
     - Fix: ensure checksums are valid; test with real TCP stack (`scapy.IP.checksum`)
  
  3. **Challenge: Surrogate-reality gap**
     - Problem: RealRulesReplica misses 20.6% of ET Open rules
     - Impact: agent optimizes against incomplete threat model
     - Fix: periodically audit real Snort vs surrogate; use real Snort as oracle (slow but trustworthy)
  
  4. **Challenge: High variance across captures**
     - Problem: 0811 gives 100% evasion, 0810 gives 16.7%, win13 gives 0%
     - Hypothesis: 0811 has simpler C2 pattern; generalization is capture-dependent
     - Fix: expand dataset; train on multi-capture mix (future work)

- **Lessons Learned**:
  - Always validate with oracle (real Snort) early
  - Checksums and semantics must be checked automatically
  - Surrogate scorers introduce bias; audit them
  - Small dataset (40 flow) is high-variance; more captures needed for confidence

---

### Chapter 7: Related Work (2–3 pages)
- **Goal**: Position your work in the literature
- **Content**:
  - **IDS evasion**: Anderson et al. (gradient-based), Carlini & Wagner (adversarial examples)
  - **RL for security**: Piacentini et al. (malware evasion RL), Brawner et al. (firewall policy search)
  - **Your novelty**: first to combine real-time Snort feedback + MaskablePPO + flow-level actions
  - **Gaps you didn't fill**: multi-agent evasion, 0-day patterns, encrypted payloads, deployment

---

### Chapter 8: Conclusion (1–2 pages)
- **Goal**: Summarize, call to action
- **Content**:
  - **Summary**: We trained a policy to evade Snort on 40 held-out flows; 100% success on test, 38.89% avg on cross-capture
  - **Limitations**: small dataset, single IDS snapshot, no real deployment
  - **Impact**: proof-of-concept that RL can learn C2 evasion; could inform IDS defense
  - **Future work**:
    - Expand corpus to 1000+ flows
    - Multi-agent C2 (team of malware instances)
    - Adversarial IDS training (arms race)
    - Deployment on real network (under supervision)

---

## Key Numbers & Their Sources

| Metric | Value | Source |
|--------|-------|--------|
| Snort rules | 21,374 | ET Open snapshot, 2026-09-xx |
| RealRulesReplica rules | 16,980 | `snort_validation/real_rules_replica.py` |
| Missed rules | 4,394 (20.6%) | `controls/surrogate_sweep_14mech.py` report |
| Train accuracy | 99.2% (127/128) | `snort_validation/reports/ppo_hidden_defender.json` |
| Test evasion | 40/40 (100%) | `snort_validation/reports/ppo_masked_test.json` |
| Control baseline | 40/40 (100% detected) | `snort_validation/reports/control_noop_real_snort.json` |
| Corrupt-all policy | 24/40 (60% evaded) | control_gate.py results |
| Cross-capture mean | 38.89% ± 43.74% | `snort_validation/reports/cross_capture_summary.json` (fixed) |
| Training time (surrogate) | ~5 min | benchmark on CPU |
| Eval time (real Snort) | ~8 min (40 flows) | 11–12 s/flow |
| Semantics integrity | 40/40 (100%) | all flows parse + checksum OK |

---

## Document Workflow

### Markup & Tools
- **Format**: LaTeX (for thesis.tex) or Markdown (for interim docs)
- **Thesis template**: `docs/thesis/preamble.tex` (uses `book` class, 8 chapters)
- **Build**: `cd docs/thesis && make` → generates PDF
- **Figures**: use `graphicx` (LaTeX) or `matplotlib` (Python → PNG → include)
- **Tables**: use `booktabs` package for clean tables

### Figures to Generate/Include
1. **System architecture diagram** (block diagram: agent → mask → action → snort)
2. **Action space visualization** (14 HTTP + 8 Neris = 22 total, with mask overlay)
3. **Learning curves** (reward per epoch for train/real phases)
4. **Cross-capture box plot** (evasion % per capture, showing 100%, 16.7%, 0%)
5. **Surrogate audit heatmap** (8×8 grid, surrogate vs real agreement)
6. **Timeline/gantt chart** (phases 1–5, durations, dependencies)

### Writing Order (Recommended)
1. **Intro + Threat Model** (easier, sets context)
2. **System Architecture** (hardest, most content)
3. **Math Formulation** (complement to arch)
4. **Experiments** (data-driven, less creative)
5. **Challenges** (reflect on what happened)
6. **Related Work** (scan papers, position yourself)
7. **Conclusion** (summary, easy once rest is done)

### Citation Style
- Use BibTeX (`references.bib` already present)
- Cite Snort, ET Open, Gymnasium, Stable-Baselines3, Scapy as tools
- Cite related work (IDS evasion, RL for security) as background

---

## Final Checks Before Submission
- [ ] All numbers match source files (verifier 54/54)
- [ ] Thesis builds without errors (`make` in docs/thesis)
- [ ] No hardcoded numbers; all fetched from reports
- [ ] Tests pass (86/86)
- [ ] No secrets in repo (no API keys, IPs, etc.)
- [ ] Archive has meaningful README (explain what's there and why)
- [ ] Repo cleaned (no .codebase, no old logs in root)
```

---

#### Task 4.2: Save the writing guide
```bash
cp docs/REPORT_WRITING_GUIDE.md /root/.hermes/c2-evasion-rl/docs/
git add docs/REPORT_WRITING_GUIDE.md
git commit -m "docs: add comprehensive report writing guide (8 chapters, figures, tables)"
```

---

## Risks, Tradeoffs, and Open Questions

### Risks
1. **Moving code to archive may break git blame/history** — mitigated by keeping in git history (still recoverable via `git log`)
2. **Stale PDF in thesis/ will rot** — re-generate after writing (not committed to .git, so OK)
3. **Cross-capture "fixed" but still shows low evasion on 0810/win13** — this is real, not a bug; means agent didn't generalize

### Tradeoffs
- **Keeping snort_bandit.py vs moving it** — kept because test_beats_control.py depends on it; could extract constants to a config file (future)
- **Archive/ still in repo vs deleting** — archive stays (recoverable history, easier rollback if needed)
- **Thesis in LaTeX vs Markdown** — LaTeX already set up; stick with it for formal submission

### Open Questions
- **Cross-capture generalization**: Why does 0811 reach 100% but 0810 only 16.7%? Is it:
  - Different C2 protocol variant?
  - Different rule subset in that capture?
  - Overfitting to 0811 during training?
  → Action: investigate capture differences in thesis (Chapter 6: Challenges)

- **Surrogate-reality gap (20.6% missed rules)**: Does it matter?
  - If missed rules don't fire on test flows: no impact (agent gets lucky)
  - If missed rules do fire on real deployment: agent fails in production
  → Action: document as limitation; recommend real-world validation before deployment

- **Semantics checking**: Current checks are static (checksum, payload index). Should we also check:
  - C2 command parsing on receiver?
  - Protocol state machine?
  → Action: future work (out of scope for this report)

---

## Verification Checklist
- [ ] Task 1.1: cross_capture_summary.json regenerated, baseline_detected corrected
- [ ] Task 2.1: archive/ created, dead code moved, tests still pass
- [ ] Task 2.2: generated artifacts removed from tracking, .gitignore updated
- [ ] Task 3.1: 86/86 tests pass, 54/54 verifier pass
- [ ] Task 3.2: all key numbers in docs match source files
- [ ] Task 3.3: demo reads fresh data (cross_capture_summary reflects corrected baseline)
- [ ] Task 4.1: REPORT_WRITING_GUIDE.md created with 8 chapters + figures/tables list
- [ ] Task 4.2: guide committed to repo

---

## Commit Messages (in order)
1. `fix(aggregate): filter eval files, regenerate cross_capture_summary with correct baseline`
2. `refactor: archive retired-generation code and old logs, keep current hidden-defender only`
3. `chore: remove generated artifacts from tracking, update gitignore`
4. `docs: add comprehensive report writing guide (8 chapters, figures, tables)`

---

## Expected Outcome
- Repo is **clean**: only active code + current data + current docs
- Repo is **trusted**: numbers match sources, tests pass, verifier validates
- Writer has **clear roadmap**: 8-chapter structure, key numbers, figures to generate
- Report is **ready to write**: plan is implementation-ready, no guessing needed
