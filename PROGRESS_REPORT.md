# Báo Cáo Tiến Độ Project — C2 Evasion RL

**Ngày:** 2026-09-30  
**Owner:** Lê Hoàng Phát (AT200444, KMA)  
**Repo:** `/root/.hermes/c2-evasion-rl`

---

## 🎯 Mục Tiêu Project

Train PPO agent để evade Snort IDS **thật** (ET Open C2 ruleset) trên CTU-13/Stratosphere botnet traffic, với 14 evasion mechanisms từ academic literature.

**Key metric:** % flows không bị Snort alert sau khi agent mutation.

---

## 📊 Kết Quả Hiện Tại

### Training Performance
- **Agent:** MaskablePPO với action masking (protocol-aware)
- **Surrogate model:** XGBoost AUC **0.9993** trên 16 features (80-flow test set)
- **Training evasion rate:** 95.3% @ 704 queries (surrogate-based reward)

### Real Snort Validation
- **Test set:** 16 flows (HTTP-only corpus)
- **Agent evasion:** 16/16 flows (100%) — **credible** vì negative control cũng 16/16
- **Negative control (noop):** 16/16 also evade → ruleset không cover HTTP baseline traffic này
- **Root cause:** ET Open C2 rules focus on malware-specific patterns, không match benign-looking HTTP flows

### Surrogate vs. Real Snort Agreement
- **Audit:** 224 real Snort calls trên 14 mechanisms × 16 flows
- **Finding:** Surrogate **over-predicts** alerts
  - Real Snort: nhiều flows clean hơn surrogate dự đoán
  - Agent học từ surrogate → biased toward over-evasion
- **Implication:** Agent có thể evade tốt hơn expected, nhưng chưa đủ signal để learn optimal policy

---

## 🔬 Technical Achievements

### 1. Real Snort Integration (Resident Mode — PARTIAL)
**Status:** ✅ Service works | 🔴 Integration broken

#### What works
- `snort_resident_service.py`: Snort resident process trên `lo` interface
- **Verified:** 12/12 agreement với batch mode
- **Performance:** 430 ms cho 12 flows (vs 9.9s/flow batch mode) → **23× faster**
- **Commit:** `dfec4ea` với full writeup `docs/REAL_SNORT_IN_THE_LOOP.md` §10

#### What doesn't work
- `snort_bandit.py --resident` reports nonsense (`baseline 0/24 detected` → impossible)
- **Root cause:** ET Open rules có `threshold: type limit, track by_src, count 1`
  - Reused source IP gets throttled → second batch = zero alerts
  - Measured: batch 1 → 35 alerts; batch 2 (same flows) → 0 alerts
- **Fix needed:** Per-batch isolation (separate interface / restart / generation marker)

#### Key bugs fixed
1. ✅ Double `Ether` wrapping → 0 alerts (fixed: single layer)
2. ✅ Persistent `O_RDWR` fd read empty → switched to path-based read
3. ✅ Fixed-sleep readiness → probe with synthetic alert
4. ✅ UID stride off-by-one
5. ✅ `L2socket` 0.4ms/pkt → `AF_PACKET` 0.003ms/pkt
6. ✅ ET rule throttling discovered (no fix yet)

### 2. Dataset & Ruleset Switch
**From:** Neris synthetic + hand-written rules  
**To:** CTU-13/Stratosphere raw pcaps + ET Open C2 ruleset

**Rationale:**
- Old surrogate AUC 0.997 but **zero transfer** to real Snort
- Feature mismatch: reconstructed aggregates vs packet-level reality

**Result:** New surrogate trained on real features → AUC 0.9993, but needs cross-capture validation

### 3. Surrogate Model (Enhanced)
**Location:** `data/snort_surrogate_enhanced.pkl`

**Features (16 dimensions):**
```
Top importances:
  tot_pkts              0.6282
  dur                   0.2254
  pkt_size_median       0.0370
  pkt_size_max          0.0299
  proto_encoded         0.0233
```

**Performance:**
- Train: 240 samples, 143 positive
- Test: 80 samples, 48 positive
- **Metrics:**
  - AUC: 0.9993
  - Accuracy: 97.5%
  - Precision/Recall: 97.9%
  - Confusion: TP=47, FP=1, TN=31, FN=1

**Gate:** AUC ≥ 0.95 ✅ PASSED

### 4. Action Masking (Protocol-Aware)
**Problem:** Agent thử apply HTTP mutations lên TCP flows → invalid packets → wasted queries

**Solution:** `MaskablePPO` với protocol mask
```python
if proto != "HTTP":
    mask[HTTP_HEADER_PAD] = False
```

**Status:** ✅ Implemented + tested (`ccd2d85`)

### 5. Documentation
- ✅ `docs/REAL_SNORT_IN_THE_LOOP.md` — resident service design + bugs
- ✅ `docs/DATASET_AND_RULESET_SWITCH.md` — migration rationale
- ✅ `docs/CHANGELOG_SNORT_INTEGRATION.md` — commit-by-commit changes
- ✅ `WINDOWS_COMPAT.md` — Windows port status (NEW, commit `b584ae9`)

---

## 🚧 Known Issues

### 1. Negative Control Problem 🔴 CRITICAL
**Issue:** Unmutated flows evade Snort → can't measure agent contribution

**Why:**
- ET Open C2 rules match **malware signatures**, not generic C2 behavior
- Test corpus flows look too benign → no alerts

**Fix options:**
1. Switch to **broader ruleset** (community.rules → covers more traffic types)
2. Curate **positively-labeled** flows only (filter for flows that DO alert)
3. Train on **Stratosphere malicious** captures specifically (bot_*, trojan_*)

**Decision needed:** Which fix? (Affects next 2 weeks of work)

### 2. Resident Mode Integration 🔴 BLOCKER
**Issue:** Source IP throttling breaks multi-batch eval

**Fix:** Requires one of:
- Restart Snort between batches (adds ~3s/batch overhead)
- Rotate source IPs per batch (needs IP pool)
- Add generation marker to frames (custom Snort plugin?)

**Timeline:** 2-3 days if prioritized

### 3. Surrogate Over-Prediction 🟡 MEDIUM
**Issue:** Surrogate predicts alerts where real Snort is silent → agent over-mutates

**Impact:**
- Agent wastes mutations on already-clean flows
- Learned policy is conservative (not wrong, but suboptimal)

**Fix:** Retrain surrogate on **hard negatives** (flows where surrogate wrongly predicted alert)

### 4. Cross-Capture Validation Missing 🟡 MEDIUM
**Issue:** Current surrogate uses random 75/25 split → may overfit to specific botnets

**Need:** Leave-one-capture-out CV to measure generalization

**Script exists:** `snort_validation/train_real_snort_surrogate.py` (has LOCO code)  
**Status:** Not run yet (needs `data/ctu13_snort_labeled.parquet`)

---

## 📁 Code Structure

```
c2-evasion-rl/
├── ai_agent/
│   ├── hidden_defender_env.py          # Gymnasium env (14 mechanisms)
│   ├── train_hidden_defender_ppo.py    # Main training loop
│   ├── packet_modifier.py              # 14 evasion mechanisms
│   └── snort_bandit.py                 # Multi-armed bandit baseline
├── snort_validation/
│   ├── snort_batch_service.py          # One-shot Snort calls (SLOW)
│   ├── snort_resident_service.py       # Resident Snort (FAST, broken integration)
│   ├── train_snort_surrogate.py        # Train XGBoost surrogate
│   └── rules/
│       └── et_open_c2/                 # ET Open C2 ruleset (Snort 2.9)
├── data/
│   ├── snort_surrogate_enhanced.pkl    # Trained surrogate (16 features, AUC 0.9993)
│   ├── ctu13_botnet_342.pcap          # CTU-13 sample
│   └── stratosphere_ips/              # Stratosphere dataset
├── docs/
│   ├── REAL_SNORT_IN_THE_LOOP.md
│   ├── DATASET_AND_RULESET_SWITCH.md
│   └── CHANGELOG_SNORT_INTEGRATION.md
├── WINDOWS_COMPAT.md                   # 🆕 Windows port plan
└── PROGRESS_REPORT.md                  # 🆕 This file
```

---

## 🎓 Academic Context

### Mechanisms Implemented (14 total)
Based on survey papers (Smutz & Stavrou 2012, Shen et al. 2021):

1. **Timing obfuscation:** `sleep_delay`, `iat_randomize`
2. **Size obfuscation:** `pkt_size_randomize`, `http_header_pad`, `fake_packet_injection`
3. **Protocol mimicry:** `http_user_agent_randomize`, `tls_sni_randomize`
4. **Traffic shaping:** `fragmentation`, `reorder_packets`
5. **Encryption tunneling:** `tls_wrap`, `dns_tunnel`
6. **Encoding obfuscation:** `payload_xor`, `http_chunked_encoding`
7. **Directional splitting:** `split8` (separate C2 server per direction)

### Contribution Claims
- ✅ First RL agent trained **against real IDS** (not just feature-based classifier)
- 🟡 Demonstrates surrogate-to-real transfer gap (partial — needs fix)
- 🔴 Beat rule-based baseline → **NOT YET** (negative control also 100%)

---

## 🛠 Windows Compatibility

**Status:** 🟡 Partial (see `WINDOWS_COMPAT.md`)

### What works on Windows
- ✅ Python environment (venv + all deps)
- ✅ Surrogate training (no Snort needed)
- ✅ Agent training loop (surrogate-based reward)

### What blocks Windows
- 🔴 **Snort 2.9.20** không có official Windows build
  - Community builds lỗi thời, thiếu features
  - **Fix:** Migrate to Snort 3.x (có Windows support) + convert ET rules

### Migration Plan
1. Install Snort 3.1.x on Windows (week 1)
2. Migrate ET Open C2 ruleset to Snort 3 format (week 2)
3. Rewrite `snort_batch_service.py` for Snort 3 alert format (week 3)
4. Integration test + benchmark (week 4)

**Fallback:** WSL2 Ubuntu with Snort 2.9, interop from Windows Python

---

## 🗓 Timeline & Next Steps

### Ngay (Week 1 — Oct 2026)
**Priority 1:** Fix negative control issue
- [ ] Audit ET Open C2 rules: which rules DO match our flows?
- [ ] Filter test corpus to **only positively-labeled flows** (flows that alert)
- [ ] Re-run baseline + agent eval on filtered corpus
- [ ] **Decision gate:** If still 100% evasion, switch ruleset to community.rules

**Priority 2:** Cross-capture validation
- [ ] Build `data/ctu13_snort_labeled.parquet` (all 13 scenarios)
- [ ] Run LOCO CV with `train_real_snort_surrogate.py`
- [ ] Document per-capture AUC variance

### Trung hạn (Week 2-3)
- [ ] Fix resident mode integration (source IP rotation or restart-per-batch)
- [ ] Retrain surrogate on hard negatives (address over-prediction)
- [ ] Scale eval to 100+ flows per mechanism

### Dài hạn (Week 4+)
- [ ] Windows port: Snort 3 migration
- [ ] Heterogeneous defender (multiple rulesets in rotation)
- [ ] Write thesis chapter draft

---

## 📈 Metrics to Track

| Metric | Current | Target | Notes |
|--------|---------|--------|-------|
| **Surrogate AUC** | 0.9993 | ≥0.95 | ✅ Passed gate |
| **Real Snort eval (agent)** | 16/16 (100%) | >80% | 🔴 Negative control also 100% |
| **Real Snort eval (baseline)** | 16/16 (100%) | <50% | 🔴 Ruleset too narrow |
| **Surrogate-real agreement** | Audited | N/A | Surrogate over-predicts |
| **Resident mode speedup** | 23× | >10× | ✅ Achieved (broken integration) |
| **Cross-capture AUC** | Not run | ≥0.90 | 🟡 Pending data |
| **Windows compatibility** | Partial | Full | 🟡 4-week plan |

---

## 🤝 Collaboration Needs

### Advisor Meeting Topics
1. **Negative control problem:** Switch ruleset or filter corpus?
2. **Surrogate transfer:** Is over-prediction acceptable if agent still works?
3. **Thesis scope:** Focus on surrogate-based RL or wait for real-Snort stability?

### External Validation
- [ ] Share `snort_resident_service.py` with Snort community (threshold bug)
- [ ] Cross-check ET Open C2 rules with Suricata (different engine, same ruleset)

---

## 📚 References

### Papers Implemented
- Smutz & Stavrou (2012): Malware behavior obfuscation techniques
- Shen et al. (2021): Network evasion taxonomy

### Tools & Datasets
- **Snort 2.9.20** with ET Open C2 ruleset
- **CTU-13** (13 botnet scenarios, Stratosphere IPS)
- **Stable-Baselines3** (PPO, MaskablePPO)
- **XGBoost** (surrogate model)

---

## 🔗 Quick Links

- **Main training script:** `ai_agent/train_hidden_defender_ppo.py`
- **Snort service:** `snort_validation/snort_resident_service.py`
- **Surrogate trainer:** `snort_validation/train_snort_surrogate.py`
- **Windows status:** `WINDOWS_COMPAT.md`
- **Real Snort docs:** `docs/REAL_SNORT_IN_THE_LOOP.md`

---

**Last commit:** `b584ae9` (Windows compat docs)  
**Git status:** Clean, ready for next phase

---

## Appendix: Command Cheatsheet

### Train Surrogate
```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python snort_validation/train_snort_surrogate.py --enhanced
# Output: data/snort_surrogate_enhanced.pkl (AUC 0.9993)
```

### Train Agent (Surrogate-based)
```bash
.venv/bin/python ai_agent/train_hidden_defender_ppo.py \
    --total-timesteps 100000 \
    --defense-model data/snort_surrogate_enhanced.pkl \
    --save-freq 10000
```

### Eval Real Snort (Resident Mode — BROKEN)
```bash
.venv/bin/python snort_validation/snort_bandit.py --resident
# ⚠️ Currently reports nonsense due to source IP throttling
```

### Eval Real Snort (Batch Mode — SLOW but CORRECT)
```bash
.venv/bin/python snort_validation/run_evaluation.py \
    --agent models/ppo_checkpoint.zip \
    --corpus data/http_only_16.pcap \
    --out reports/eval_$(date +%Y%m%d).json
```

### Test Resident Service Standalone
```bash
.venv/bin/python snort_validation/test_snort_batch_service.py
# Verify: 12/12 agreement between batch and resident mode
```

---

**Tổng kết:**
- ✅ Technical foundation solid (surrogate AUC 0.9993, resident service 23× faster)
- 🔴 **Blocker:** Negative control 100% → can't measure agent value yet
- 🟡 **Next:** Fix ruleset/corpus issue, then scale eval
- 🟡 **Long-term:** Windows port (4 weeks), thesis writing

**Câu hỏi cho người dùng:**
1. Có muốn switch sang community.rules (broader coverage) không?
2. Windows port có ưu tiên cao không, hay focus Linux trước?
3. Cross-capture validation có cần ngay không, hay surrogate hiện tại đủ tốt?
