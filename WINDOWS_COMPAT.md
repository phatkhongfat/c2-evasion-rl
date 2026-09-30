# Windows Compatibility Status

**Ngày:** 2026-09-30  
**Trạng thái:** 🚧 Đang triển khai

## Tổng Quan

Project hiện được thiết kế cho Linux (Ubuntu 22.04+). Document này track tiến độ port sang Windows 10/11.

---

## 1️⃣ Môi Trường Python ✅ DONE

### Trạng thái
- ✅ Tất cả dependencies Python là cross-platform
- ✅ Virtual environment `.venv` tương thích Windows
- ✅ Training pipeline không dùng Linux-specific syscalls

### Dependencies đã verify
```
gymnasium==0.29.1
stable-baselines3==2.1.0
sb3-contrib==2.1.0
torch>=2.0.0
scapy==2.5.0
xgboost==2.0.3
pandas==2.1.3
numpy==1.24.3
scikit-learn==1.3.2
joblib==1.3.2
```

### Cài đặt trên Windows
```powershell
# PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## 2️⃣ Snort IDS Integration 🔴 BLOCKER

### Vấn đề hiện tại
- Snort 2.9.20 không có Windows build chính thức từ 2020
- Community builds (WinPcap-based) lỗi thời, không hỗ trợ `--pcap-dir`, `--pcap-reset`
- Snort 3.x có Windows support, nhưng ruleset ET Open C2 dành cho Snort 2.x

### Lộ trình giải quyết

#### Option A: Snort 3.x trên Windows (PREFERRED)
1. **Cài Snort 3.1.x** (có official Windows build)
   - Download: https://www.snort.org/downloads
   - Yêu cầu: Visual C++ Redistributable 2019+
   
2. **Migrate ruleset ET Open C2 → Snort 3 format**
   ```bash
   snort2lua -c et_open_c2/snort_et_c2.conf -o snort3_et_c2.lua
   ```
   - Cần test validate rules không bị mất coverage
   
3. **Update `snort_batch_service.py` và `snort_resident_service.py`**
   - Snort 3 CLI khác: `--pcap-dir` → `-r pcap_dir/`
   - Alert format: unified2 → JSON hoặc CSV
   - Cần wrapper mới để parse

#### Option B: Docker/WSL2 (FALLBACK)
- **WSL2 Ubuntu** với Snort 2.9.20 native Linux
- Code Python chạy Windows, gọi Snort qua WSL interop
- Cần overhead: file path translation (`\\wsl$\Ubuntu\...`)

#### Option C: Surrogate-only mode (TRAINING ONLY)
- Training không cần Snort thật (chỉ cần surrogate model)
- Evaluation + validation vẫn cần Snort → yêu cầu Linux VM hoặc SSH remote

### Timeline
- [ ] **Week 1:** Cài Snort 3 trên Windows test VM, verify pcap replay works
- [ ] **Week 2:** Migrate ET Open ruleset, diff coverage vs Snort 2
- [ ] **Week 3:** Rewrite `snort_batch_service.py` cho Snort 3 alert format
- [ ] **Week 4:** Integration test với real PPO eval

---

## 3️⃣ Hardcoded Paths 🟡 IN PROGRESS

### Files cần sửa (19 files)
```python
# BAD (Linux absolute path)
REPO = Path("/root/.hermes/c2-evasion-rl")

# GOOD (relative to script)
REPO = Path(__file__).resolve().parent.parent
```

#### Priority 1 — Core training/eval
- [x] `ai_agent/train_agent.py`
- [x] `ai_agent/hidden_defender_env.py`
- [ ] `ai_agent/train_hidden_defender_ppo.py`
- [ ] `ai_agent/eval_all_real_snort.py`
- [ ] `snort_validation/run_evaluation.py`

#### Priority 2 — Data pipeline
- [ ] `snort_validation/build_hidden_defender_corpus.py`
- [ ] `snort_validation/extract_ctu13_real_features.py`
- [ ] `snort_validation/label_real_flows_with_snort.py`
- [ ] `snort_validation/train_real_snort_surrogate.py`

#### Priority 3 — Tests
- [ ] `snort_validation/test_snort_batch_service.py`
- [ ] `snort_validation/_diag_*.py` (9 files)

### Snort config files
```bash
# snort_validation/rules/snort.conf
var RULE_PATH /root/.hermes/c2-evasion-rl/snort_validation/rules/et_open_c2
```
→ Cần environment variable `SNORT_RULE_PATH` hoặc relative path

---

## 4️⃣ Temp Directory `/tmp` 🟡 IN PROGRESS

### Files affected (13 files)
```python
# BAD
scratch = Path("/tmp/snort_scratch")

# GOOD
import tempfile
scratch = Path(tempfile.gettempdir()) / "snort_scratch"
```

#### Auto-detect pattern
```python
def get_scratch_dir():
    """Cross-platform temp dir for Snort workdir."""
    if sys.platform == "win32":
        return Path(os.environ.get("TEMP", "C:\\Temp")) / "c2_snort"
    else:
        return Path("/tmp/c2_snort")
```

---

## 5️⃣ Shell Scripts → Python 🟡 IN PROGRESS

### Scripts cần rewrite
1. **`fetch_stratosphere.sh`** → `fetch_stratosphere.py`
   - `wget` → `requests` hoặc `urllib`
   
2. **`extract_stratosphere.sh`** → `extract_stratosphere.py`
   - `tar` / `gunzip` → `tarfile` module
   
3. **`snort_validation/build_et_open_c2_ruleset.sh`**
   - `curl` + `grep` → Python `requests` + regex

---

## 6️⃣ File Encoding 🟡 IN PROGRESS

### Issue
58 chỗ `open()` không có `encoding="utf-8"` → Windows mặc định `cp1252` sẽ crash với:
- Tiếng Việt trong docs
- UTF-8 JSON reports

### Fix pattern
```python
# BAD
with open("report.json", "w") as f:

# GOOD
with open("report.json", "w", encoding="utf-8") as f:
```

### Auto-fix script
```bash
# Tìm tất cả open() không có encoding
rg 'open\([^)]+\)' --type py | grep -v encoding= | grep -v 'rb\|wb'
```

---

## 7️⃣ Platform-specific Code 🟡 IN PROGRESS

### `snort_resident_service.py` — AF_PACKET
```python
# Linux-only raw socket
from socket import AF_PACKET, SOCK_RAW
s = socket.socket(AF_PACKET, SOCK_RAW)
```
→ **Windows:** Cần WinPcap/Npcap, không có `AF_PACKET`  
→ **Giải pháp:** Scapy abstraction (`sendp()` tự detect platform)

### `subprocess.run(["which", "snort"])`
```python
# BAD
subprocess.run(["which", "snort"])

# GOOD
import shutil
snort_path = shutil.which("snort")
if not snort_path:
    raise FileNotFoundError("Snort not found in PATH")
```

---

## 8️⃣ PYTHONPATH Syntax 🟢 READY

### Linux
```bash
export PYTHONPATH=ai_agent:snort_validation
```

### Windows (PowerShell)
```powershell
$env:PYTHONPATH = "ai_agent;snort_validation"
```

### Cross-platform (trong code)
```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "ai_agent"))
sys.path.insert(0, str(Path(__file__).parent / "snort_validation"))
```

---

## 9️⃣ pytest Discovery 🟢 READY

### Current issue
Tests hardcode paths → discovery fails on Windows

### Fix: Add `conftest.py`
```python
# conftest.py (root repo)
import sys
from pathlib import Path

REPO = Path(__file__).parent
sys.path.insert(0, str(REPO / "ai_agent"))
sys.path.insert(0, str(REPO / "snort_validation"))
```

---

## 🔟 Documentation Additions 🟡 IN PROGRESS

### Cần thêm vào README.md

#### Snort Installation (Windows)
```markdown
### Windows Setup

1. **Install Snort 3.x**
   - Download: https://www.snort.org/downloads#snort3-downloads
   - Install Visual C++ 2019+ Redistributable
   - Add `C:\Snort\bin` to PATH

2. **Install Npcap** (thay WinPcap)
   - https://npcap.com/
   - Check "WinPcap compatibility mode"

3. **Verify**
   ```powershell
   snort --version
   # Should show: Snort++ 3.1.x.x
   ```
```

#### Virtual Environment
```markdown
### Windows
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
```

---

## Timeline Tổng Hợp

| Tuần | Nhiệm vụ | Owner | Status |
|------|----------|-------|--------|
| W1 | ✅ Python env + surrogate training work trên Windows | Agent | DONE |
| W1 | 🟡 Fix 19 hardcoded paths (Priority 1 files) | Agent | 2/5 done |
| W1 | 🔴 Snort 3 install + test trên Windows VM | User | BLOCKED |
| W2 | 🔴 Migrate ET Open C2 ruleset → Snort 3 | Agent | WAITING |
| W2 | 🟡 Rewrite 5 shell scripts → Python | Agent | 0/5 |
| W3 | 🔴 Snort batch/resident service cho Snort 3 alert format | Agent | WAITING |
| W3 | 🟡 Add encoding="utf-8" to 58 open() calls | Agent | TODO |
| W4 | 🔴 Integration test: PPO eval với real Snort trên Windows | Both | WAITING |
| W4 | 📝 Update README + Windows setup docs | Agent | TODO |

---

## Rủi Ro

### 🔴 HIGH: Snort 3 ruleset compatibility
- **Risk:** ET Open C2 rules không hoàn toàn tương thích với Snort 3 syntax
- **Mitigation:** Manual test 20 sample flows, so sánh alert count Snort 2 vs 3
- **Fallback:** Giữ Snort 2 cho eval, chỉ train surrogate trên Windows

### 🟡 MEDIUM: Performance overhead
- **Risk:** Snort 3 trên Windows có thể chậm hơn Linux (WinPcap driver)
- **Mitigation:** Benchmark resident mode latency, chấp nhận +50% nếu < 1s/batch
- **Fallback:** Remote eval via SSH Linux server

### 🟢 LOW: Path encoding issues
- **Risk:** Windows path có thể chứa tiếng Việt → UTF-8 encoding breaks
- **Mitigation:** Force `encoding="utf-8"` everywhere, test với path `C:\Users\Hoàng Phát\`

---

## Checklist Trước Khi Merge

- [ ] `pytest` pass 100% trên Windows 11
- [ ] `pytest` vẫn pass trên Linux (regression test)
- [ ] Snort 3 eval match Snort 2 baseline (±5% alert count)
- [ ] README có Windows install instructions
- [ ] CI/CD thêm Windows runner (GitHub Actions)

---

## Contact

**Owner:** Lê Hoàng Phát (AT200444)  
**Repo:** `/root/.hermes/c2-evasion-rl`  
**Last Update:** 2026-09-30 (sau khi train surrogate enhanced AUC 0.9993)
