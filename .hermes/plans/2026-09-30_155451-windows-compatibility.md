# Plan: Windows compatibility for the C2-evasion pipeline

**Goal:** Make the repo run end-to-end on Windows 10/11 — including real-Snort scoring —
without breaking the verified Linux path, and ship an install guide for Snort 2.9.20 on Windows.

---

## 1. Current context / assumptions

### What the project actually is (verified this session)

- Branch `packet-level-rl`, HEAD `544c4b9`, git clean, 167 commits.
- Current system: `HiddenDefenderEnv` (14 mechanisms) + `MaskablePPO`. **The bandit /
  continuous-packet-stage / resident-socket code is history** — `README.md` says so
  explicitly. Do not spend effort on `snort_resident_service.py`.
- Tests: **90 passed in 442s** (verified this session with
  `PYTHONPATH=ai_agent:snort_validation .venv/bin/python3 -m pytest tests/ -q`).
- Headline numbers: 16/16 held-out evasions under real Snort; negative control 16/16 alerted.
- Snort here is **2.9.20 GRE (Build 82)**, and it is invoked in **pcap file mode**
  (`snort -c <conf> -r <pcap> -l <logdir> -q -A fast`). It never uses live capture
  (`-i`) in the current system.

### Windows feasibility (researched, not assumed)

- Cisco publishes **`Snort_2_9_20_Installer.x64.exe`** on snort.org/downloads — the same
  2.9.20 version this project is pinned to. So Windows uses the real binary, not a
  workaround.
- **Target is Windows 11.** This makes Npcap *mandatory*, not merely recommended: WinPcap
  4.1.3 refuses to install on Windows 11 (it ships an NDIS 5.0 installer; the vendor states
  the project is unmaintained and the installer reports "This version of Windows is not
  supported"). Npcap is the only viable capture driver, so it must be installed **with the
  "Install Npcap in WinPcap API-compatible mode" option ticked** — that option is what
  provides the `wpcap.dll`/Libpcap API that Snort 2.9 links against. Snort 3's Npcap mode
  is a different mode and is *not* compatible.
- Needs the Visual C++ Redistributable.
- **File mode is the easy path**: no live-capture driver involvement, only the DAQ read
  path. This is why full Snort scoring on Windows is realistic.
- **Windows 11 may fight the driver.** Memory Integrity / Core Isolation (HVCI) plus the
  vulnerable-driver blocklist can refuse to load an older NDIS capture driver. Npcap's
  current release is signed for Windows 11, so this normally works, but if `snort` cannot
  open the pcap the first thing to try is the Npcap reinstall/upgrade path — not a code
  change. Do **not** advise disabling Memory Integrity in the guide; document the
  reinstall-and-verify route instead.

### Blocker inventory (measured by grep, not guessed)

| # | Blocker | Scope | Severity |
|---|---|---|---|
| 1 | Hardcoded `/root/.hermes/c2-evasion-rl` | **19 files** (list in Task 1) | Blocker |
| 2 | `snort.conf` + `snort_et_c2.conf` hardcode `var RULE_PATH /root/...` | 2 files | Blocker |
| 3 | Hardcoded `/tmp` scratch dirs | 13 files | Blocker |
| 4 | `subprocess.run(["which", "snort"])` — no `which` on Windows | `validate_with_snort.py:33` | Blocker |
| 5 | Bare `["snort", ...]` — PATH-dependent, 11 call sites | 11 sites | High |
| 6 | `open()` without `encoding=` — Windows defaults to cp1252, repo has UTF-8/Vietnamese | 58 sites | High |
| 7 | No `conftest.py`; tests hardcode paths | tests/ | High |
| 8 | `AF_PACKET` raw socket | `snort_resident_service.py:199` | None (history) |
| 9 | 5 `.sh` fetch scripts | snort_validation/, data/ | Medium |
| 10 | `PYTHONPATH=ai_agent:snort_validation` uses `:` (Windows needs `;`) | docs + Makefile | Medium |
| 11 | No `requirements.txt`, no `.gitattributes` | repo root | Low |

### Assumptions

- The Linux path must stay byte-for-byte behaviourally identical. All 90 tests must still
  pass on Linux after every task.
- Repo layout stays as-is; this is a portability pass, not a restructure.
- Windows target: Windows 10/11 x64, Python 3.11, PowerShell + cmd both usable.
- Data artifacts are already portable: `hidden_defender_corpus.pkl` contains **0** Linux
  absolute paths (verified). `et_open_c2.rules` contains **0** absolute paths (verified).

---

## 2. Architecture / proposed approach

Introduce one repo-root module, `c2_paths.py`, that resolves `REPO`, `REPORTS`, `MODELS`,
`DATA`, and a scratch dir from `__file__` (with an env-var override), plus a
`find_snort()` helper built on `shutil.which` that honours `$SNORT_BIN`/`%SNORT_BIN%`.
Every hardcoded path and every bare `["snort", ...]` call then routes through it.
Make the two `.conf` files path-agnostic by generating them at runtime into the scratch
dir, so `var RULE_PATH` is always correct for the machine that is running.

This is deliberately the smallest change that removes the platform coupling: one new
module, mechanical replacements at 19 + 11 + 13 sites, two generated confs, one
`conftest.py`, and an install guide. No architectural change, no behaviour change on Linux.

---

## 3. Step-by-step tasks

### Task 1 — Add `c2_paths.py` (the single source of truth)

**File:** `c2_paths.py` (new, repo root)

```python
"""Repo-relative paths and the Snort executable, resolved at import time.

Every module that needs a repo path imports from here instead of hardcoding an
absolute path, so the checkout works on Linux, macOS and Windows unchanged.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(os.environ.get("C2_REPO", Path(__file__).resolve().parent))

REPORTS = REPO / "snort_validation" / "reports"
MODELS = REPO / "models"
DATA = REPO / "data"
RULES = REPO / "snort_validation" / "rules"
ET_C2 = REPO / "snort_validation" / "et_open_c2"

SCRATCH = Path(os.environ.get("C2_SCRATCH", Path(tempfile.gettempdir()) / "c2scratch"))
SCRATCH.mkdir(parents=True, exist_ok=True)


def find_snort() -> str:
    """Absolute path to the snort binary, or a bare name as a last resort."""
    env = os.environ.get("SNORT_BIN")
    if env:
        return env
    found = shutil.which("snort")
    if found:
        return found
    if sys.platform == "win32":
        for cand in (r"C:\Snort\bin\snort.exe",
                     r"C:\Program Files (x86)\Snort\bin\snort.exe"):
            if Path(cand).is_file():
                return cand
    return "snort"          # let the caller fail with a clear OS error
```

**Verification (Linux):**

```bash
cd /root/.hermes/c2-evasion-rl
python3 -c "import c2_paths as p; print(p.REPO, p.REPORTS.exists(), p.find_snort())"
```
Expected: the repo path, `True`, and a path ending in `snort`.

**Commit:** `feat(portability): add c2_paths.py — repo-relative paths + snort discovery`

---

### Task 2 — Replace the 19 hardcoded repo paths

**Files (exact, all 19):**

```
ai_agent/hidden_defender_env.py:29            REPO = Path("/root/.hermes/c2-evasion-rl")
ai_agent/train_hidden_defender_ppo.py:26      REPO = Path("/root/.hermes/c2-evasion-rl")
ai_agent/verify_against_real_snort.py:18      REPO = Path("/root/.hermes/c2-evasion-rl")
snort_validation/baseline_hidden_defender.py:25
snort_validation/build_hidden_defender_corpus.py:28
snort_validation/detection_rate_by_framing.py:16
snort_validation/eval_all_real_snort.py:27
snort_validation/evasion_fidelity_test.py:22
snort_validation/frag3_policy_comparison.py:21
snort_validation/fragment_validity_test.py:26
snort_validation/joint_outcomes.py:6          REP = "/root/.../reports"
snort_validation/offset_sweep_test.py:22
snort_validation/parse_http_eval.py:30        inline Path(...) inside a function
snort_validation/semantics_strict_test.py:26
test_direction_1.py:7
test_direction_2.py:7
tests/test_hidden_defender_env.py:17
tests/test_mechanisms_ab.py:11
tests/test_snort_verdict_integrity.py:12
```

**Replacement rule.** For the 18 `REPO = Path("/root/...")` lines, substitute the import
form (do **not** leave a local `REPO =`):

```python
from c2_paths import REPO          # noqa: E402  (see note below)
```

Two special cases:

```python
# snort_validation/joint_outcomes.py:6
from c2_paths import REPORTS as REP

# snort_validation/parse_http_eval.py:30
from c2_paths import REPORTS
report_path = REPORTS / "eval_http_only_real_snort.json"
```

**Import-order note.** Modules under `ai_agent/`, `snort_validation/`, `tests/` rely on
`PYTHONPATH` containing the repo root. `c2_paths.py` lives at the repo root, so
`PYTHONPATH` must include `.` in addition to `ai_agent:snort_validation`. Rather than
force that on every caller, add this guard **at the top of each of the 19 files, before
the `c2_paths` import**:

```python
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent
                        if _Path(__file__).parent.name in {"ai_agent", "snort_validation", "tests"}
                        else _Path(__file__).parent))
```

This is ugly. **Better alternative, and the one to use:** add `conftest.py` (Task 7) for
tests, and for the non-test modules rely on the documented `PYTHONPATH` already being
repo-root-inclusive — change the docs to
`PYTHONPATH=.:ai_agent:snort_validation` (Task 9). Then each file needs only the plain
`from c2_paths import REPO` line. **Verify this choice by running the tests in Task 2's
verification step; if any module fails to import, fall back to the guard above.**

**Verification:**

```bash
cd /root/.hermes/c2-evasion-rl
grep -rn '"/root/\.hermes' --include="*.py" . | grep -v "\.venv"    # expect: no output
PYTHONPATH=.:ai_agent:snort_validation .venv/bin/python3 -m pytest tests/ -q
```
Expected: no matches; then `90 passed`.

**Commit:** `refactor(portability): route 19 hardcoded repo paths through c2_paths`

---

### Task 3 — Generate the two Snort confs at runtime

**Why:** `snort_validation/rules/snort.conf` and `snort_validation/et_open_c2/snort_et_c2.conf`
both hardcode `var RULE_PATH /root/.hermes/c2-evasion-rl/snort_validation/rules`. Snort
resolves `$RULE_PATH` itself, so the value must be correct on the running machine, and a
Windows path must use backslashes or forward slashes that Snort accepts.

**File:** `c2_paths.py` (append)

```python
CONF_TEMPLATES = {
    "snort_et_c2.conf": """\
var RULE_PATH {rules}
var SO_RULE_PATH $RULE_PATH
var PREPROC_RULE_PATH $RULE_PATH
var ET_C2_RULES {et_c2_rules}
var HOME_NET any
var EXTERNAL_NET any
var DNS_SERVERS 192.0.2.11
var HTTP_SERVERS any
var SMTP_SERVERS 192.0.2.10
var SQL_SERVERS any
var FTP_PORTS 21
var HTTP_PORTS 80
var HTTPS_PORTS 443
var SSH_PORTS 22
var WALLETS_START 1000
output alert_fast: alert
include $RULE_PATH/classification.config
include $RULE_PATH/reference.config
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy first detect_anomalies
preprocessor stream5_global: track_tcp yes, track_udp yes, track_icmp yes
preprocessor stream5_tcp: policy first, use_static_footprint_sizes
preprocessor stream5_udp:
include $ET_C2_RULES
""",
}


def write_conf(name: str, dest: Path | None = None) -> Path:
    """Materialise a Snort conf with this checkout's absolute paths."""
    dest = Path(dest) if dest else SCRATCH / name
    body = CONF_TEMPLATES[name].format(
        rules=RULES.as_posix(),
        et_c2_rules=(ET_C2 / "et_open_c2.rules").as_posix(),
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(body, encoding="utf-8", newline="\n")
    return dest
```

`as_posix()` is deliberate: Snort 2.9 accepts forward slashes on Windows, and it avoids
`\` escaping bugs in the template.

**Then** update the 6 conf-consuming modules to call `write_conf(...)` instead of pointing
at the committed file:

```
snort_validation/snort_batch_service.py:52        SNORT_CONF = write_conf("snort_et_c2.conf")
snort_validation/real_rules_replica.py:48         SNORT_CONF = write_conf("snort_et_c2.conf")
snort_validation/detection_rate_by_framing.py:25  CONF = write_conf("snort_et_c2.conf")
snort_validation/snort_resident_service.py:53     (history — leave alone)
snort_validation/validate_with_snort.py:211       write_conf("snort_et_c2.conf")
snort_validation/snort_query_service.py:48        write_conf("snort.conf")   # needs a second template
```

**Note:** `snort.conf` (the `rules/` one) has a *different* body — it includes
`$RULE_PATH/botnet-behavior.rules`. Add a matching `"snort.conf"` template with
`include $RULE_PATH/botnet-behavior.rules` and no `$ET_C2_RULES`. Copy the exact body from
the committed file; do not retype it.

**Verification:**

```bash
cd /root/.hermes/c2-evasion-rl
PYTHONPATH=.:ai_agent:snort_validation .venv/bin/python3 -c "
import c2_paths as p
c = p.write_conf('snort_et_c2.conf')
print(c)
print(c.read_text(encoding='utf-8')[:200])
"
# then prove Snort still parses it and the test that depends on it passes
PYTHONPATH=.:ai_agent:snort_validation .venv/bin/python3 -m pytest \
  snort_validation/test_snort_batch_service.py -q
```
Expected: the conf path under the scratch dir, a body starting `var RULE_PATH /root/...`,
and the batch-service tests passing.

**Commit:** `feat(portability): generate Snort confs at runtime for any checkout path`

---

### Task 4 — Resolve the Snort binary instead of assuming PATH

**Files (11 bare-`"snort"` call sites):** replace `["snort", ...]` with
`[find_snort(), ...]`, importing `from c2_paths import find_snort`.

```
snort_validation/real_rules_replica.py:246
snort_validation/snort_batch_service.py:176, 229, 325
snort_validation/probe_overlap_evasion.py:51
snort_validation/snort_query_service.py:227
snort_validation/aggressive_snort_replica.py:216
snort_validation/label_real_flows_with_snort.py:78
snort_validation/validate_real_features_vs_snort.py:150
snort_validation/test_snort_batch_service.py:76
snort_validation/test_stratosphere_sweep.py:127
```

**Also fix the `which` call** — `snort_validation/validate_with_snort.py:33`:

```python
# before
result = subprocess.run(['which', 'snort'], capture_output=True)
# after
found = find_snort()
result = type("R", (), {"returncode": 0 if found != "snort" else 1,
                        "stdout": (found + "\n").encode()})()
```

Simpler and preferable — replace the whole block with:

```python
from c2_paths import find_snort
snort_path = find_snort()
if snort_path == "snort":
    print("[!] snort not found on PATH; set SNORT_BIN to its full path")
```

**Verification:**

```bash
cd /root/.hermes/c2-evasion-rl
grep -rn '\["snort"' --include="*.py" . | grep -v "\.venv"    # expect: no output
PYTHONPATH=.:ai_agent:snort_validation .venv/bin/python3 -m pytest tests/ -q
```
Expected: no matches; `90 passed`.

**Commit:** `refactor(portability): resolve snort via shutil.which, not bare PATH lookup`

---

### Task 5 — Replace hardcoded `/tmp` scratch dirs

**Files (13):** `ai_agent/ablate_actions.py`, `ai_agent/eval_real_snort_agent.py`,
`ai_agent/hidden_defender_env.py`, `ai_agent/train_real_snort_agent.py`,
`ai_agent/verify_real_env.py`, `snort_validation/aggressive_snort_replica.py`,
`snort_validation/build_et_open_c2_ruleset.py`, `snort_validation/detection_rate_by_framing.py`,
`snort_validation/eval_policy_horizon.py`, `snort_validation/frag3_policy_comparison.py`,
`snort_validation/snort_query_service.py`, `snort_validation/test_snort_batch_service.py`,
`snort_validation/verify_snort_replica.py`.

**Rule:** any `Path("/tmp/...")` or `"/tmp/..."` default becomes a `c2_paths.SCRATCH`
subdirectory:

```python
from c2_paths import SCRATCH
workdir = Path(workdir or (SCRATCH / "snort_query"))
```

For `/tmp/etopen/rules` in `build_et_open_c2_ruleset.py:43`, keep it as an overridable
default but make it scratch-relative:

```python
ET_DIR = Path(sys.argv[1] if len(sys.argv) > 1 else (SCRATCH / "etopen" / "rules"))
```

**Also:** the docstring/comment mentions of `/tmp/jev-poc/venv/bin/python` in
`train_real_snort_agent.py`, `verify_real_env.py`, `ablate_actions.py`,
`eval_real_snort_agent.py`, `eval_policy_horizon.py`, `verify_snort_replica.py`,
`test_snort_batch_service.py` are stale — that venv is the *old* one. Replace with
`python` and a note that the repo-local `.venv` is the documented interpreter.

**Verification:**

```bash
cd /root/.hermes/c2-evasion-rl
grep -rn '/tmp/' --include="*.py" . | grep -v "\.venv" | grep -v '"""'   # expect: no output
PYTHONPATH=.:ai_agent:snort_validation .venv/bin/python3 -m pytest tests/ -q
```

**Commit:** `refactor(portability): scratch dirs via c2_paths.SCRATCH instead of /tmp`

---

### Task 6 — Add `encoding="utf-8"` to file I/O

**Why:** Windows defaults `open()` to the ANSI code page (cp1252 on most machines). The
repo reads/writes UTF-8 and contains Vietnamese text, so unqualified `open()` corrupts or
crashes there. 58 sites.

**Command to list them:**

```bash
cd /root/.hermes/c2-evasion-rl
grep -rn "open(" --include="*.py" ai_agent/ snort_validation/ controls/ tests/ \
  | grep -v "encoding=" | grep -v "\.venv"
```

**Rule:** add `encoding="utf-8"` to every text-mode `open()`, `Path.read_text()`,
`Path.write_text()`, and `json.load(open(...))`/`json.dump(..., open(...))`. For writes
that should be LF on Windows (the generated confs), also pass `newline="\n"`.

**Do not** touch binary-mode opens (`"rb"`, `"wb"`) — they take no encoding.

**Verification:**

```bash
cd /root/.hermes/c2-evasion-rl
grep -rn "open(" --include="*.py" ai_agent/ snort_validation/ controls/ tests/ \
  | grep -v "encoding=" | grep -v '"rb"' | grep -v '"wb"' | grep -v "\.venv"
PYTHONPATH=.:ai_agent:snort_validation .venv/bin/python3 -m pytest tests/ -q
```
Expected: only binary-mode opens remain; `90 passed`.

**Commit:** `fix(portability): explicit utf-8 encoding on text file I/O`

---

### Task 7 — Add `conftest.py` so tests work from any cwd

**File:** `conftest.py` (new, repo root)

```python
"""Make the repo root importable so tests run from any working directory."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for p in (ROOT, ROOT / "ai_agent", ROOT / "snort_validation"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
```

**Verification — this is the task that proves the portability work:**

```bash
cd /root/.hermes/c2-evasion-rl
.venv/bin/python3 -m pytest tests/ -q          # NO PYTHONPATH set
```
Expected: `90 passed`. If it fails on imports, Tasks 1–5 missed a site.

**Commit:** `test(portability): conftest.py — tests run without PYTHONPATH`

---

### Task 8 — Add `requirements.txt` and `.gitattributes`

**File:** `requirements.txt` (new) — mirror `environment.yml`'s measured pins:

```
numpy>=2.0,<3.0
pandas>=2.2
scipy>=1.11
scikit-learn>=1.4
pyarrow>=15.0
joblib>=1.3
xgboost>=2.0
scapy==2.7.0
stable-baselines3==2.9.0
sb3-contrib==2.9.0
gymnasium==1.3.0
pytest==9.1.1
```

Plus, in the guide, the torch line:
`pip install "torch==2.14.*+cpu" --index-url https://download.pytorch.org/whl/cpu`

**File:** `.gitattributes` (new)

```
* text=auto eol=lf
*.pcap binary
*.pkl binary
*.zip binary
*.pdf binary
*.rules text eol=lf
*.conf text eol=lf
```

**Why it matters:** without this, a Windows checkout converts `.rules`/`.conf` to CRLF.
Snort 2.9's config parser is not reliably CRLF-tolerant across all directives, and the
`alert_fast` output parsing in `snort_batch_service.py` splits on newlines. Pinning LF
removes a whole class of Windows-only breakage.

**Verification:**

```bash
cd /root/.hermes/c2-evasion-rl
git add --renormalize . && git status --short | head
python3 -c "print(open('requirements.txt', encoding='utf-8').read().count(chr(10)), 'lines')"
```

**Commit:** `chore(portability): requirements.txt + .gitattributes (pin LF)`

---

### Task 9 — Windows install and usage guide

**File:** `docs/WINDOWS_SETUP.md` (new)

Must contain, with exact commands:

1. **Python 3.11** — from python.org, tick "Add python.exe to PATH". Verify:
   `python --version` → `Python 3.11.x`.
2. **Visual C++ Redistributable** — link to the x64 installer; required by Snort 2.9.
   (Link: `https://aka.ms/vs/17/release/vc_redist.x64.exe`.)
3. **Npcap (mandatory on Windows 11)** — link to npcap.com. Run the installer **as
   administrator** and **tick "Install Npcap in WinPcap API-compatible mode"**.
   State plainly: *WinPcap 4.1.3 does not install on Windows 11 — Npcap in
   WinPcap-compatible mode is the only supported capture driver here.* That mode is what
   gives Snort 2.9 the `wpcap.dll` / Libpcap API it links against. Verify the driver is
   present:
   ```
   sc query npcap
   ```
   Expected: `STATE : 4 RUNNING`.
4. **Snort 2.9.20** — `Snort_2_9_20_Installer.x64.exe` from snort.org/downloads. Install
   to the default `C:\Snort`. Verify:
   `& "C:\Snort\bin\snort.exe" -V` → `Version 2.9.20 GRE (Build 82)`.
   Then prove file mode actually reads a pcap (this is the step that catches a bad Npcap
   install):
   ```
   & "C:\Snort\bin\snort.exe" -c <generated conf> -r <some.pcap> -l . -q -A fast
   ```
   Expected: exit 0 and an `alert` file created (even if empty). A DAQ/`wpcap` error here
   means Npcap is missing or not in compatible mode — go back to step 3.
5. **Set `SNORT_BIN`**:
   `setx SNORT_BIN "C:\Snort\bin\snort.exe"` (new shells pick it up).
   PowerShell current-session alternative: `$env:SNORT_BIN="C:\Snort\bin\snort.exe"`.
6. **Clone + venv** — clone to a **short path** (Windows 11 long-path limits bite on the
   15 MB rules file and deep checkouts). Recommended: `C:\c2rl`.
   ```
   git clone <url> C:\c2rl
   cd C:\c2rl
   python -m venv .venv
   .venv\Scripts\python -m pip install --upgrade pip
   .venv\Scripts\pip install -r requirements.txt
   .venv\Scripts\pip install "torch==2.14.*+cpu" --index-url https://download.pytorch.org/whl/cpu
   ```
7. **Run the tests**: `.venv\Scripts\python -m pytest tests\ -q` → `90 passed`.
   Note that no `PYTHONPATH` is needed thanks to `conftest.py`.
8. **Run the headline eval**:
   ```
   .venv\Scripts\python ai_agent\eval_masked_ppo_test.py --real-snort
   ```
   Expected: 16/16.
9. **PowerShell vs cmd note** — `$env:SNORT_BIN="..."` for the current session in
   PowerShell; `set SNORT_BIN=...` in cmd. `setx` is persistent but only affects *new*
   shells.
10. **Troubleshooting table** (Windows 11 specifics):
    - `snort not found` → `SNORT_BIN` unset or wrong; check step 4.
    - `DAQ` / `wpcap.dll` / "not located" errors → Npcap missing, or installed without
      WinPcap-compatible mode. Reinstall Npcap, tick the box, reboot.
    - `sc query npcap` not RUNNING → driver blocked. Check Windows Security → Device
      Security → Core isolation. Prefer upgrading Npcap to the current signed release;
      do not disable Memory Integrity as a first resort.
    - `MSVCP140.dll missing` → install the VC++ Redistributable (step 2).
    - `UnicodeDecodeError` → a file I/O site missed Task 6.
    - Snort parses conf but finds no rules → Task 3 conf not regenerated; delete the
      scratch conf and re-run.
    - `FileNotFoundError` with a very long path → clone shorter (`C:\c2rl`).

11. **Data note**: the pcaps/corpus are not all in git (`.gitignore` excludes large data).
    Document which artifacts must be fetched (the `.sh` scripts are bash-only — give the
    equivalent `curl`/`Invoke-WebRequest` commands, or note that WSL/Git-Bash can run them).

**Verification:** read the file back and confirm every command block is present:

```bash
cd /root/.hermes/c2-evasion-rl
grep -c '```' docs/WINDOWS_SETUP.md
grep -n "WinPcap API-compatible\|SNORT_BIN\|Snort_2_9_20_Installer\|90 passed" docs/WINDOWS_SETUP.md
```

**Commit:** `docs(portability): Windows 10/11 setup guide incl. Snort 2.9.20`

---

### Task 10 — Update the READMEs and Makefile

**Files:** `README.md`, `README.vi.md`, `Makefile` (if it sets `PYTHONPATH`).

- Change every `PYTHONPATH=ai_agent:snort_validation` to
  `PYTHONPATH=.:ai_agent:snort_validation`, and note that `conftest.py` means tests need
  no `PYTHONPATH` at all.
- Add a short "Platform support" section to both READMEs linking `docs/WINDOWS_SETUP.md`,
  stating Linux is the reference platform and Windows is supported for the full path
  including real-Snort scoring.
- Keep the two READMEs in sync (they are translations of each other).

**Verification:**

```bash
cd /root/.hermes/c2-evasion-rl
grep -rn "PYTHONPATH=ai_agent:snort_validation" README.md README.vi.md Makefile
```
Expected: no output (all updated).

**Commit:** `docs(portability): document Windows support and the conftest PYTHONPATH change`

---

### Task 11 — Prove it end-to-end on Linux (the regression gate)

**Why:** Windows cannot be tested from here. The guarantee we *can* give is that the
portability refactor changed nothing on the reference platform.

```bash
cd /root/.hermes/c2-evasion-rl
git log --oneline -12
.venv/bin/python3 -m pytest tests/ -q                    # 90 passed
PYTHONPATH=.:ai_agent:snort_validation .venv/bin/python3 \
  ai_agent/eval_masked_ppo_test.py --real-snort          # 16/16
PYTHONPATH=.:ai_agent:snort_validation .venv/bin/python3 \
  controls/control_noop_real_snort.py                    # 16/16 alerted
```

Expected: 90 passed; `valid_evasion_pct: 100.0`; control `alerted: 16`.
The 16/16 must be reproduced with the **real** binary, not the surrogate.

**Commit:** none (verification only) — but record the numbers in
`docs/03-experiments/results-final.md` under a "post-portability regression" heading.

---

## 4. Tests / validation

Per-task TDD is not meaningful for a mechanical refactor (there is no new behaviour to
drive out), so the discipline is: **the existing 90 tests are the spec, and they must pass
after every single task.** Run them before committing each task, not just at the end.

The two genuinely new tests to add:

**`tests/test_paths_portable.py`** (new)

```python
"""The checkout must not depend on where it lives."""
from pathlib import Path
import c2_paths


def test_no_hardcoded_repo_path_in_python_sources():
    repo = Path(__file__).resolve().parent.parent
    offenders = []
    for p in repo.rglob("*.py"):
        if ".venv" in p.parts:
            continue
        if '"/root/.hermes' in p.read_text(encoding="utf-8", errors="ignore"):
            offenders.append(str(p.relative_to(repo)))
    assert offenders == []


def test_conf_is_generated_with_real_paths(tmp_path):
    conf = c2_paths.write_conf("snort_et_c2.conf", dest=tmp_path / "c.conf")
    body = conf.read_text(encoding="utf-8")
    assert c2_paths.RULES.as_posix() in body
    assert (c2_paths.ET_C2 / "et_open_c2.rules").as_posix() in body
    assert "/root/.hermes" not in body or c2_paths.REPO.as_posix().startswith("/root/.hermes")


def test_find_snort_honours_env(monkeypatch):
    monkeypatch.setenv("SNORT_BIN", "/fake/snort")
    assert c2_paths.find_snort() == "/fake/snort"
```

Run: `.venv/bin/python3 -m pytest tests/test_paths_portable.py -q` → `3 passed`.

**A CRLF check** in the same file:

```python
def test_committed_rules_use_lf():
    repo = Path(__file__).resolve().parent.parent
    for pat in ("snort_validation/rules/*.rules", "snort_validation/et_open_c2/*.rules",
                "snort_validation/rules/*.conf"):
        for f in repo.glob(pat):
            assert b"\r\n" not in f.read_bytes(), f
```

---

## 5. Risks, tradeoffs, and open questions

### Risks

1. **Path-length limit on Windows 11.** `snort_validation/et_open_c2/et_open_c2.rules` is
   15 MB with very long rule lines; Snort on Windows has historically had issues with deep
   paths. Mitigation: `C2_SCRATCH` defaults to the system temp dir; the guide instructs
   cloning to `C:\c2rl`. Windows 11 long-path support can also be enabled via the
   `LongPathsEnabled` registry value, but the guide should not require it.
2. **`subprocess` + `text=True`** decodes with the locale encoding. If a Snort message
   contains non-ASCII, Windows may raise `UnicodeDecodeError`. Mitigation: pass
   `encoding="utf-8", errors="replace"` on the Snort subprocess calls. **Not yet applied —
   decide during Task 4.**
3. **CRLF in `.rules`** can break Snort's config parser. `.gitattributes` (Task 8) is the
   fix, but any existing Windows clone needs `git rm --cached -r . && git reset --hard`.
4. **`as_posix()` paths in the conf.** Snort 2.9 on Windows generally accepts forward
   slashes, but this is the single most likely Windows-specific failure. If it fails, the
   fallback is `str(path)` with backslashes, which needs `\` doubling in the template.
5. **`.sh` scripts** cannot run natively. Either document Git-Bash/WSL, or port the 5
   scripts to Python. **Recommend: document, do not port** — they are one-time data fetches
   and porting them is not on the critical path.
6. **Snort 2.9.20 on Windows is old.** It is the version the results were measured on, so
   it is the *correct* choice for reproducibility, but it may need
   compatibility-mode tweaks on Windows 11.

### Tradeoffs

- **Runtime-generated confs vs. committed confs.** Generating is correct (paths must match
  the machine) but means the conf is no longer a reviewable artifact and is re-created on
  every import. The committed files stay in the repo as the template source of truth.
- **`c2_paths.py` at repo root** requires `PYTHONPATH` to include `.`. The alternative — a
  proper `pyproject.toml` with `pip install -e .` — is cleaner but a bigger change and
  would alter how every documented command runs. Deliberately deferred (YAGNI).

### Open questions (need the user)

1. ~~Which Windows version~~ — **answered: Windows 11.** Npcap is therefore mandatory
   (WinPcap 4.1.3 will not install); see §1 and Task 9 step 3.
2. **Is the Windows machine the same one that will produce report numbers?** If yes, the
   portability pass needs a full result re-run, not just the test suite. If it is only for
   development/reading, Task 11's Linux gate is sufficient.
3. **Should the `.sh` scripts be ported to Python** for a no-bash setup, or is Git-Bash
   acceptable?
4. **Report language/format** — the earlier `docs/thesis/` files are stale (they describe
   the superseded bandit system: grep for `16/16`, `split8`, `MaskablePPO`,
   `hidden_defender` returns **0 matches**). Separately from Windows support, the thesis
   needs rewriting against the current system. Confirm whether that is in scope now or
   after the portability work lands.

---

## 6. Ordering and estimated shape

Tasks 1→2→3→4→5 are the code refactor (each independently testable, each its own commit).
Tasks 6→7→8 are hygiene. Task 9 is the guide. Task 10 is docs. Task 11 is the gate.

The high-risk work is Tasks 2–4 (touching the live scoring path). Everything else is
additive and cannot regress the Linux behaviour. Task 7 (`conftest.py`) is the milestone
that proves the refactor is complete: the suite passing with no `PYTHONPATH` means no
module depends on an absolute path any more.
