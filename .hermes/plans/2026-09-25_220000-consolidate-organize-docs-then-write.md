# Plan: Consolidate & Organize Documentation, Then Write README + Thesis

**Goal**: Consolidate all existing reports/docs into organized `docs/` folder with clear structure, then write bilingual README + Vietnamese thesis on top of that organized foundation, and push everything to current branch.

---

## Current Context

**Existing scattered docs** (repo root):
- `FINAL_EXECUTION_REPORT.md` — latest measurements (11 data points)
- `FINAL_CORRECTED_REPORT.md` — root cause analysis, technical details
- `COMPREHENSIVE_FINAL_REPORT.md` — older comprehensive report
- `FINAL_REPORT.md` — even older report
- `README.md`, `README.vi.md` — current READMEs (outdated)
- Many other `.md` files in root (INVESTIGATION_*.md, TASK_*.md, DELIVERY.md, etc.)
- `docs/` folder exists but is sparse (has pipeline.mmd, some analysis docs)
- `snort_validation/README.md` — validation-specific docs

**Current branch**: Unknown; will be determined before push

**Goal**: Clean structure like:
```
docs/
├── README.md                    # Navigation index
├── 01-overview/
│   ├── introduction.md
│   ├── threat-model.md
│   └── project-scope.md
├── 02-technical/
│   ├── system-architecture.md
│   ├── mathematical-formulation.md
│   └── implementation-details.md
├── 03-experiments/
│   ├── datasets.md
│   ├── experimental-setup.md
│   └── results-final.md
├── 04-challenges/
│   ├── bug-1-unidirectional-flows.md
│   ├── bug-2-naive-rewrites.md
│   └── lessons-learned.md
├── 05-validation/
│   ├── snort-validation-overview.md
│   └── measurements-11-points.json (or .md)
├── 06-archive/
│   ├── old-reports/
│   │   ├── COMPREHENSIVE_FINAL_REPORT.md
│   │   ├── FINAL_REPORT.md
│   │   └── ...
│   └── investigation-notes/
│       ├── INVESTIGATION_BASELINE_PARADOX.md
│       ├── TASK_*.md
│       └── ...
└── thesis/ (or separate folder)
    ├── thesis_en.md
    └── thesis_vi.md

README.md (repo root) — bilingual quick start, links to docs/
README.vi.md (repo root) — Vietnamese quick start
```

---

## Architecture / Proposed Approach

**3-phase execution**:
1. **Phase 1: Inventory & Audit** — list all existing docs, categorize by content type
2. **Phase 2: Consolidate & Organize** — move files to `docs/`, create new summaries, delete/archive redundant files
3. **Phase 3: Write README + Thesis** — create bilingual README.md + README.vi.md at repo root; write thesis_en.md + thesis_vi.md in docs/thesis/
4. **Phase 4: Verify & Push** — test links, verify structure, commit all, push to current branch

**Key decision**: Keep repo root clean (only README.md + README.vi.md + core code dirs). All documentation lives under `docs/`.

---

## Step-by-Step Tasks

### Phase 1: Inventory & Audit (5 min total)

#### Task 1.1: List all existing docs (2 min)
**Command**:
```bash
cd /root/.hermes/c2-evasion-rl
find . -maxdepth 1 -name "*.md" -type f | sort
# Expected output:
# ./COMPREHENSIVE_FINAL_REPORT.md
# ./DELIVERY.md
# ./FINAL_CHECKLIST.md
# ./FINAL_CORRECTED_REPORT.md
# ./FINAL_EXECUTION_REPORT.md
# ./FINAL_REPORT.md
# ./FINAL_STRATOSPHERE_REPORT.md
# ./INVESTIGATION_BASELINE_PARADOX.md
# ./PACKET_LEVEL_RL_COMPLETION.md
# ./PIPELINE_SUMMARY.md
# ./README.md
# ./README.vi.md
# ./SCALE_UP_VALIDATION.md
# ./SNORT_VALIDATION_RESULTS.md
# ./TASK_5_6_COMPLETION_REPORT.md
# ./TASK6_FINAL_STATE.md
# ... (list all)
```

**Categorize output**:
```
CATEGORY: Final/Latest Reports
- FINAL_EXECUTION_REPORT.md (KEEP — latest measurements, use as primary source)
- FINAL_CORRECTED_REPORT.md (KEEP — root cause analysis)

CATEGORY: Earlier Reports (Archive)
- COMPREHENSIVE_FINAL_REPORT.md
- FINAL_REPORT.md
- FINAL_STRATOSPHERE_REPORT.md
- SNORT_VALIDATION_RESULTS.md
- ... (all older versions)

CATEGORY: Task/Investigation Notes (Archive)
- TASK_5_6_COMPLETION_REPORT.md
- TASK6_FINAL_STATE.md
- INVESTIGATION_BASELINE_PARADOX.md
- PACKET_LEVEL_RL_COMPLETION.md
- SCALE_UP_VALIDATION.md
- ... (all intermediate states)

CATEGORY: Current README
- README.md (UPDATE LATER)
- README.vi.md (UPDATE LATER)
```

**Verification**: Save categorization to `/tmp/doc_audit.txt` for reference.

#### Task 1.2: Check existing docs/ folder structure (2 min)
**Command**:
```bash
find docs/ -type f -name "*.md" | head -20
# Expected: see what's already in docs/
ls -la docs/
```

**Verification**: List all existing docs/ contents.

#### Task 1.3: Determine current git branch (1 min)
**Command**:
```bash
cd /root/.hermes/c2-evasion-rl
git branch -v
# Expected: something like "* packet-level-rl  abc1234  commit message"
git status
# Expected: "On branch <branch-name>"
```

**Record**: Current branch name for later push.

---

### Phase 2: Consolidate & Organize (25 min total)

#### Task 2.1: Create docs/ folder structure (5 min)
**Commands**:
```bash
cd /root/.hermes/c2-evasion-rl
mkdir -p docs/{01-overview,02-technical,03-experiments,04-challenges,05-validation,06-archive/old-reports,06-archive/investigation-notes,thesis}

# Verify structure
find docs -type d | sort
# Expected: all 8 subdirectories created
```

**Verification**: `ls -la docs/` shows all subdirs.

#### Task 2.2: Move & organize old reports to archive (5 min)
**Commands**:
```bash
# Archive old comprehensive/final reports
mv COMPREHENSIVE_FINAL_REPORT.md docs/06-archive/old-reports/
mv FINAL_REPORT.md docs/06-archive/old-reports/
mv FINAL_STRATOSPHERE_REPORT.md docs/06-archive/old-reports/
mv SNORT_VALIDATION_RESULTS.md docs/06-archive/old-reports/

# Archive task/investigation notes
mv TASK_*.md docs/06-archive/investigation-notes/
mv INVESTIGATION_*.md docs/06-archive/investigation-notes/
mv PACKET_LEVEL_RL_COMPLETION.md docs/06-archive/investigation-notes/
mv SCALE_UP_VALIDATION.md docs/06-archive/investigation-notes/
mv PIPELINE_SUMMARY.md docs/06-archive/investigation-notes/
mv DELIVERY.md docs/06-archive/investigation-notes/
mv FINAL_CHECKLIST.md docs/06-archive/investigation-notes/

# List what moved
ls -la docs/06-archive/old-reports/
ls -la docs/06-archive/investigation-notes/
```

**Verification**: `ls -la docs/06-archive/*/` shows moved files; repo root no longer has them.

#### Task 2.3: Move key reports to organized folders (5 min)
**Commands**:
```bash
# Move latest reports to appropriate sections
cp FINAL_EXECUTION_REPORT.md docs/03-experiments/results-final.md
cp FINAL_CORRECTED_REPORT.md docs/04-challenges/root-cause-analysis.md

# Keep README files at repo root (for now — will update later)
# Don't move them yet; we'll rewrite them

# Verify
ls docs/03-experiments/
ls docs/04-challenges/
```

**Verification**: Files are in correct subdirs.

#### Task 2.4: Create section introduction files (10 min)
**For each section, create a brief intro .md that explains what's in that folder:**

##### Task 2.4a: docs/01-overview/README.md (2 min)
```markdown
# Project Overview

This section covers the high-level project scope, threat model, and project goals.

## Contents

- **introduction.md** — Project motivation, problem statement, contributions
- **threat-model.md** — Adversarial setting, assumptions, threat actors
- **project-scope.md** — What's in scope, what's out of scope, deliverables
```

##### Task 2.4b: docs/02-technical/README.md (2 min)
```markdown
# Technical Documentation

Detailed technical design, architecture, and mathematical foundations.

## Contents

- **system-architecture.md** — Pipeline, components, data flow
- **mathematical-formulation.md** — MDP, reward function, value function
- **implementation-details.md** — Code structure, key algorithms, pseudocode
```

##### Task 2.4c: docs/03-experiments/README.md (2 min)
```markdown
# Experimental Design & Results

Datasets, methodology, and measured results.

## Contents

- **datasets.md** — CTU-13, MCFP, data cleaning, splits
- **experimental-setup.md** — Hyperparameters, hardware, reproducibility
- **results-final.md** — 11 measurements, statistical analysis, key findings
```

##### Task 2.4d: docs/04-challenges/README.md (2 min)
```markdown
# Technical Challenges & Solutions

Engineering challenges discovered during implementation and validation.

## Contents

- **bug-1-unidirectional-flows.md** — Root cause, fix, verification
- **bug-2-naive-rewrites.md** — Root cause, fix, verification
- **lessons-learned.md** — Implications for similar systems
- **root-cause-analysis.md** — Consolidated technical analysis
```

##### Task 2.4e: docs/05-validation/README.md (2 min)
```markdown
# Validation & Verification

Snort IDS validation layer, measurement methodology, and verification results.

## Contents

- **snort-validation-overview.md** — Validation layer design, resident Snort service
- **measurements-11-points.md** — Description of 11 validated measurements
```

**Verification**: All 5 README files created; each explains contents of its folder.

#### Task 2.5: Create master docs index (3 min)
**File**: `docs/README.md`

```markdown
# Documentation Index

Welcome to the C2-Evasion RL project documentation. Start here to find what you need.

## Quick Navigation

### 📘 For First-Time Readers
1. Start with `/README.md` (English quick start) or `/README.vi.md` (Tiếng Việt)
2. Then read [`01-overview/`](01-overview/) for project scope

### 🏗️ For Technical Details
- [`02-technical/`](02-technical/) — Architecture, math, implementation
- [`03-experiments/`](03-experiments/) — Datasets, setup, results
- [`04-challenges/`](04-challenges/) — How we debugged and fixed critical bugs

### 🔬 For Validation & Results
- [`05-validation/`](05-validation/) — Snort IDS validation layer
- [`03-experiments/results-final.md`](03-experiments/results-final.md) — 11 measurements (latest)

### 📚 For Academic Submission
- `/thesis_en.md` — Full English thesis (1650 lines)
- `/thesis_vi.md` — Full Vietnamese thesis (1660 lines)

### 📦 For Historical Context
- [`06-archive/old-reports/`](06-archive/old-reports/) — Earlier comprehensive reports
- [`06-archive/investigation-notes/`](06-archive/investigation-notes/) — Task notes, intermediate results

---

## Folder Structure

```
docs/
├── README.md (this file)
├── 01-overview/
│   ├── README.md — folder guide
│   ├── introduction.md
│   ├── threat-model.md
│   └── project-scope.md
├── 02-technical/
│   ├── README.md — folder guide
│   ├── system-architecture.md
│   ├── mathematical-formulation.md
│   └── implementation-details.md
├── 03-experiments/
│   ├── README.md — folder guide
│   ├── datasets.md
│   ├── experimental-setup.md
│   └── results-final.md (← LATEST MEASUREMENTS)
├── 04-challenges/
│   ├── README.md — folder guide
│   ├── bug-1-unidirectional-flows.md
│   ├── bug-2-naive-rewrites.md
│   ├── lessons-learned.md
│   └── root-cause-analysis.md
├── 05-validation/
│   ├── README.md — folder guide
│   ├── snort-validation-overview.md
│   └── measurements-11-points.md
├── 06-archive/
│   ├── old-reports/ (earlier comprehensive reports)
│   └── investigation-notes/ (task notes, intermediate results)
└── thesis/
    ├── thesis_en.md (will be created)
    └── thesis_vi.md (will be created)
```

---

## Document Purpose Guide

| Document | Purpose | Audience | Length |
|----------|---------|----------|--------|
| `/README.md` | Quick start, overview | Developers, researchers | 200 lines |
| `/README.vi.md` | Quick start (Vietnamese) | Vietnamese readers | 200 lines |
| `/thesis_en.md` | Full academic thesis | KMA submission, peer review | 1650 lines |
| `/thesis_vi.md` | Full thesis (Vietnamese) | KMA cybersecurity program | 1660 lines |
| `03-experiments/results-final.md` | Measurement details | Technical audience | Reference |
| `04-challenges/` | How we debugged | Engineers learning from pitfalls | Reference |
| `06-archive/` | Historical context | Project historians | Archive only |

---

## How to Contribute

1. **Updating results?** → Edit `03-experiments/results-final.md` and update `/README.md` references
2. **Found a bug?** → Document in `04-challenges/` before fixing
3. **Adding new section?** → Create folder in `docs/`, add README.md, link from this index
4. **Archiving old work?** → Move to `06-archive/` and note in git commit

---

**Last updated**: September 25, 2026
```

**Verification**: `wc -l docs/README.md` ≥ 100.

---

### Phase 3: Write Bilingual README + Thesis (90 min total)

#### Task 3.1: Write English README at repo root (30 min)
**File**: `README.md` (repo root, overwrite existing)

**Structure**: 7 sections + quick start (same as previous plan, but now with links to docs/)

**Key additions**:
- In each section, add links to corresponding `docs/` files for deep dives
- Example: After intro → `See [docs/01-overview/introduction.md](docs/01-overview/introduction.md) for full context`

**Verification**: `wc -l README.md` ≥ 180; `grep -c "docs/" README.md` ≥ 5 (links present).

#### Task 3.2: Write Vietnamese README at repo root (30 min)
**File**: `README.vi.md` (repo root, overwrite existing)

**Structure**: Mirror English README; all 7 sections in Vietnamese

**Verification**: `wc -l README.vi.md` ≥ 180; Vietnamese text present throughout.

#### Task 3.3: Write English thesis (30 min)
**File**: `docs/thesis/thesis_en.md`

**Structure**: Same 7 sections (intro, threat model, arch, math, setup, challenges, results)

**Note**: Can reference `docs/` files directly; e.g., `See [System Architecture](../02-technical/system-architecture.md) for component details.`

**Verification**: `wc -l docs/thesis/thesis_en.md` ≥ 1500; `git status | grep thesis_en.md` shows file.

#### Task 3.4: Write Vietnamese thesis (30 min)
**File**: `docs/thesis/thesis_vi.md`

**Structure**: Mirror English thesis; full academic Vietnamese

**Verification**: `wc -l docs/thesis/thesis_vi.md` ≥ 1500; Vietnamese throughout.

#### Task 3.5: Add thesis README (2 min)
**File**: `docs/thesis/README.md`

```markdown
# Thesis Directory

This folder contains full academic theses in English and Vietnamese.

## Contents

- **thesis_en.md** — Full English thesis (1650 lines)
  - For: Peer review, English-speaking audience
  - Sections: Intro, threat model, architecture, math, experiments, challenges, results
  - Includes: References (~30), appendices, formal notation

- **thesis_vi.md** — Full Vietnamese thesis (1660 lines)
  - For: KMA cybersecurity program submission
  - Sections: Giới thiệu, mô hình mối đe dọa, kiến trúc, toán học, thực nghiệm, thách thức, kết quả
  - Includes: Tài liệu tham khảo (~30), phụ lục, ký hiệu toán học

## How to Use

1. **For submission**: Use `thesis_vi.md` (Vietnamese thesis)
2. **For peer review**: Use `thesis_en.md` (English thesis)
3. **For quick reference**: See `/README.md` or `/README.vi.md` at repo root

## References & Links

- [System Architecture Details](../02-technical/system-architecture.md)
- [Root Cause Analysis](../04-challenges/root-cause-analysis.md)
- [Final Measurements](../03-experiments/results-final.md)
```

**Verification**: `wc -l docs/thesis/README.md` ≥ 30.

---

### Phase 4: Verify & Commit (15 min total)

#### Task 4.1: Verify link integrity (5 min)
**Commands**:
```bash
cd /root/.hermes/c2-evasion-rl

# Check all relative links in README files
grep -r "\[.*\](.*\.md)" README.md README.vi.md docs/ | while read line; do
  file=$(echo "$line" | grep -oP '\(\K[^)]+' | head -1)
  if [ -n "$file" ]; then
    if [ -e "$file" ]; then
      echo "✓ $file"
    else
      echo "✗ BROKEN: $file"
    fi
  fi
done

# Count broken links (should be 0)
grep -r "\[.*\](.*\.md)" README.md README.vi.md docs/ | grep -oP '\(\K[^)]+' | \
  while read f; do [ ! -e "$f" ] && echo "$f"; done | wc -l
# Expected: 0 (no broken links)
```

**Verification**: Output shows all links valid.

#### Task 4.2: Verify folder structure (3 min)
**Commands**:
```bash
# Check all required folders exist
for folder in 01-overview 02-technical 03-experiments 04-challenges 05-validation 06-archive thesis; do
  [ -d "docs/$folder" ] && echo "✓ docs/$folder" || echo "✗ MISSING: docs/$folder"
done

# Check key files exist
for file in README.md README.vi.md docs/README.md docs/thesis/thesis_en.md docs/thesis/thesis_vi.md; do
  [ -f "$file" ] && echo "✓ $file" || echo "✗ MISSING: $file"
done
```

**Expected output**: All ✓ (no ✗)

**Verification**: Count ✓ symbols; should be ≥12.

#### Task 4.3: Count lines in final docs (2 min)
**Commands**:
```bash
echo "README Files:"
wc -l README.md README.vi.md

echo -e "\nThesis Files:"
wc -l docs/thesis/thesis_en.md docs/thesis/thesis_vi.md

echo -e "\nKey Technical Docs:"
wc -l docs/03-experiments/results-final.md docs/04-challenges/root-cause-analysis.md
```

**Expected output**:
```
README.md: ~180 lines
README.vi.md: ~180 lines
thesis_en.md: ~1650 lines
thesis_vi.md: ~1660 lines
```

**Verification**: All files have expected line counts.

#### Task 4.4: Verify no sensitive data leaked (2 min)
**Commands**:
```bash
grep -r "password\|secret\|api_key\|token\|credential" README.md README.vi.md docs/ || echo "PASS: no credentials"
grep -r "http://\|https://" README.md README.vi.md docs/ | grep -v "github\|arxiv\|stratosphere" || echo "PASS: no suspicious URLs"
```

**Expected output**: PASS messages; no credentials or suspicious URLs.

---

#### Task 4.5: Git status & commit (3 min)
**Commands**:
```bash
cd /root/.hermes/c2-evasion-rl
git status
# Expected: Shows moved/created files

# Stage all changes
git add -A

# View what will be committed
git diff --cached --stat | head -20

# Commit with descriptive message
git commit -m "docs: Consolidate documentation structure + write bilingual README + thesis

STRUCTURE CHANGES:
- Created docs/ folder hierarchy (01-overview, 02-technical, 03-experiments, 04-challenges, 05-validation, 06-archive, thesis)
- Archived old reports to docs/06-archive/old-reports/
- Archived task notes to docs/06-archive/investigation-notes/
- Moved key reports (FINAL_EXECUTION, FINAL_CORRECTED) to docs/03-experiments/, docs/04-challenges/
- Created section README files for each docs/ subfolder
- Created master docs/README.md navigation index

NEW DOCUMENTATION:
- README.md: English quick start (180 lines, 7 sections + usage)
- README.vi.md: Vietnamese quick start (180 lines, mirrored English)
- docs/thesis/thesis_en.md: Full English thesis (1650 lines, academic depth)
- docs/thesis/thesis_vi.md: Full Vietnamese thesis (1660 lines, academic depth VI)

All documents include:
1. Introduction / Giới thiệu
2. Threat Model / Mô hình mối đe dọa
3. System Architecture / Kiến trúc hệ thống
4. Mathematical Formulation / Mô hình hóa toán học
5. Experimental Setup / Thiết lập thực nghiệm
6. Technical Challenges / Xử lý nút thắt kỹ thuật
7. Results & Evaluation / Kết quả thực nghiệm

All links verified; no broken references; no credentials leaked.
Ready for publication.
"

# Verify commit succeeded
git log --oneline | head -1
```

**Verification**: New commit appears in git log; `git status` shows "nothing to commit".

#### Task 4.6: Determine current branch & prepare to push (2 min)
**Commands**:
```bash
git branch -v
# Expected: shows current branch name (e.g., "* packet-level-rl  abc1234  commit message")

git log --oneline | head -5
# Expected: shows recent commits including new documentation commit

# Check remote
git remote -v
# Expected: shows origin URL
```

**Record**: Current branch name for push command (Task 4.7).

#### Task 4.7: Push to current branch (1 min)
**Command** (substitute `BRANCH_NAME` from Task 4.6):
```bash
git push origin BRANCH_NAME
# Example: git push origin packet-level-rl

# Verify push succeeded
git log --oneline origin/BRANCH_NAME | head -1
# Should match local HEAD
```

**Expected output**:
```
Enumerating objects: 42, done.
Counting objects: 100% (42/42), done.
Delta compression using up to 4 threads
Compressing objects: 100% (38/38), done.
Writing objects: 100% (38/38), 125 KiB, done.
Total 42 (delta 28), reused 0 (delta 0), pack-reused 0
```

**Verification**: No errors; push completed successfully.

---

## Tests & Validation

### Automated Checks
1. **Folder structure**: All 8 subdirs under docs/ exist
2. **File counts**: 
   - `docs/01-overview/`: ≥3 files
   - `docs/02-technical/`: ≥3 files
   - `docs/03-experiments/`: ≥3 files
   - Each section has README.md
3. **Link integrity**: All `[text](path)` links point to existing files
4. **Line counts**:
   - README.md ≥ 180
   - README.vi.md ≥ 180
   - thesis_en.md ≥ 1500
   - thesis_vi.md ≥ 1500
5. **No broken refs**: No 404 links in any markdown
6. **No credentials**: grep for password/token/key returns nothing

### Manual Review
1. **Navigation**: Can reader find info easily via docs/README.md?
2. **Consistency**: Do all 4 README+thesis files describe same 11 measurements?
3. **Language**: English docs are clear; Vietnamese docs are grammatically correct
4. **Completeness**: All 7 sections present in README and thesis

---

## Risks, Tradeoffs & Open Questions

### Risks
1. **Breaking existing links** — if anyone has bookmarked old doc paths, they will 404; mitigate with git history + archive folder
2. **Git commit size** — moving many files may create large commit; acceptable
3. **Branch conflicts** — if others push to same branch, may need rebase; mitigate by pushing immediately after commit

### Tradeoffs
1. **Folder structure complexity** — more folders = easier navigation but harder to maintain; accepted for readability
2. **File duplication** — thesis repeats some sections from README; accepted because thesis needs full depth while README needs brevity

### Open Questions
1. **Should we create a GitHub Pages site from docs/?** — Not in scope for this plan; can add later
2. **Do we need PDF versions of thesis?** — Not in scope; can generate later with Pandoc if needed
3. **Should repo root have only code + README?** — Yes; all technical docs in docs/; this plan achieves it

---

## Execution Notes

- **Total task count**: 16 tasks (1.1–4.7)
- **Estimated time**: ~2.5 hours
  - Phase 1: 5 min (inventory)
  - Phase 2: 25 min (consolidate)
  - Phase 3: 90 min (write docs)
  - Phase 4: 15 min (verify + push)
- **Parallelizable**: Phase 3 tasks (README EN, README VI, thesis EN, thesis VI) can run in parallel
- **Commit strategy**: 1 large commit with all changes (structure + new docs)
- **Rollback**: `git revert <commit-sha>` if needed

---

**Plan saved to**: `.hermes/plans/2026-09-25_220000-consolidate-organize-docs-then-write.md`
