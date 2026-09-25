# Plan: Consolidate & Organize Documentation, Then Write README + LaTeX Thesis

**Goal**: Consolidate all existing reports/docs into organized `docs/` folder with clear structure, then write bilingual README (Markdown) at repo root + Vietnamese thesis in LaTeX, and push everything to current branch.

---

## Current Context

**Existing scattered docs** (repo root): 24 .md files
- `FINAL_EXECUTION_REPORT.md` — latest measurements (11 data points)
- `FINAL_CORRECTED_REPORT.md` — root cause analysis
- Many others (task notes, investigation, old reports)

**Current branch**: Unknown; will be determined before push

**LaTeX decision**: 
- Thesis will be compiled `.tex` files (Vietnamese thesis primary)
- Can generate PDF via `pdflatex thesis_vi.tex` or online compiler
- English thesis also LaTeX for consistency

**Goal structure**:
```
docs/
├── README.md                    # Navigation index
├── 01-overview/ ... 06-archive/ # Same as before (5 folders of .md docs)
└── thesis/
    ├── README.md               # Guide to thesis files
    ├── thesis_vi.tex           # Vietnamese thesis (LaTeX)
    ├── thesis_en.tex           # English thesis (LaTeX)
    ├── preamble.tex            # Shared LaTeX preamble (packages, macros)
    ├── Makefile                # Build PDF: make thesis_vi, make thesis_en
    └── build/                  # Generated PDFs (gitignore)
        ├── thesis_vi.pdf
        └── thesis_en.pdf

README.md (repo root) — bilingual quick start, links to docs/
README.vi.md (repo root) — Vietnamese quick start
```

---

## Architecture / Proposed Approach

**4-phase execution** (same as before, but Phase 3 adapted for LaTeX):
1. **Phase 1: Inventory & Audit** — list existing docs (5 min)
2. **Phase 2: Consolidate & Organize** — move to docs/, create navigation (25 min)
3. **Phase 3: Write Bilingual README + LaTeX Thesis** — README .md files (60 min) + thesis .tex files (90 min)
4. **Phase 4: Verify & Push** — test, commit, push (20 min)

**Key change**: Phase 3 now has 2 parts:
- Part A: README files (same as before)
- Part B: LaTeX thesis with `preamble.tex` shared file

**Total time**: ~3 hours (added 30 min for LaTeX setup + Makefile)

---

## Step-by-Step Tasks

### Phase 1: Inventory & Audit (5 min total)
[Same as before — Tasks 1.1, 1.2, 1.3]

---

### Phase 2: Consolidate & Organize (25 min total)
[Same as before — Tasks 2.1–2.5]

---

### Phase 3: Write Bilingual README + LaTeX Thesis (150 min total)

#### Part A: README Files (60 min)

**Task 3.1: Write English README at repo root** (30 min)
- Same as before: 7 sections, 180+ lines, links to docs/
- Verification: `wc -l README.md` ≥ 180; `grep -c "docs/" README.md` ≥ 5

**Task 3.2: Write Vietnamese README at repo root** (30 min)
- Same as before: 7 sections in Vietnamese, 180+ lines
- Verification: `wc -l README.vi.md` ≥ 180

#### Part B: LaTeX Thesis (90 min)

**Task 3.3: Create LaTeX preamble** (10 min)
**File**: `docs/thesis/preamble.tex`

**Content**: Shared package includes, custom macros, document class settings

```latex
% preamble.tex — shared LaTeX preamble for C2-Evasion RL thesis

\usepackage[utf-8]{inputenc}
\usepackage[vietnamese,english]{babel}  % Vietnamese + English support
\usepackage{amsmath, amssymb, amsfonts}
\usepackage{graphicx}
\usepackage{hyperref}
\usepackage{listings}
\usepackage{xcolor}
\usepackage{fancyhdr}
\usepackage[margin=1in]{geometry}
\usepackage{natbib}  % Bibliography

% Custom macros
\newcommand{\eg}{\emph{e.g.}}
\newcommand{\ie}{\emph{i.e.}}
\newcommand{\etal}{\emph{et al.}}
\newcommand{\PPO}{\texttt{PPO}}
\newcommand{\IDS}{\texttt{IDS}}
\newcommand{\XGB}{\texttt{XGBoost}}

% Code listing style
\lstset{
  basicstyle=\ttfamily\small,
  breaklines=true,
  columns=fullflexible,
  frame=single,
  numbers=left,
  numberstyle=\tiny,
  keywordstyle=\color{blue},
  commentstyle=\color{gray},
  stringstyle=\color{red},
  backgroundcolor=\color{lightgray!10}
}

% Hyperref setup
\hypersetup{
  colorlinks=true,
  linkcolor=blue,
  citecolor=blue,
  urlcolor=blue
}
```

**Verification**: `wc -l docs/thesis/preamble.tex` ≥ 40; LaTeX syntax valid.

---

**Task 3.4: Write Vietnamese thesis in LaTeX** (50 min)
**File**: `docs/thesis/thesis_vi.tex`

**Structure**: 7 sections matching plan (intro, threat model, arch, math, setup, challenges, results)

**Template outline**:
```latex
\documentclass[12pt,a4paper]{article}

\input{preamble.tex}

\usepackage[vietnamese]{babel}
\selectlanguage{vietnamese}

\title{Học Tăng Cường Cấp Gói để Vượt Qua Phát Hiện Mạng: \\ 
       Đo Lường, Triển Khai, và Xác Thực Thực Tế Với Snort IDS}
\author{Lê Hoàng Phát}
\date{Tháng 9, 2026}

\begin{document}

\maketitle

\begin{abstract}
Luận văn này trình bày hệ thống hoàn chỉnh để đo lường khả năng vượt qua 
của những kẻ tấn công thích ứng chống lại hệ thống phát hiện xâm nhập (IDS) 
bằng học tăng cường. Chúng tôi triển khai một agent PPO học biến đổi luồng 
mạng ở cấp gói tin, huấn luyện trên một bộ phân loại thay thế (XGBoost), 
và xác thực kết quả chống lại một Snort IDS thực tế...
\end{abstract}

\section{Giới Thiệu}
% Content from earlier plan, adapted to LaTeX format
\subsection{Động Lực}
\subsection{Vấn Đề Nghiên Cứu}
\subsection{Đóng Góp}
\subsection{Cấu Trúc Luận Văn}

\section{Mô Hình Mối Đe Dọa \& Cơ Sở Lý Thuyết}
\subsection{Cài Đặt Đối Kháng}
\subsection{IDS Như Một Bộ Phân Loại}
\subsection{Khoảng Cách Giữa Mô Phỏng \& Thực Tế}

\section{Kiến Trúc Hệ Thống}
\subsection{Pipeline Tổng Quan}
\subsection{Các Thành Phần}
\subsection{Luồng Dữ Liệu}

\section{Mô Hình Hóa Toán Học}
\subsection{Phát Biểu MDP}
\begin{equation}
R(t) = R_{\text{ev}} \cdot \mathbb{1}[\hat{g}(s_t)=0] + \beta \cdot \nabla P_{\text{mal}}(s_t) 
       - \lambda \cdot \|a_t\| - \gamma_{\text{step}}
\end{equation}
\subsection{Hàm Giá Trị}
\subsection{Ước Lượng Lợi Thế}

\section{Thiết Lập Thực Nghiệm}
\subsection{Tập Dữ Liệu}
\subsection{Siêu Tham Số}
\subsection{Phần Cứng \& Tái Lập}

\section{Những Thách Thức Kỹ Thuật \& Giải Pháp}
\subsection{Lỗi \#1: Trích Xuất Luồng Một Chiều}
\subsubsection{Triệu Chứng}
\subsubsection{Nguyên Nhân Gốc}
\subsubsection{Giải Pháp}
\subsubsection{Xác Thực}

\subsection{Lỗi \#2: Viết Lại Gói Tin Ngây Thơ}
% Similar structure

\section{Kết Quả \& Đánh Giá}
\subsection{Bảng Đo Lường Cuối Cùng}
% 11 measurements table
\subsection{Phát Hiện Chính}
\subsection{Hạn Chế}

\section{Kết Luận}
\subsection{Tóm Tắt Đóng Góp}
\subsection{Hướng Nghiên Cứu Tương Lai}

\bibliographystyle{plain}
\bibliography{references}

\appendix
\section{Siêu Tham Số Chi Tiết}
\section{Phân Chia Dữ Liệu}
\section{Lệnh Tái Lập}

\end{document}
```

**Verification**: `wc -l docs/thesis/thesis_vi.tex` ≥ 300 (will expand to 1500+ with full content).

---

**Task 3.5: Write English thesis in LaTeX** (40 min)
**File**: `docs/thesis/thesis_en.tex`

**Same structure as thesis_vi.tex but in English**:
```latex
\documentclass[12pt,a4paper]{article}

\input{preamble.tex}

\usepackage[english]{babel}
\selectlanguage{english}

\title{Packet-Level Reinforcement Learning for Adversarial Network Flow Evasion: \\
       Measurement, Implementation, and Real-World Validation Against Snort IDS}
\author{Hoang Phat Le}
\date{September 2026}

\begin{document}

\maketitle

\begin{abstract}
This thesis presents a complete system for measuring evasion capability of 
adaptive attackers against intrusion detection systems (IDS) using reinforcement 
learning. We implement a PPO agent that learns packet-level flow mutations, 
train it on a surrogate judge (XGBoost), and validate results against a real 
Snort IDS using 11 reproducible measurements...
\end{abstract}

\section{Introduction}
\subsection{Motivation}
\subsection{Problem Statement}
\subsection{Contributions}
\subsection{Organization}

% ... (rest of 7 sections, structure matching Vietnamese thesis)

\end{document}
```

**Verification**: `wc -l docs/thesis/thesis_en.tex` ≥ 300.

---

**Task 3.6: Create Makefile for LaTeX compilation** (5 min)
**File**: `docs/thesis/Makefile`

**Content**:
```makefile
.PHONY: thesis_vi thesis_en clean all pdf-view

# Build Vietnamese thesis
thesis_vi:
	mkdir -p build
	pdflatex -interaction=nonstopmode -output-directory=build thesis_vi.tex
	bibtex build/thesis_vi.aux
	pdflatex -interaction=nonstopmode -output-directory=build thesis_vi.tex
	pdflatex -interaction=nonstopmode -output-directory=build thesis_vi.tex
	@echo "✓ Built: build/thesis_vi.pdf"

# Build English thesis
thesis_en:
	mkdir -p build
	pdflatex -interaction=nonstopmode -output-directory=build thesis_en.tex
	bibtex build/thesis_en.aux
	pdflatex -interaction=nonstopmode -output-directory=build thesis_en.tex
	pdflatex -interaction=nonstopmode -output-directory=build thesis_en.tex
	@echo "✓ Built: build/thesis_en.pdf"

# Build both
all: thesis_vi thesis_en
	@echo "✓ Both theses built successfully"

# View PDF (requires evince, mupdf, or open)
pdf-view-vi:
	@command -v evince >/dev/null && evince build/thesis_vi.pdf || \
	 command -v open >/dev/null && open build/thesis_vi.pdf || \
	 echo "PDF viewer not found; open build/thesis_vi.pdf manually"

pdf-view-en:
	@command -v evince >/dev/null && evince build/thesis_en.pdf || \
	 command -v open >/dev/null && open build/thesis_en.pdf || \
	 echo "PDF viewer not found; open build/thesis_en.pdf manually"

# Clean build artifacts
clean:
	rm -rf build/
	rm -f *.aux *.log *.out *.toc *.bbl *.blg

help:
	@echo "Available targets:"
	@echo "  make thesis_vi    — Build Vietnamese thesis PDF"
	@echo "  make thesis_en    — Build English thesis PDF"
	@echo "  make all          — Build both theses"
	@echo "  make pdf-view-vi  — View Vietnamese thesis PDF"
	@echo "  make pdf-view-en  — View English thesis PDF"
	@echo "  make clean        — Remove build artifacts"
	@echo "  make help         — Show this message"
```

**Verification**: `head -5 Makefile` shows `.PHONY:` declarations; `grep -c "thesis_" Makefile` ≥ 4 targets.

---

**Task 3.7: Create BibTeX references file** (5 min)
**File**: `docs/thesis/references.bib`

**Content**: ~30 references in BibTeX format
```bibtex
@article{kingma2014adam,
  title={Adam: A Method for Stochastic Optimization},
  author={Kingma, Diederik P and Ba, Jimmy},
  journal={arXiv preprint arXiv:1412.6980},
  year={2014}
}

@inproceedings{schulman2017proximal,
  title={Proximal Policy Optimization Algorithms},
  author={Schulman, John and Wolski, Filip and Dhariwal, Prafulla and Radford, Alec and Klimov, Oleg},
  booktitle={arXiv preprint arXiv:1707.06347},
  year={2017}
}

@dataset{stratosphere_ctu13,
  title={CTU-13 Botnet Traffic Capture},
  author={Stratosphere IPS},
  year={2013},
  url={https://www.stratosphereips.org/datasets-ctu13}
}

@dataset{stratosphere_mcfp,
  title={Malware Capture Facility Project},
  author={CVUT FEL},
  year={Various},
  url={https://mcfp.felk.cvut.cz/publicDatasets/}
}

% Add ~26 more references covering:
% - IDS evasion literature
% - Adversarial ML papers
% - Network traffic analysis
% - RL in security
% - Snort documentation
```

**Verification**: `wc -l references.bib` ≥ 150; `grep -c "@" references.bib` ≥ 30 entries.

---

**Task 3.8: Create thesis README** (2 min)
**File**: `docs/thesis/README.md`

```markdown
# Thesis Directory (LaTeX)

This folder contains full academic theses in English and Vietnamese, written in LaTeX.

## Contents

- **thesis_vi.tex** — Full Vietnamese thesis (LaTeX source)
  - For: KMA cybersecurity program submission
  - Sections: Giới thiệu, mô hình mối đe dọa, kiến trúc, toán học, thực nghiệm, thách thức, kết quả
  - ~1500 lines after full content fill-in

- **thesis_en.tex** — Full English thesis (LaTeX source)
  - For: Peer review, English-speaking audience
  - Sections: Introduction, threat model, architecture, math, experiments, challenges, results
  - ~1500 lines after full content fill-in

- **preamble.tex** — Shared LaTeX preamble
  - Packages: amsmath, hyperref, listings, babel (Vietnamese/English), natbib
  - Custom macros and formatting
  - Included by both thesis files via `\input{preamble.tex}`

- **references.bib** — BibTeX bibliography
  - ~30 references covering IDS evasion, adversarial ML, RL, network analysis
  - Referenced via `\bibliographystyle{plain}` and `\bibliography{references}`

- **Makefile** — LaTeX build automation
  - `make thesis_vi` — Compile Vietnamese thesis to PDF
  - `make thesis_en` — Compile English thesis to PDF
  - `make all` — Compile both
  - `make clean` — Remove build artifacts

## Build Instructions

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get install texlive-latex-base texlive-latex-extra texlive-fonts-recommended

# macOS (via Homebrew)
brew install basictex
sudo tlmgr update --self && sudo tlmgr install babel-english babel-vietnamese amsfonts
```

### Compile
```bash
cd docs/thesis

# Vietnamese thesis
make thesis_vi
# Output: build/thesis_vi.pdf

# English thesis
make thesis_en
# Output: build/thesis_en.pdf

# Both
make all

# Clean build artifacts
make clean
```

## Folder Structure

```
docs/thesis/
├── README.md (this file)
├── preamble.tex
├── thesis_vi.tex
├── thesis_en.tex
├── references.bib
├── Makefile
├── build/ (generated)
│   ├── thesis_vi.pdf
│   └── thesis_en.pdf
└── .gitignore (contains build/)
```

## LaTeX Structure

Each thesis file has:
1. Document class: `article` (12pt, A4)
2. Preamble: `\input{preamble.tex}` (shared)
3. Title, author, date
4. Abstract
5. 7 main sections
6. Bibliography (via `\bibliography{references}`)
7. Appendices

## How to Use

1. **For submission**: Compile `thesis_vi.tex`, submit `build/thesis_vi.pdf` to KMA
2. **For peer review**: Compile `thesis_en.tex`, share `build/thesis_en.pdf`
3. **For editing**: Edit `.tex` files; run `make all` to rebuild
4. **For version control**: `build/` folder is in `.gitignore`; only `.tex`, `.bib`, `preamble.tex`, `Makefile` are committed

## References & Links

- [System Architecture Details](../02-technical/system-architecture.md)
- [Root Cause Analysis](../04-challenges/root-cause-analysis.md)
- [Final Measurements](../03-experiments/results-final.md)
```

**Verification**: `wc -l docs/thesis/README.md` ≥ 80.

---

**Task 3.9: Create .gitignore for thesis folder** (2 min)
**File**: `docs/thesis/.gitignore`

```
# LaTeX build artifacts
build/
*.pdf
*.aux
*.log
*.out
*.toc
*.bbl
*.blg
*.fls
*.fdb_latexmk
*.synctex.gz
```

**Verification**: `cat docs/thesis/.gitignore | wc -l` ≥ 10.

---

### Phase 4: Verify & Commit (20 min total)

**Task 4.1: Verify folder structure** (3 min)
```bash
# Check all required folders + files
for folder in 01-overview 02-technical 03-experiments 04-challenges 05-validation 06-archive thesis; do
  [ -d "docs/$folder" ] && echo "✓ docs/$folder" || echo "✗ MISSING: docs/$folder"
done

# Check thesis files
for file in thesis_vi.tex thesis_en.tex preamble.tex references.bib Makefile; do
  [ -f "docs/thesis/$file" ] && echo "✓ docs/thesis/$file" || echo "✗ MISSING: docs/thesis/$file"
done

# Check README files
for file in README.md README.vi.md docs/README.md docs/thesis/README.md; do
  [ -f "$file" ] && echo "✓ $file" || echo "✗ MISSING: $file"
done
```

**Expected**: All ✓ (no ✗).

---

**Task 4.2: Verify LaTeX syntax** (5 min)
```bash
cd docs/thesis

# Check for LaTeX syntax errors (basic check with pdflatex -draftmode)
for file in thesis_vi.tex thesis_en.tex preamble.tex; do
  echo "Checking $file..."
  pdflatex -draftmode -interaction=nonstopmode "$file" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "✓ $file — syntax OK"
  else
    echo "✗ $file — syntax error"
  fi
done

# Clean up draft files
rm -f *.aux *.log *.out
```

**Expected**: All ✓.

---

**Task 4.3: Test Makefile** (5 min)
```bash
cd docs/thesis

# Test make targets
echo "Testing: make clean"
make clean 2>&1 | grep -q "error" && echo "✗ FAILED" || echo "✓ PASS"

echo "Testing: make help"
make help 2>&1 | grep -q "Available targets" && echo "✓ PASS" || echo "✗ FAILED"

# Don't actually compile (takes time); just verify Makefile syntax
echo "Testing Makefile syntax..."
make -n thesis_vi > /dev/null 2>&1 && echo "✓ Makefile syntax OK" || echo "✗ Makefile error"
```

**Expected**: All ✓.

---

**Task 4.4: Verify links & no credentials** (3 min)
```bash
# Check for broken markdown links in README files
grep -r "\[.*\](.*\.md)" README.md README.vi.md docs/ | grep -oP '\(\K[^)]+' | \
  while read f; do [ ! -e "$f" ] && echo "✗ BROKEN: $f"; done | wc -l
# Expected: 0

# Check for credentials
grep -r "password\|secret\|api_key\|token" README.md README.vi.md docs/ && echo "✗ CREDENTIALS FOUND" || echo "✓ PASS: no credentials"
```

**Expected**: 0 broken links, no credentials.

---

**Task 4.5: Verify line counts** (2 min)
```bash
echo "=== README files ==="
wc -l README.md README.vi.md

echo -e "\n=== Thesis LaTeX files ==="
wc -l docs/thesis/*.tex

echo -e "\n=== Bibliography ==="
grep -c "^@" docs/thesis/references.bib
# Expected: ≥ 30 references
```

**Expected output**:
```
README.md: ~180 lines
README.vi.md: ~180 lines
preamble.tex: ~50 lines
thesis_vi.tex: ~300 lines (will expand to 1500+ with full content)
thesis_en.tex: ~300 lines (will expand to 1500+ with full content)
Makefile: ~50 lines
references.bib: 150+ lines (30 entries)
```

---

**Task 4.6: Git status & commit** (2 min)
```bash
cd /root/.hermes/c2-evasion-rl
git status
# Expected: Shows new files in docs/ + README changes

git add -A

# View diff
git diff --cached --stat | head -30
```

---

**Task 4.7: Commit with descriptive message** (2 min)
```bash
git commit -m "docs: Consolidate documentation + bilingual README + LaTeX thesis

STRUCTURE CHANGES:
- Created docs/ folder hierarchy (01-overview, 02-technical, 03-experiments, 04-challenges, 05-validation, 06-archive, thesis)
- Archived 24 old .md reports to docs/06-archive/
- Created section README files for navigation
- Master docs/README.md index

NEW DOCUMENTATION:
- README.md: English quick start (180 lines, 7 sections)
- README.vi.md: Vietnamese quick start (180 lines, mirrored)
- docs/thesis/thesis_vi.tex: Vietnamese thesis in LaTeX (300→1500+ lines with full content)
- docs/thesis/thesis_en.tex: English thesis in LaTeX (300→1500+ lines with full content)
- docs/thesis/preamble.tex: Shared LaTeX preamble (packages, macros, styles)
- docs/thesis/references.bib: ~30 BibTeX references
- docs/thesis/Makefile: Build automation (make thesis_vi, make thesis_en, make all)
- docs/thesis/.gitignore: Exclude build/ and .pdf artifacts

All links verified; LaTeX syntax validated; Makefile tested.
Build instructions: cd docs/thesis && make thesis_vi (or thesis_en, or all)
Output: build/thesis_vi.pdf, build/thesis_en.pdf
"

git log --oneline | head -1
```

**Verification**: New commit appears in git log.

---

**Task 4.8: Determine branch & push** (2 min)
```bash
git branch -v
# Record: current branch name

git push origin <BRANCH_NAME>
# Example: git push origin packet-level-rl

# Verify push succeeded
git log --oneline origin/<BRANCH_NAME> | head -1
```

**Expected**: Push completes without errors.

---

## Tests & Validation

### Automated Checks
1. **Folder structure**: 8 docs/ subdirs exist
2. **File counts**: Each section has ≥3 .md files; thesis/ has 6 files (2 .tex + preamble + .bib + Makefile + README)
3. **LaTeX syntax**: `pdflatex -draftmode` passes on both .tex files
4. **Link integrity**: No broken `[text](path)` references in .md files
5. **BibTeX**: ≥30 `@` entries in references.bib
6. **Makefile**: `make -n` parses without error
7. **No credentials**: grep finds nothing

### Manual Review
1. **README clarity**: Each section ≤10 sentences; links to docs/ present
2. **LaTeX structure**: Both theses have same 7 sections; preamble properly imported
3. **Language**: Vietnamese thesis readable; English thesis readable
4. **Build**: Can run `make thesis_vi` successfully (if LaTeX installed)

---

## Risks, Tradeoffs & Open Questions

### Risks
1. **LaTeX not installed** — compilation requires TexLive; mitigate with Makefile help + build instructions
2. **Encoding issues** — Vietnamese in LaTeX needs `\usepackage[vietnamese]{babel}` + `inputenc[utf-8]`; already in preamble
3. **Large PDFs** — if theses expand to 1500+ lines, PDFs could be 5–10 MB; acceptable

### Tradeoffs
1. **LaTeX vs Markdown** — LaTeX is more formal for theses but harder to edit; accepted for academic submission
2. **File size** — .tex files smaller than compiled PDFs; PDFs excluded from git via .gitignore (good)

### Open Questions
1. **Should we pre-compile PDFs and commit them?** — NO; .gitignore excludes build/; users compile locally
2. **Do we need GitHub Actions CI to auto-compile?** — Not in scope for this plan; can add later
3. **References in BibTeX — should we extract from papers or enter manually?** — Manual for now; can auto-generate from Zotero later

---

## Execution Notes

- **Total task count**: 18 tasks (1.1–4.8)
- **Estimated time**: ~3 hours
  - Phase 1: 5 min
  - Phase 2: 25 min
  - Phase 3A (README): 60 min
  - Phase 3B (LaTeX thesis): 90 min (can parallelize with 3A)
  - Phase 4: 20 min
- **Parallelizable**: Phase 3A + 3B can run concurrently (README writing + thesis writing)
- **Prerequisites**: LaTeX must be installed to verify Task 4.2; README generation doesn't require it
- **Commit strategy**: 1 commit with all changes (structure + README + thesis)
- **Rollback**: `git revert <commit-sha>` if needed

---

**Plan saved to**: `.hermes/plans/2026-09-25_221000-consolidate-organize-docs-then-write-latex-thesis.md`
