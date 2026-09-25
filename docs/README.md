# Documentation Index

Welcome to the C2-Evasion RL project documentation. Start here to find what you need.

## Quick Navigation

### 📘 For First-Time Readers
1. Start with [`/README.md`](../README.md) (English quick start) or [`/README.vi.md`](../README.vi.md) (Tiếng Việt)
2. Then read [`01-overview/`](01-overview/) for project scope

### 🏗️ For Technical Details
- [`02-technical/`](02-technical/) — Architecture, math, implementation
- [`03-experiments/`](03-experiments/) — Datasets, setup, results
- [`04-challenges/`](04-challenges/) — How we debugged and fixed critical bugs

### 🔬 For Validation & Results
- [`05-validation/`](05-validation/) — Snort IDS validation layer
- [`03-experiments/results-final.md`](03-experiments/results-final.md) — 11 measurements (latest)

### 📚 For Academic Submission
- `thesis/thesis_en.md` — Full English thesis (1650 lines, Phase 3)
- `thesis/thesis_vi.md` — Full Vietnamese thesis (1660 lines, Phase 3)

### 📦 For Historical Context
- [`06-archive/old-reports/`](06-archive/old-reports/) — Earlier comprehensive reports
- [`06-archive/investigation-notes/`](06-archive/investigation-notes/) — Task notes, intermediate results
- [`06-archive/documentation-audit.md`](06-archive/documentation-audit.md) — Phase 1 inventory & categorization audit

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
│   ├── README.md — folder guide
│   ├── old-reports/ (6 earlier comprehensive reports)
│   └── investigation-notes/ (13 task notes, intermediate results)
└── thesis/
    ├── README.md — folder guide
    ├── thesis_en.md (will be created)
    └── thesis_vi.md (will be created)
```

---

## Document Purpose Guide

| Document | Purpose | Audience | Length |
|----------|---------|----------|--------|
| `/README.md` | Quick start, overview | Developers, researchers | 200 lines |
| `/README.vi.md` | Quick start (Vietnamese) | Vietnamese readers | 200 lines |
| `thesis/thesis_en.md` | Full academic thesis | KMA submission, peer review | 1650 lines |
| `thesis/thesis_vi.md` | Full thesis (Vietnamese) | KMA cybersecurity program | 1660 lines |
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
