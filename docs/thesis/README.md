# Thesis Directory

Full academic theses in LaTeX, in English and Vietnamese, built to PDF with `make`.

## Contents

| File | Purpose |
|---|---|
| `thesis_vi.tex` | Vietnamese thesis (KMA cybersecurity submission) — 9 chapters, 23 sections |
| `thesis_en.tex` | English thesis (peer review) — same structure in English |
| `preamble.tex` | Shared preamble: packages, Vietnamese (T5) encoding, macros, listing/hyperref config |
| `references.bib` | 30 BibTeX entries (articles, inproceedings, dataset, book, misc) |
| `Makefile` | Build targets (`thesis_vi`, `thesis_en`, `all`, `clean`, `help`) |
| `.gitignore` | Excludes `build/` and generated PDFs |
| `build/` | Generated PDFs and LaTeX auxiliaries (gitignored) |

## Structure (both theses)

1. Introduction — motivation, problem statement, contributions
2. Threat Model & Scope — adversarial setting, assumptions
3. System Architecture — pipeline, components, data flow
4. Mathematical Formulation — MDP, PPO objective, reward function
5. Experiments — datasets, phases, measurements
6. Challenges & Lessons — the two critical bugs and how they were found
7. Related Work — adversarial ML, RL foundations, detectors/datasets
8. Conclusion — findings, limitations, future work
9. Appendix — implementation details

## Building

```bash
cd docs/thesis
make thesis_vi    # -> build/thesis_vi.pdf
make thesis_en    # -> build/thesis_en.pdf
make all          # both
make clean        # remove build/
```

Each target runs 3 × `pdflatex` with `bibtex` in between, so citations and
cross-references resolve. Requires TeX Live with `texlive-lang-other`
(vntex / `vietnamese.ldf`) for the Vietnamese thesis.

## Notes

- Vietnamese typesetting needs the T5 font encoding; `preamble.tex` loads
  `fontenc` with `T5` and declares babel as `[english,vietnamese]` — Vietnamese
  must be the **main** language or the T5 glyph macros stay bound to OT1 and the
  build fails with `Command \ohorn unavailable in encoding OT1`.
- `references.bib` uses `@dataset` for the CTU-13 entry; `plainnat.bst` has no
  driver for that type and emits one cosmetic warning. The entry still renders.

## References & Links

- [Root Cause Analysis](../04-challenges/root-cause-analysis.md)
- [Final Measurements](../03-experiments/results-final.md)
- [System Architecture Details](../02-technical/)
