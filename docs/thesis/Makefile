# Makefile — C2-Evasion RL thesis (LaTeX -> PDF)
#
#   make thesis_vi   build the Vietnamese thesis  -> build/thesis_vi.pdf
#   make thesis_en   build the English thesis     -> build/thesis_en.pdf
#   make all         build both
#   make clean       remove build/ and stray intermediates
#   make help        list targets
#
# Each thesis needs 3 pdflatex passes with a bibtex pass in between, so that
# \cite keys resolve, the .bbl is picked up, and the table of contents /
# cross-references settle.

.PHONY: all thesis_vi thesis_en pdf-view-vi pdf-view-en clean help

OUTDIR   := build
PDFLATEX := pdflatex -interaction=nonstopmode -halt-on-error -output-directory=$(OUTDIR)
BIBTEX   := bibtex

.DEFAULT_GOAL := help

# --- primary targets -------------------------------------------------------

thesis_vi:
	@mkdir -p $(OUTDIR)
	@echo "[*] Pass 1/3 (LaTeX)  — thesis_vi"
	@$(PDFLATEX) thesis_vi.tex > $(OUTDIR)/thesis_vi.pass1.log 2>&1 || \
		{ tail -40 $(OUTDIR)/thesis_vi.pass1.log; exit 1; }
	@echo "[*] Pass 2/3 (BibTeX) — thesis_vi"
	@$(BIBTEX) $(OUTDIR)/thesis_vi.aux > $(OUTDIR)/thesis_vi.blg 2>&1 || \
		{ echo "bibtex failed; see $(OUTDIR)/thesis_vi.blg"; exit 1; }
	@echo "[*] Pass 3/3 (LaTeX x2) — thesis_vi"
	@$(PDFLATEX) thesis_vi.tex > $(OUTDIR)/thesis_vi.pass2.log 2>&1 || \
		{ tail -40 $(OUTDIR)/thesis_vi.pass2.log; exit 1; }
	@$(PDFLATEX) thesis_vi.tex > $(OUTDIR)/thesis_vi.pass3.log 2>&1 || \
		{ tail -40 $(OUTDIR)/thesis_vi.pass3.log; exit 1; }
	@echo "[ok] built $(OUTDIR)/thesis_vi.pdf"

thesis_en:
	@mkdir -p $(OUTDIR)
	@echo "[*] Pass 1/3 (LaTeX)  — thesis_en"
	@$(PDFLATEX) thesis_en.tex > $(OUTDIR)/thesis_en.pass1.log 2>&1 || \
		{ tail -40 $(OUTDIR)/thesis_en.pass1.log; exit 1; }
	@echo "[*] Pass 2/3 (BibTeX) — thesis_en"
	@$(BIBTEX) $(OUTDIR)/thesis_en.aux > $(OUTDIR)/thesis_en.blg 2>&1 || \
		{ echo "bibtex failed; see $(OUTDIR)/thesis_en.blg"; exit 1; }
	@echo "[*] Pass 3/3 (LaTeX x2) — thesis_en"
	@$(PDFLATEX) thesis_en.tex > $(OUTDIR)/thesis_en.pass2.log 2>&1 || \
		{ tail -40 $(OUTDIR)/thesis_en.pass2.log; exit 1; }
	@$(PDFLATEX) thesis_en.tex > $(OUTDIR)/thesis_en.pass3.log 2>&1 || \
		{ tail -40 $(OUTDIR)/thesis_en.pass3.log; exit 1; }
	@echo "[ok] built $(OUTDIR)/thesis_en.pdf"

all: thesis_vi thesis_en
	@echo "[ok] both theses built"

# --- convenience -----------------------------------------------------------

pdf-view-vi:
	@command -v evince >/dev/null && evince $(OUTDIR)/thesis_vi.pdf || \
	 command -v open   >/dev/null && open   $(OUTDIR)/thesis_vi.pdf || \
	 echo "No PDF viewer found; open $(OUTDIR)/thesis_vi.pdf manually"

pdf-view-en:
	@command -v evince >/dev/null && evince $(OUTDIR)/thesis_en.pdf || \
	 command -v open   >/dev/null && open   $(OUTDIR)/thesis_en.pdf || \
	 echo "No PDF viewer found; open $(OUTDIR)/thesis_en.pdf manually"

clean:
	@echo "[*] Removing build artifacts..."
	@rm -rf $(OUTDIR)
	@rm -f *.aux *.bbl *.blg *.log *.out *.toc *.lof *.lot *.fls *.fdb_latexmk
	@echo "[ok] clean"

help:
	@echo "C2-Evasion RL thesis — available targets:"
	@echo "  make thesis_vi    Build Vietnamese thesis  -> $(OUTDIR)/thesis_vi.pdf"
	@echo "  make thesis_en    Build English thesis     -> $(OUTDIR)/thesis_en.pdf"
	@echo "  make all          Build both theses"
	@echo "  make pdf-view-vi  Open the Vietnamese PDF"
	@echo "  make pdf-view-en  Open the English PDF"
	@echo "  make clean        Remove build/ and intermediates"
	@echo "  make help         Show this message"
