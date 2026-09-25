# Makefile for C2-Evasion RL Thesis
# Builds both English and Vietnamese LaTeX theses to PDF

.PHONY: all en vi clean distclean help

THESIS_DIR := .
THESIS_EN := thesis_en
THESIS_VI := thesis_vi
PDFLATEX := pdflatex -interaction=nonstopmode -halt-on-error
BIBTEX := bibtex

help:
	@echo "C2-Evasion RL Thesis — Build targets:"
	@echo "  make all      Build both English and Vietnamese theses (PDFs)"
	@echo "  make en       Build English thesis only"
	@echo "  make vi       Build Vietnamese thesis only"
	@echo "  make clean    Remove intermediate files (.aux, .bbl, .blg, .log, .out)"
	@echo "  make distclean Remove all generated files (including PDFs)"
	@echo ""
	@echo "Output: $(THESIS_EN).pdf, $(THESIS_VI).pdf"

all: en vi
	@echo "[✓] Both theses built successfully"

en: $(THESIS_EN).pdf

vi: $(THESIS_VI).pdf

$(THESIS_EN).pdf: $(THESIS_EN).tex preamble.tex references.bib
	@echo "[*] Building English thesis..."
	$(PDFLATEX) $(THESIS_EN).tex > /dev/null
	$(BIBTEX) $(THESIS_EN) > /dev/null 2>&1 || true
	$(PDFLATEX) $(THESIS_EN).tex > /dev/null
	$(PDFLATEX) $(THESIS_EN).tex > /dev/null
	@echo "[✓] $(THESIS_EN).pdf"

$(THESIS_VI).pdf: $(THESIS_VI).tex preamble.tex references.bib
	@echo "[*] Building Vietnamese thesis..."
	$(PDFLATEX) $(THESIS_VI).tex > /dev/null
	$(BIBTEX) $(THESIS_VI) > /dev/null 2>&1 || true
	$(PDFLATEX) $(THESIS_VI).tex > /dev/null
	$(PDFLATEX) $(THESIS_VI).tex > /dev/null
	@echo "[✓] $(THESIS_VI).pdf"

clean:
	@echo "[*] Cleaning intermediate files..."
	rm -f $(THESIS_EN).aux $(THESIS_EN).bbl $(THESIS_EN).blg $(THESIS_EN).log $(THESIS_EN).out $(THESIS_EN).toc
	rm -f $(THESIS_VI).aux $(THESIS_VI).bbl $(THESIS_VI).blg $(THESIS_VI).log $(THESIS_VI).out $(THESIS_VI).toc
	rm -f *.aux *.bbl *.blg *.log *.out *.toc
	@echo "[✓] Cleaned"

distclean: clean
	@echo "[*] Removing all generated files..."
	rm -f $(THESIS_EN).pdf $(THESIS_VI).pdf
	@echo "[✓] Distcleaned"

.DEFAULT_GOAL := help
