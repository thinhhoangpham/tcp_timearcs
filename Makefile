# Makefile for TCP TimeArcs Paper
# LaTeX compilation with BibTeX references

# Main LaTeX file (without .tex extension)
MAIN = paper_introduction

# PDF viewer (change to your preference)
PDFVIEWER = evince

# LaTeX compiler
LATEX = pdflatex
BIBTEX = bibtex

.PHONY: all clean view help

# Default target: compile the paper
all: $(MAIN).pdf

# Full compilation with bibliography
$(MAIN).pdf: $(MAIN).tex PAPER_REFERENCES.bib
	@echo "==> First LaTeX pass..."
	$(LATEX) $(MAIN).tex
	@echo "==> Running BibTeX..."
	$(BIBTEX) $(MAIN)
	@echo "==> Second LaTeX pass..."
	$(LATEX) $(MAIN).tex
	@echo "==> Third LaTeX pass (resolve references)..."
	$(LATEX) $(MAIN).tex
	@echo "==> PDF generated: $(MAIN).pdf"

# Quick compile (no bibliography update)
quick: $(MAIN).tex
	@echo "==> Quick compile (no BibTeX)..."
	$(LATEX) $(MAIN).tex

# View the generated PDF
view: $(MAIN).pdf
	$(PDFVIEWER) $(MAIN).pdf &

# Clean auxiliary files
clean:
	@echo "==> Cleaning auxiliary files..."
	rm -f *.aux *.log *.bbl *.blg *.out *.toc *.lof *.lot *.fls *.fdb_latexmk *.synctex.gz

# Clean everything including PDF
distclean: clean
	@echo "==> Removing PDF..."
	rm -f $(MAIN).pdf

# Check for LaTeX errors
check:
	@echo "==> Checking for LaTeX installation..."
	@which $(LATEX) > /dev/null && echo "✓ pdflatex found" || echo "✗ pdflatex not found"
	@which $(BIBTEX) > /dev/null && echo "✓ bibtex found" || echo "✗ bibtex not found"
	@test -f $(MAIN).tex && echo "✓ $(MAIN).tex exists" || echo "✗ $(MAIN).tex not found"
	@test -f PAPER_REFERENCES.bib && echo "✓ PAPER_REFERENCES.bib exists" || echo "✗ PAPER_REFERENCES.bib not found"

# Word count (approximate)
wordcount:
	@echo "==> Approximate word count (text only)..."
	@detex $(MAIN).tex | wc -w

# Help message
help:
	@echo "TCP TimeArcs Paper - Makefile Help"
	@echo "==================================="
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Compile paper with bibliography (default)"
	@echo "  quick      - Quick compile without updating bibliography"
	@echo "  view       - Open generated PDF in viewer"
	@echo "  clean      - Remove auxiliary files (.aux, .log, etc.)"
	@echo "  distclean  - Remove all generated files including PDF"
	@echo "  check      - Verify LaTeX installation and required files"
	@echo "  wordcount  - Count words in document (requires detex)"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make           # Compile the paper"
	@echo "  make view      # Compile and view"
	@echo "  make clean     # Clean temporary files"
