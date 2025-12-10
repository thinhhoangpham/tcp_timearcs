# LaTeX Compilation Guide for TCP TimeArcs Paper

## Files Overview

### Main LaTeX Files
- **`paper_introduction.tex`** - Main LaTeX document with introduction section
- **`PAPER_REFERENCES.bib`** - BibTeX bibliography file with all references
- **`Makefile`** - Automated compilation script

### Supporting Documentation
- **`PAPER_INTRODUCTION.md`** - Markdown version (reference only)
- **`PAPER_WRITING_GUIDE.md`** - Complete paper writing roadmap

## Quick Start

### Option 1: Using Makefile (Recommended)

```bash
# Compile the paper (generates PDF)
make

# View the generated PDF
make view

# Clean temporary files
make clean
```

### Option 2: Manual Compilation

```bash
# Step 1: First LaTeX pass
pdflatex paper_introduction.tex

# Step 2: Process bibliography
bibtex paper_introduction

# Step 3: Second LaTeX pass (resolve citations)
pdflatex paper_introduction.tex

# Step 4: Third LaTeX pass (resolve references)
pdflatex paper_introduction.tex
```

### Option 3: Using Overleaf (Online)

1. Go to [https://www.overleaf.com/](https://www.overleaf.com/)
2. Create new project: "Upload Project"
3. Upload `paper_introduction.tex` and `PAPER_REFERENCES.bib`
4. Click "Recompile" to generate PDF

## Installation Requirements

### Linux (Ubuntu/Debian)

```bash
# Install full TeX Live distribution
sudo apt-get update
sudo apt-get install texlive-full

# Or minimal installation
sudo apt-get install texlive-latex-base texlive-latex-extra texlive-bibtex-extra
```

### macOS

```bash
# Install MacTeX (recommended)
brew install --cask mactex

# Or BasicTeX (minimal, 100MB instead of 4GB)
brew install --cask basictex
sudo tlmgr update --self
sudo tlmgr install latexmk
```

### Windows

Download and install:
- **MiKTeX**: [https://miktex.org/download](https://miktex.org/download)
- **TeXworks** (included with MiKTeX for editing)

## Verifying Installation

```bash
# Check if LaTeX is installed
make check

# Expected output:
# ✓ pdflatex found
# ✓ bibtex found
# ✓ paper_introduction.tex exists
# ✓ PAPER_REFERENCES.bib exists
```

## Common LaTeX Commands

### Compilation

```bash
make              # Full compile with bibliography
make quick        # Quick compile (skip BibTeX)
make view         # Compile and open PDF
```

### Cleaning

```bash
make clean        # Remove .aux, .log, .bbl files
make distclean    # Remove everything including PDF
```

### Word Count

```bash
make wordcount    # Requires 'detex' package
```

## File Structure After Compilation

```
tcp_timearcs/
├── paper_introduction.tex      # Source LaTeX file
├── PAPER_REFERENCES.bib        # Bibliography database
├── Makefile                    # Compilation automation
│
├── paper_introduction.pdf      # Generated PDF ✓
│
└── Temporary files (cleaned with 'make clean'):
    ├── paper_introduction.aux
    ├── paper_introduction.bbl  # Formatted bibliography
    ├── paper_introduction.blg  # BibTeX log
    ├── paper_introduction.log  # LaTeX log
    └── paper_introduction.out  # Hyperref bookmarks
```

## Editing the LaTeX Document

### Recommended LaTeX Editors

#### Cross-Platform
- **Overleaf** (online): https://www.overleaf.com/
- **TeXstudio**: https://www.texstudio.org/
- **VS Code** + LaTeX Workshop extension

#### Linux
- **TeXmaker**: `sudo apt install texmaker`
- **Kile**: `sudo apt install kile`

#### macOS
- **TeXShop** (included with MacTeX)
- **TeXPad**: https://www.texpad.com/

#### Windows
- **TeXworks** (included with MiKTeX)
- **WinEdt**: https://www.winedt.com/

### VS Code Setup (Recommended)

```bash
# 1. Install VS Code extensions
code --install-extension James-Yu.latex-workshop

# 2. Open folder in VS Code
code .

# 3. Open paper_introduction.tex
# 4. Press Ctrl+Alt+B to build (or Cmd+Alt+B on macOS)
# 5. Press Ctrl+Alt+V to view PDF
```

## Customizing the Document

### Change Conference Format

**Current**: IEEE Conference format (`\documentclass[conference]{IEEEtran}`)

**Options**:
```latex
% Journal format
\documentclass[journal]{IEEEtran}

% Standard article
\documentclass[11pt,twocolumn]{article}

% ACM format
\documentclass[sigconf]{acmart}  % Requires acmart.cls
```

### Add Figures

```latex
% In the preamble (already included):
\usepackage{graphicx}

% In the document body:
\begin{figure}[t]
\centering
\includegraphics[width=0.9\columnwidth]{images/timearcs_example.png}
\caption{TCP TimeArcs visualization showing DDoS attack pattern.}
\label{fig:example}
\end{figure}

% Reference in text:
As shown in Fig.~\ref{fig:example}, the arc diagram reveals...
```

### Add Tables

```latex
\begin{table}[t]
\centering
\caption{Performance Comparison}
\label{tab:performance}
\begin{tabular}{|l|r|r|}
\hline
\textbf{Tool} & \textbf{Load Time (s)} & \textbf{Memory (MB)} \\
\hline
Wireshark & 180 & OOM crash \\
Arkime & 45 & 4096 \\
TCP TimeArcs & 15 & 200 \\
\hline
\end{tabular}
\end{table}
```

### Add Algorithms

```latex
% In preamble (already included):
\usepackage{algorithmic}

% Or use algorithmicx for better formatting:
\usepackage{algorithm}
\usepackage{algpseudocode}

% In document:
\begin{algorithm}
\caption{TCP Flow Detection}
\label{alg:flow}
\begin{algorithmic}[1]
\STATE Initialize connection\_map $\leftarrow$ empty
\FOR{each packet $p$ in stream}
    \STATE key $\leftarrow$ (src\_ip, dst\_ip, src\_port, dst\_port)
    \IF{SYN flag set}
        \STATE connection\_map[key] $\leftarrow$ NEW\_FLOW
    \ENDIF
\ENDFOR
\end{algorithmic}
\end{algorithm}
```

## Managing References

### Adding a New Citation

**Step 1**: Add entry to `PAPER_REFERENCES.bib`

```bibtex
@article{newpaper2024,
  author  = {Smith, John and Doe, Jane},
  title   = {New Approach to Network Visualization},
  journal = {IEEE Security \& Privacy},
  year    = {2024},
  volume  = {22},
  number  = {3},
  pages   = {45--56},
  doi     = {10.1109/MSEC.2024.1234567}
}
```

**Step 2**: Cite in LaTeX document

```latex
Recent work on network visualization~\cite{newpaper2024} demonstrates...
```

**Step 3**: Recompile with bibliography

```bash
make
```

### Citation Formats

```latex
% Single citation
\cite{dang2016timearcs}                    % [14]

% Multiple citations
\cite{ring2019survey,moustafa2015unsw}     % [2], [13]

% Citation in sentence
As demonstrated by Dang et al.~\cite{dang2016timearcs}...

% Suppress brackets (for author names)
\citeauthor{dang2016timearcs}              % Dang et al.
\citeyear{dang2016timearcs}                % 2016
```

### Common BibTeX Entry Types

```bibtex
% Journal article
@article{key, author={}, title={}, journal={}, year={}, volume={}, pages={}}

% Conference paper
@inproceedings{key, author={}, title={}, booktitle={}, year={}, pages={}}

% Book
@book{key, author={}, title={}, publisher={}, year={}}

% Technical report
@techreport{key, author={}, title={}, institution={}, year={}}

% Website/Blog
@misc{key, author={}, title={}, year={}, howpublished={}, url={}}
```

## Troubleshooting

### Error: "LaTeX Error: File `IEEEtran.cls' not found"

**Solution**: Install IEEE document class
```bash
sudo apt install texlive-publishers  # Linux
sudo tlmgr install IEEEtran          # macOS
```

### Error: "Citation undefined"

**Cause**: BibTeX not run or .bbl file missing

**Solution**: Full recompile
```bash
make clean
make
```

### Error: "! Undefined control sequence"

**Cause**: Missing package or typo in command

**Solution**: Check LaTeX log
```bash
cat paper_introduction.log | grep "Undefined"
```

### PDF Not Updating

**Cause**: PDF viewer has file locked

**Solution**: Close PDF viewer, then recompile
```bash
make clean
make
```

### Bibliography Not Appearing

**Checklist**:
- [ ] Is `PAPER_REFERENCES.bib` in same directory?
- [ ] Did you run BibTeX? (`bibtex paper_introduction`)
- [ ] Did you compile LaTeX twice after BibTeX?
- [ ] Are citation keys correct? (check .blg file)

**Debug**:
```bash
# Check BibTeX log
cat paper_introduction.blg

# Full verbose recompile
pdflatex paper_introduction.tex
bibtex paper_introduction
pdflatex paper_introduction.tex
pdflatex paper_introduction.tex
```

## Submitting to Conferences

### IEEE Conferences (VizSec, VIS)

**Format**: IEEE conference format (already configured)

**Requirements**:
- Use `IEEEtran.cls` template ✓
- Two-column format ✓
- 10pt font ✓
- References in IEEE style ✓

**Upload**: PDF only (do NOT submit .tex unless requested)

### ACM Conferences (SIGCOMM, IMC)

**Format**: Requires ACM template

**Change** in `paper_introduction.tex`:
```latex
% Replace line 1 with:
\documentclass[sigconf,review]{acmart}

% Download acmart.cls from:
% https://www.acm.org/publications/proceedings-template
```

### Arxiv Preprint

**Requirement**: Upload source files (.tex + .bib + images)

**Prepare**:
```bash
# Create submission directory
mkdir arxiv_submission
cp paper_introduction.tex arxiv_submission/
cp PAPER_REFERENCES.bib arxiv_submission/
cp -r images/ arxiv_submission/  # if you have images

# Create tarball
cd arxiv_submission
tar -czf ../tcp_timearcs_arxiv.tar.gz *
```

## Quality Checks Before Submission

### Spelling and Grammar

```bash
# Install aspell
sudo apt install aspell

# Check spelling
aspell -t -c paper_introduction.tex
```

### LaTeX Warnings

```bash
# Check for warnings in log
grep "Warning" paper_introduction.log

# Common warnings to fix:
# - "Overfull \hbox" (line too long)
# - "Citation undefined" (missing reference)
# - "Reference undefined" (missing label)
```

### PDF Metadata

```bash
# Check PDF properties
pdfinfo paper_introduction.pdf

# Ensure:
# - Title is set correctly
# - Author names are correct
# - No compilation errors in metadata
```

## Additional Resources

### LaTeX Documentation
- **Overleaf Guides**: https://www.overleaf.com/learn
- **LaTeX Wikibook**: https://en.wikibooks.org/wiki/LaTeX
- **TeX StackExchange**: https://tex.stackexchange.com/

### IEEE Templates
- **IEEE Author Center**: https://ieeeauthorcenter.ieee.org/
- **IEEEtran Documentation**: http://www.ctan.org/pkg/ieeetran

### BibTeX Tools
- **JabRef** (bibliography manager): https://www.jabref.org/
- **Zotero** (reference manager): https://www.zotero.org/
- **DOI to BibTeX**: https://www.doi2bib.org/

## Getting Help

### Check Compilation Errors

```bash
# View last 50 lines of LaTeX log
tail -50 paper_introduction.log

# Search for errors
grep -i "error" paper_introduction.log
```

### Test Minimal Document

Create `test.tex`:
```latex
\documentclass{article}
\begin{document}
Hello World!
\end{document}
```

Compile:
```bash
pdflatex test.tex
```

If this fails, LaTeX installation is broken.

### Online Help

1. **Overleaf** - Upload to Overleaf to test online
2. **TeX StackExchange** - Post error messages with MWE (Minimal Working Example)
3. **LaTeX Community Forum** - https://latex.org/forum/

---

## Summary of Key Commands

```bash
# Full compilation workflow
make                    # Compile with bibliography
make view              # View PDF
make clean             # Remove temporary files

# Manual compilation
pdflatex paper_introduction.tex
bibtex paper_introduction
pdflatex paper_introduction.tex
pdflatex paper_introduction.tex

# Verification
make check             # Verify installation
pdfinfo paper_introduction.pdf  # Check PDF metadata

# Editing
code .                 # Open in VS Code
texstudio paper_introduction.tex  # Open in TeXstudio
```

**Happy writing! 📝**
