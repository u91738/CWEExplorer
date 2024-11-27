# CWEExplorer
Angr exploration technique to navigate to basic blocks that look like bad examples from SARD Juliet 1.3 dataset.
"Looks like" is defined by ML model trained on disassembly.

# WIP

# What is the ML model exactly?
- Build SARD binaries
- Get control flow graphs for good and bad binaries
- Use chains of basic blocks present only in good/bad binaries as good/bad examples for dataset
- embedding for each instruction is a set of features:
    - instruction group (arithmetic, conditional branch, etc. thanks capstone)
    - writes memory? Reads memory? Immediate values?
    - affected registers
- Feed to XGBoost
