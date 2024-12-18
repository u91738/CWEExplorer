# CWEExplorer
Angr exploration technique to navigate to basic blocks that look like bad examples from SARD Juliet 1.3 dataset.
"Looks like" is defined by ML model trained on disassembly.

# How to use
## Train
Go to `cwe_explorer/train`.

Call `./get-data.sh` to get dataset and clean it.

Settings are set and documented in `config.Makefile`.
Set config as close to build of your target binaries as possible. Different compiler version should be fine, different achitecture - absolutely not.
Call `./cwe-stats.py` to see what CWEs are present and how many examples for them are in dataset. Not all of them can be caught by CWEExplorer's approach, some don't have enough samples, some are only present in source code etc.

Call `make` to train. It will build the SARD binaries, call the data processing scripts and train the models.


## Run
See `example.py`.

# How it works
## What is the ML part exactly?
- Build SARD binaries
- Get control flow graphs for good and bad binaries
- Use chains of basic blocks present only in good/bad binaries as good/bad examples for dataset
- Embedding for each instruction is a set of features:
    - instruction group (arithmetic, conditional branch, etc. thanks capstone)
    - writes memory? Reads memory? Immediate values?
    - affected registers
- Add a separate feature for a call to each common C function (malloc, free, strlen, ...)
- Feed to XGBoost, input is a chain of N basic blocks from CFG (default=6) with cutoff at M instructions per block (default=20)

## Exploration Technique
- Get control flow graph from target binary
- Use XGBoost model to tell which subpaths of N basic blocks look vulnerable
- Guide angr simulation to these execution paths in a way similar to Explorer technique from angr itself
- Get false positives. It was better on test data :(
