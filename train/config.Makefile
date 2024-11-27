# Compiler flags
# Try to train the model with the same flags and compiler as your targets
# original dataset doesn't use CXXFLAGS variables, so you will have to deal with CFLAGS applied to C++
CC?=gcc
CXX?=g++
CFLAGS?=-g -O2
LDFLAGS?=

JOBS=15

# Evaluate control flow graph in fragments of N basic blocks (instruction sequence without branching)
# increasing MAX_PATH_LEN can exponentially increase memory requirements
MAX_PATH_LEN=5

# Ignore control flow graph nodes with more than N successors
# Sometimes CFG has nodes leading to a ton of places, probably indirect calls
# Higher MAX_SUCCESSORS can make dataset much bigger
MAX_SUCCESSORS=8

# Active CWEs
# Run ./cwe/stats.py to see what CWEs are in dataset, how many samples and brief description
CWE=CWE-121 CWE-122

# Embedding mode
# instruction - separate vector per instruction, best if you have resources
# block - merge all instruction vectors in block into one with bitwise or, works better than it sounds
MODE=instruction

# In instruction mode, use first N instructions of each basic block
BLOCK_LEN=10

# Registers packing mode, one of
# minimal - only major registers have their own feature
#           best for instruction mode
# subregisters - treat x86 subregisters (RAX-EAX-AX-AH-AL) as separate registers
#                vector registers are stil cramped in one feature, same for FP
#                seems to help block mode accuracy
# all - every register has it's own feature
REGPACK=minimal

# Preset for smaller dataset with some loss of precision
#MAX_PATH_LEN=5
#MODE=block
#REGPACK=subregisters
