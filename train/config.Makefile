# Compiler flags
# Try to train the model with the same flags and compiler as your targets
# original dataset doesn't use CXXFLAGS variables, so you will have to deal with CFLAGS applied to C++
CONF_NAME?=amd64-gcc
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

# Merge N instructions into one embedding
# i.e. with MERGE_BY=2 "POP RAX; POP RBX" will be represented as one instruction that writes RAX and RBX
MERGE_BY=2

# In use first N instructions of each basic block (Applied after MERGE_BY)
BLOCK_LEN=10

# Registers packing mode, one of
# minimal - only major registers have their own feature
#           best for instruction mode
# subregisters - treat x86 subregisters (RAX-EAX-AX-AH-AL) as separate registers
#                vector registers are stil cramped in one feature, same for FP
#                seems to help block mode accuracy
# all - every register has it's own feature, hypothetically can help precision but seems to be a waste of space
REGPACK=minimal

# If you want to save memory with loss of precision
# high MERGE_BY, low BLOCK_LEN, low MAX_PATH_LEN, REGPACK=minimal
