import re
from enum import Enum
from typing import Union
from typeguard import typechecked
import capstone
from archinfo import Arch
import networkx as nx

class RegistersPacking(Enum):
    COMPACT = 0
    SUBREGISTERS = 1
    ALL = 2

class RegisterCategory(Enum):
    VECTOR = 1
    FP = 2
    OTHER = 3
    MAX = 3

class Registers:
    @typechecked
    def __init__(self, arch:Arch, pack:RegistersPacking):
        self.pack = pack
        self.by_name = { i.name : i for i in arch.register_list}
        self.gp = [i.name for i in arch.register_list if i.general_purpose or pack == RegistersPacking.ALL]
        for r in arch.register_list:
            for alias in r.alias_names:
                self.by_name[alias] = r
            for sr, _, _ in r.subregisters:
                self.by_name[sr] = r

                if m := re.match('mm(\d)', sr):
                    self.by_name[f'st({m.group(1)})'] = r

                self.by_name[sr.lstrip('_')] = r

                for alias in r.alias_names:
                    self.by_name[alias] = r

                if r.general_purpose and (pack == RegistersPacking.ALL or pack == RegistersPacking.SUBREGISTERS):
                    self.gp.append(sr)

    @typechecked
    def index(self, reg_name:str) -> Union[int, RegisterCategory]:
        if self.pack == RegistersPacking.ALL:
            try:
                return self.gp.index(reg_name)
            except ValueError:
                r = self.by_name[reg_name]
                return self.gp.index(r.name)
        else:
            r = self.by_name[reg_name]
            if r.vector:
                return RegisterCategory.VECTOR
            if r.floating_point:
                return RegisterCategory.FP
            if r.general_purpose:
                try:
                    return self.gp.index(reg_name)
                except ValueError:
                    return self.gp.index(r.name)
            else:
                return RegisterCategory.OTHER # CR0-8, CS, DS

# find juliet -name '*.c' -or -name '*.cpp' -exec grep -Eo '\w+\s*\(' {} \; | \
#       grep -vE '^\s*\d\s\w|global|static|WSA|CWE|[Gg]ood|[Bb]ad|if|for|main|action|close_socketsizeof|time|srand|while|makeword|switch|print.*Line' | \
#       tr '[A-Z]' '[a-z]' | \
#       sort | uniq -c | sort -nr | tr -d '('
common_functions = [
    "free",          # 28252
    "malloc",        # 12000
    "memset",        # 10489
    "open",          # 8453
    "strlen",        # 7715
    "wmemset",       # 6632
    "push_back",     # 6362
    "exit",          # 6133
    "insert",        # 5754
    "fgets",         # 5463
    "close",         # 5023
    "wcslen",        # 5014
    "strcat",        # 4375
    "socket ",       # 4130
    "alloca",        # 3711
    "strcpy",        # 3610
    "wcscpy",        # 3448
    "calloc",        # 3163
    "realloc",       # 3157
    "socket",        # 3036
    "recv",          # 3036
    "htons",         # 3036
    "memcpy",        # 2879
    "fopen",         # 2855
    "memmove",       # 2828
    "fscanf",        # 2520
    "strchr",        # 2224
    "fclose",        # 2076
    "wcscat",        # 1850
    "listen",        # 1519
    "bind",          # 1519
    "accept",        # 1519
    "inet_addr",     # 1517
    "connect",       # 1517
    "fgetws",        # 1503
    "strncpy",       # 1270
    "wcschr",        # 1206
    "atoi",          # 1196
    "strncat",       # 905
    "wcsncpy",       # 896
    "strtoul",       # 771
    "new",           # 706
    "getenv",        # 553
    "va_start",      # 525
    "va_end",        # 525
    "snprintf",      # 454
    "strdup",        # 438
    "wcsdup",        # 417
    "fscanf ",       # 366
    "wcsncat",       # 350
    "popen",         # 245
    "system",        # 230
    "begin",         # 172
    "end",
    "sqrt",          # 155
    "abs",           # 155
    "printf",        # 151
    "vfprintf",      # 147
    "fprintf",       # 147
    "vprintf",       # 144
    "sscanf",        # 144
    "wprintf",       # 120
    "vwprintf",      # 120
    "swscanf",       # 120
    "fwprintf",      # 120
    "pclose",        # 118
    "vfwprintf",     # 114
    "putenv",        # 100
    "execl",         # 98
    "execlp",        # 90
    "flose",         # 52
    "freopen",       # 46
]

class InsEmbedding:
    @typechecked
    def __init__(self, regs:Registers):
        self.regs = regs
        self.groups_count = 8

    @typechecked
    def size(self) -> int:
        # 1 - instr or funcall, 3 - mem_read, mem_write, immediate arg
        return 1 + 3 + (len(self.regs.gp) + RegisterCategory.MAX.value)* 2 + self.groups_count

    @typechecked
    def instr(self, ins:capstone.CsInsn) -> Union[bytes, int]:
        mem_read, mem_write, imm = 0, 0, 0
        groups = bytearray(self.groups_count)
        regs_write = bytearray(len(self.regs.gp) + RegisterCategory.MAX.value)
        regs_read = bytearray(len(self.regs.gp) + RegisterCategory.MAX.value)

        for op in ins.operands:
            match op.type:
                case capstone.CS_OP_MEM:
                    if op.access & capstone.CS_AC_READ:
                        mem_read = 1
                    if op.access & capstone.CS_AC_WRITE:
                        mem_write = 1
                case capstone.CS_OP_IMM:
                    imm = 1
                case capstone.CS_OP_REG:
                    rind = self.regs.index(ins.reg_name(op.reg))
                    if isinstance(rind, RegisterCategory):
                        rind = len(self.regs.gp) + rind.value
                    if op.access & capstone.CS_AC_READ:
                        regs_read[rind] = 1
                    if op.access & capstone.CS_AC_WRITE:
                        regs_write[rind] = 1

        for i in ins.groups:
            if i < 100: # visually, groups over 100 are sse, mode64 and other less important stuff
                if i < len(groups):
                    groups[i] = 1
                else:
                    print('unexpected group:', i, ins.group_name(i))
                    raise

        res = bytes([1, mem_read, mem_write, imm]) + regs_write + regs_read + groups
        assert len(res) == self.size()
        return res

    @typechecked
    def fun_index(self, fname:str) -> Union[None, int]:
        for i, common_fn in enumerate(common_functions):
            if fname in common_fn:
                return i
        return None

    @typechecked
    def fun(self, fname:str) -> bytes:
        res = bytearray(self.size())
        i = self.fun_index(fname)
        if i is not None:
            res[i + 1] = 1
        return bytes(res)


    @typechecked
    def block(self, node) -> tuple[bytes, ...]:
        if node.block:
            return tuple(self.instr(ins.insn) for ins in node.block.disassembly.insns)
        elif node.name is not None:
            return (self.fun(node.name),)
        else:
            assert False, f'Invalid node: {node}'

@typechecked
def disasm_graph(out_graph:nx.DiGraph, graph:nx.DiGraph, emb) -> set[tuple]:
    '''
    Add numeric edges to out_graph with embedding attached
    based on graph - CFG from angr
    returns edges added to out_graph
    '''
    res = set()
    for a, b in graph.edges:
        ia, ib = id(a), id(b)
        out_graph.add_edge(ia, ib)
        da = emb.block(a)
        db = emb.block(b)
        out_graph.nodes[ia]['disasm'] = da
        out_graph.nodes[ib]['disasm'] = db
        out_graph.nodes[ia]['addr'] = a.addr
        out_graph.nodes[ib]['addr'] = b.addr
        res.add((da, db))
    assert all('disasm' in out_graph.nodes[ia] for ia in out_graph.nodes)
    return res