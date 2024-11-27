#!/usr/bin/python3
import argparse
import gzip
import pickle

import angr
import networkx as nx

from embedding import Registers, RegistersPacking, RegisterCategory, BlockEmbedding, InsEmbedding, disasm_graph

ap = argparse.ArgumentParser('cfg.py', description='Get control flow graph from a binary')   
ap.add_argument('--good', help='good binary file to analyze')
ap.add_argument('--bad', help='bad binary file to analyze')
ap.add_argument('--mode', choices=('instruction', 'block'), required=True, help='vector per instruction or per block')
ap.add_argument('--registers', choices=('minimal', 'subregisters', 'all'), default=False)
ap.add_argument('--print-instr-size', default=False, action='store_true')
ap.add_argument('--out', help='output gzip file')
args = ap.parse_args()

lo = {'auto_load_libs': False, 'load_debug_info': True}
good_proj = angr.Project(args.good, load_options=lo)
bad_proj = angr.Project(args.bad, load_options=lo)

good_cfg = good_proj.analyses.CFGFast(resolve_indirect_jumps = True, normalize=True)
bad_cfg = bad_proj.analyses.CFGFast(resolve_indirect_jumps = True, normalize=True)

match args.registers:
    case 'all':
        pack = RegistersPacking.ALL
    case 'subregisters':
        pack = RegistersPacking.SUBREGISTERS
    case _:
        pack = RegistersPacking.COMPACT

regs = Registers(good_proj.arch, pack)
emb = BlockEmbedding(regs) if args.mode == 'block' else InsEmbedding(regs)

if args.print_instr_size:
    print(emb.size())
else:
    res = nx.DiGraph()
    good_da_edges = disasm_graph(res, good_cfg.graph, emb)
    bad_da_edges = disasm_graph(res, bad_cfg.graph, emb)

    for a,b in res.edges:
        de = res.nodes[a]['disasm'], res.nodes[b]['disasm']   
        if de in good_da_edges and de not in bad_da_edges:
            res.get_edge_data(a,b)['good'] = True
        if de not in good_da_edges and de in bad_da_edges:
            res.get_edge_data(a,b)['bad'] = True

    with gzip.open(args.out, 'wb') as f:
        pickle.dump(res, f)
