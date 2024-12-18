#!/usr/bin/python3
import argparse
import gzip
import pickle
from enum import Enum

import numpy as np
from typeguard import typechecked
import networkx as nx

from flatten import disasm_path, expand_paths

class EdgeKind(Enum):
    GOOD = 0
    BAD = 1
    OTHER = 2

    @staticmethod
    def get(graph, a, b):
        d = graph.get_edge_data(a, b)
        assert not ('bad' in d and 'good' in d)
        if 'bad' in d:
            return EdgeKind.BAD
        elif 'good' in d:
            return EdgeKind.GOOD
        else:
            return EdgeKind.OTHER

    def inverse(self):
        match self:
            case EdgeKind.GOOD:
                return EdgeKind.BAD
            case EdgeKind.BAD:
                return EdgeKind.GOOD
            case _:
                raise KeyError()

@typechecked
def expand_training_paths(
    graph:nx.DiGraph, merge_by:int, block_len:int, max_path_len:int, max_successors:int,
    res:set[bytes], edge_kind:EdgeKind) -> set[bytes]:

    queue = set(i for i in graph.edges() if EdgeKind.get(graph, *i) == edge_kind)
    inv_edge_kind = edge_kind.inverse()
    filter_edge = lambda a, b: EdgeKind.get(graph, a, b) != inv_edge_kind

    for i in expand_paths(graph, queue, max_path_len, max_successors, filter_edge):
        res.add(disasm_path(graph, i, merge_by, block_len) + bytes([edge_kind.value]))

    return res


ap = argparse.ArgumentParser('mkdata.py', description='')
ap.add_argument('--max-path-len', type=int, default=5, help='max subpath length')
ap.add_argument('--merge-by', type=int, default=None, help='merge n instructions into one')
ap.add_argument('--block-len', type=int, default=None, help='max instructions per block')
ap.add_argument('--max-successors', type=int, default=8, help='max successors per node, drop nodes with too many successors')
ap.add_argument('--inp', required=True, help='input CFG pickle file')
ap.add_argument('--out', required=True, help='output file')
args = ap.parse_args()

with gzip.open(args.inp, 'rb') as f:
    graph = pickle.load(f)

res = set()
expand_training_paths(graph, args.merge_by, args.block_len, args.max_path_len, args.max_successors, res, EdgeKind.GOOD)
expand_training_paths(graph, args.merge_by, args.block_len, args.max_path_len, args.max_successors, res, EdgeKind.BAD)

res = np.array([np.frombuffer(i, dtype=np.uint8) for i in res])

with open(args.out, 'wb') as f:
    np.savez_compressed(f,res)

