import networkx as nx
from typing import Iterator
from typeguard import typechecked
import more_itertools as mit

@typechecked
def merge(instructions:list[bytes]) -> bytes:
    if len(instructions):
        return bytes(max(i) for i in mit.zip_equal(*instructions))
    else:
        return b''

@typechecked
def get_vector(block:tuple[bytes, ...], merge_by:int, block_len:int) -> bytes:
    assert len(block)
    assert block_len > 0
    assert merge_by > 0

    r = [merge(i) for i in mit.chunked(block, merge_by)]
    expected_len = len(r[0]) * block_len

    if len(block) > block_len:
        r[block_len-1:] = [merge(r[block_len:])]
    r = b''.join(r)
    if len(r) < expected_len:
        r += bytes(expected_len - len(r))

    return r

@typechecked
def expand_paths(graph:nx.DiGraph, queue:set[tuple], max_path_len:int, max_successors:int, filter_edge) \
     -> Iterator[tuple[int, ...]]:

    while queue:
        i = queue.pop()
        if len(i) >= max_path_len:
            yield i
            continue

        successors = [s for s in graph.successors(i[-1]) if filter_edge(i[-1], s)]
        #print('successors:', len(successors))
        if len(successors) <= max_successors:
            for s in successors:
                queue.add(i + (s,))

        predecessors = [s for s in graph.predecessors(i[0]) if filter_edge(s, i[0])]
        #print('predecessors:', len(predecessors))
        if len(predecessors) <= max_successors:
            for p in predecessors:
                queue.add((p,) + i)

def disasm_path(graph, path, merge_by, block_len) -> bytes:
    return b''.join(get_vector(graph.nodes[j]['disasm'], merge_by, block_len) for j in path)
