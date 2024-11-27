import networkx as nx
from typing import Iterator
from typeguard import typechecked

def get_vector(block, block_len):
    assert len(block)
    if isinstance(block, tuple):
        res = b''.join(block[:block_len])
        return res + bytes(len(block[0]) * block_len - len(res))
    elif isinstance(block, bytes):
        return np.frombuffer(block, dtype=np.uint8)
    else:
        assert False, 'Invalid type in disasm'

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

def disasm_path(graph, path, block_len) -> bytes:
    return b''.join([get_vector(graph.nodes[j]['disasm'], block_len) for j in path])
