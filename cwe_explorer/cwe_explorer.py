import argparse
import json
from os import path, listdir
from collections import defaultdict
from typing import Iterator
import itertools as it
import more_itertools as mit
from typeguard import typechecked

import archinfo
import angr
from angr.knowledge_plugins.cfg import CFGModel
from angr.analyses.cfg import CFGBase
import xgboost as xgb
import networkx as nx
import numpy as np

from .train.embedding import Registers, RegistersPacking, InsEmbedding, disasm_graph
from .train.flatten import disasm_path, expand_paths

class CWEExplorerConfig:

    @typechecked
    def __init__(self, architecture:archinfo.Arch, config_file:str, models:dict[str, str]):
        assert path.isfile(config_file)
        assert all(path.isfile(i) for i in models.values())

        self.model_files = models.copy()

        with open(config_file, 'rb') as f:
            conf = json.load(f)

        match conf['REGPACK']:
            case 'all':
                pack = RegistersPacking.ALL
            case 'subregisters':
                pack = RegistersPacking.SUBREGISTERS
            case 'minimal':
                pack = RegistersPacking.COMPACT
            case errval:
                raise ValueError('Config: Invalid REGPACK', errval)

        self.embedding = InsEmbedding(Registers(architecture, pack))

        self.merge_by = conf['MERGE_BY']
        self.block_len = conf['BLOCK_LEN']
        self.max_path_len = conf["MAX_PATH_LEN"]
        self.max_successors = conf['MAX_SUCCESSORS']

        assert isinstance(self.merge_by, int)
        assert isinstance(self.block_len, int)
        assert isinstance(self.max_path_len, int)
        assert isinstance(self.max_successors, int)

    @typechecked
    def models(self) -> Iterator[tuple[str, xgb.XGBModel]]:
        model = xgb.XGBModel()
        for f, p in self.model_files.items():
            model.load_model(p)
            yield f, model


@typechecked
def all_paths(cfg:CFGModel | CFGBase, conf:CWEExplorerConfig) -> dict[bytes, list[tuple[int, ...]]]:
    disasm = nx.DiGraph()
    disasm_graph(disasm, cfg.graph, conf.embedding)

    res = defaultdict(list)
    queue = set(i for i in disasm.edges())
    for path in expand_paths(disasm, queue, conf.max_path_len, conf.max_successors, lambda a, b: True):
        vec = disasm_path(disasm, path, conf.merge_by, conf.block_len)
        res[vec].append(path)

    return dict(res)


@typechecked
def predict_paths(paths:dict[bytes, list[tuple[int, ...]]], model:xgb.XGBModel, threshold:float) -> Iterator[tuple[int, ...]]:
    keys = tuple(paths.keys())
    pred = model.predict(np.array([np.frombuffer(vec, dtype=np.uint8) for vec in keys], dtype=np.float32))
    for i, v in enumerate(pred >= threshold):
        if v:
            for path in paths[keys[i]]:
                if path:
                    yield path


@typechecked
def classify_paths(paths:dict[bytes, list[tuple[int, ...]]], conf:CWEExplorerConfig, threshold:float) -> dict[tuple[int, ...], str]:
    if threshold < 0 or threshold > 1:
        raise ValueError('Invalid threshold', threshold)

    path2model = dict()
    for mfile, model in conf.models():
        for path in predict_paths(paths, model, threshold):
            path2model[path] = mfile

    if len(path2model) == 0:
        raise ValueError('No interesting blocks found in binary')

    assert max(len(i) for i in path2model.keys()) == min(len(i) for i in path2model.keys())
    return path2model


class CWEExplorer(angr.ExplorationTechnique):
    @typechecked
    def __init__(self,
                 cfg:CFGModel | CFGBase,
                 config:CWEExplorerConfig,
                 threshold:float = 0.5,
                 avoid_stash="avoid"):
        super().__init__()
        self.avoid_stash = avoid_stash

        p = all_paths(cfg, config)
        self.cfg = cfg
        path2model = classify_paths(p, config, threshold)
        self.path_len = len(next(iter(path2model.keys())))

        self.id2node = { id(n) : n for n in self.cfg.nodes() }

        self.ok_blocks = set()
        self.addr2model = {tuple(self.__id2addr(i) for i in path) : md for path, md in path2model.items()}
        self.starts = set(path[0] for path in self.addr2model.keys())
        self.ends = set(path[-1] for path in self.addr2model.keys())

        seen = set()
        queue = [self.id2node[i[0]] for i in path2model.keys()]
        while queue:
            item = queue.pop()
            item_id = id(item)
            if item_id not in seen:
                self.ok_blocks.add(item.addr)

                seen.add(item_id)
                queue.extend(item.predecessors)

    def setup(self, simgr):
        if self.avoid_stash not in simgr.stashes:
            simgr.stashes[self.avoid_stash] = []

    def __id2addr(self, item_id):
        if node := self.id2node.get(item_id):
            if block := node.block:
                return block.addr
        return None

    def __get_hist_addrs(self, state):
        r = [i.addr for i in mit.tail(self.path_len - 1, state.history.lineage)]
        r.append(state.addr)
        return r

    def __find(self, state) -> str|bool:
        '''
        Check is state is on target
        Returns:
         - string with model name
         - True - on the matched path, but not done yet
         - False - not interesting
        '''
        hist = tuple(it.dropwhile(lambda addr: addr not in self.starts, self.__get_hist_addrs(state)))
        if not hist:
            return False

        for path, cwe in self.addr2model.items():
            if all(p == h for p, h in zip(path, hist)):
                if len(hist) == len(path):
                    return cwe
                else: # state may be approaching a target
                    return True # This is ugly
        return False

    def __find_intermediate(self, state):
        '''
        Check if state accidentally stumbled upon a target.
        Can be caused by path to later target including another target
        '''
        hist = self.__get_hist_addrs(state)
        return self.addr2model.get(tuple(hist))

    def filter(self, simgr, state, **kwargs):
        if state.addr in self.ends:
            if report := self.__find_intermediate(state):
                return report

        if state.addr in self.ok_blocks:
            return simgr.filter(state, **kwargs) # To next ExplorationTechnique

        match self.__find(state):
            case False: pass
            case True: return simgr.filter(state, **kwargs) # To next ExplorationTechnique
            case report:
                return report

        return self.avoid_stash
