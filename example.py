#!/usr/bin/python3
import argparse
from os import path
import pickle
import sys

import angr
from cwe_explorer import CWEExplorer, CWEExplorerConfig


ap = argparse.ArgumentParser(
    'example.py',
    description='Example script for using CWE-Explorer from your script',
    usage='If trained with default config, run as\n'
          './example.py \\\n'
          '    --model-dir=cwe_explorer/train/data/amd64-gcc/minimal/m1bl20pl6s8/model \\\n'
          '    --config=cwe_explorer/train/data/amd64-gcc/minimal/m1bl20pl6s8/config.json \\\n'
          '    --proj-file=example.proj\n'
          '    /bin/ls')
ap.add_argument('--proj-file', default=None, help='File name to store/load angr project')

ap.add_argument('--model-dir', help='Path to models directory')
ap.add_argument('--config', help='config.json used for model training')

ap.add_argument('bin', help='binary file to analyze')

args = ap.parse_args()

assert path.isdir(args.model_dir)
assert path.isfile(args.config)
assert path.isfile(args.proj_file) or not path.exists(args.proj_file) or not args.proj_file

models = { # Add more models that you care about
    'stack_overflow' : path.join(args.model_dir, 'CWE-121.ubj') # stack_overflow is just a user-friendly name here
}

config_json = path.join(args.model_dir, 'config.json')

if args.proj_file and path.isfile(args.proj_file):
    # Cache the angr project to save time on repeated runs when playing with the script
    print('Reading from', args.proj_file)
    with open(args.proj_file, 'rb') as f:
        proj = pickle.load(f)
        cfg = proj.kb.cfgs.get_most_accurate()
else:
    proj = angr.Project(args.bin, load_options={'auto_load_libs': False, 'load_debug_info': True})
    cfg = proj.analyses.CFGEmulated(resolve_indirect_jumps = True, normalize=True)
    if args.proj_file:
        with open(args.proj_file, 'wb') as f:
            pickle.dump(proj, f)

# Create the explorer
config = CWEExplorerConfig(proj.arch, args.config, models)
cwex = CWEExplorer(cfg, config)
print('Target blocks:', len(cwex.ok_blocks))

# Init simulation
sim = proj.factory.simulation_manager(save_unconstrained=True)
sim.use_technique(angr.exploration_techniques.MemoryWatcher())
sim.use_technique(angr.exploration_techniques.LoopSeer())
sim.use_technique(cwex)

start_state = proj.factory.entry_state()
sim.active.append(start_state)

# if you decide to call explore() do not pass CFG to it
# it would make Explorer will do extra work already covered by CWEExplorer
n = 0
while sim.active:
    for i in range(10):
        sim.step()
        n += 1
    print(n, sim)
    # States you would see in sim.stack_overflow stash are states that followed through
    # all of N (6 by default) basic blocks detected by model.
    # You may want to play with these states and a few states back in their history.
    # But the real catch would be in unconstrained stash.
    # CWEExplorer just tries to guide there.
