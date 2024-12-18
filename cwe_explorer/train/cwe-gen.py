#!/usr/bin/python3
import json
from os import path

with open('data/juliet/sarifs.json', 'r') as f:
    sarifs = json.load(f)['testCases']

cwes = dict()
for s in sarifs:
    r = s['sarif']['runs'][0]
    t = r['taxonomies'][0]

    assert len(s['sarif']['runs']) == 1
    assert len(r['taxonomies']) == 1

    for taxa in t['taxa']:
        key = f"{t['name']}-{taxa['id']}"
        if key not in cwes:
            cwes[key] = {'id' : [], 'desc' : taxa['name']}
        dirname = s['identifier']
        if path.isdir(path.join('data/juliet', dirname)):
            cwes[key]['id'].append(dirname)


with open('data/cwe.json', 'w') as f:
    json.dump(cwes, f)
