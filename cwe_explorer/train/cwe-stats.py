#!/usr/bin/python3
import json

with open('data/cwe.json', 'r') as f:
    cwes = json.load(f)

print('Name     |  Cnt | Desc')
for cwe, d in sorted(cwes.items(), key=lambda i : len(i[1]['id'])):
    print('%-8s | %4d | %s' % (cwe, len(d['id']), d['desc']))
