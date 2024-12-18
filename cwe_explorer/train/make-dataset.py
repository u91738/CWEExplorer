#!/usr/bin/python3
import numpy as np
from random import random
from os import path
from sys import stderr
import json
import argparse

def read_input(fname):
    with open(fname, 'rb') as f:
        return np.load(f)['arr_0'].astype(np.uint8)

ap = argparse.ArgumentParser(
    description='script to train word2vec models on CVEFixes dataset')
ap.add_argument('--inp', required=True, help='input directory')
ap.add_argument('--cwe', required=True, help='cwe id to use')
ap.add_argument('--out', required=True, help='output dir')
args = ap.parse_args()

assert path.isdir(args.out)

with open('data/cwe.json', 'r') as f:
    cwes = json.load(f)

assert args.cwe in cwes

data_files = []
for bin_id in cwes[args.cwe]['id']:
    f = f'{args.inp}/{bin_id}.npz'
    if path.isfile(f):
        data_files.append(f)

train_x, train_y, test_x, test_y = [], [], [], []
print('Collect')
for data_file in data_files:
    data = read_input(data_file)
    if data.size == 0:
        continue

    xs, ys = (train_x, train_y) if random() > 0.1 else (test_x, test_y)

    ydata = data[:,-1]
    bad = (ydata == 1).sum()
    good = (ydata == 0).sum()
    if good == 0 or bad == 0:
        continue
    drop0 = 1 - bad / good if bad / good < 0.9 else None
    drop1 = 1 - good / bad if good / bad < 0.9 else None

    x_batch = []
    y_batch = []
    for d in data:
        x, y = d[:-1], d[-1]
        if y == 0.0 and drop0 and random() < drop0:
            continue
        if y == 1.0 and drop1 and random() < drop1:
            continue

        assert y == 0.0 or y == 1.0
        x_batch.append(x)
        #print(len(x))
        y_batch.append(y)

    xs.append(np.array(x_batch, dtype=np.uint8))
    ys.append(np.array(y_batch, dtype=np.uint8))
data_file = None

print('Reshape')

def batches_to_mmap(fname, batches):
    mlen = 0
    for batch in batches:
        for row in batch:
            mlen += 1

    f = np.memmap(fname, dtype=np.uint8, mode='w+', shape=(mlen, len(batches[0][0])))

    i = 0
    for batch in batches:
        for row in batch:
            f[i] = row
            i += 1

try:
    batches_to_mmap(path.join(args.out, 'test-x.mmap'), test_x)
    test_x = None
    print('Reshape test_x done')

    train_y = np.concatenate(train_y, axis=0, dtype=np.uint8)
    train_y.tofile(path.join(args.out, 'train-y.mmap'))
    train_y = None
    print('Reshape train_y done')

    test_y = np.concatenate(test_y, axis=0, dtype=np.uint8)
    test_y.tofile(path.join(args.out, 'test-y.mmap'))
    test_y = None
    print('Reshape test_y done')

    batches_to_mmap(path.join(args.out, 'train-x.mmap'), train_x)
    print('Reshape train_x done')
except:
    print('Error, delete incomplete results', file=stderr)
    for i in 'test-x.mmap', 'train-y.mmap', 'test-y.mmap', 'train-x.mmap':
        try:
            print(i, file=stderr)
            os.unlink(i)
        except FileNotFoundError:
            print(i, 'Not found', file=stderr)
    raise
