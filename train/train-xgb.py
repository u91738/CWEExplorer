#!/usr/bin/python3
import numpy as np
import xgboost as xgb
import os
from os import path
import argparse
from sklearn.metrics import f1_score,precision_score,recall_score,mean_squared_error,classification_report
from sklearn.utils import compute_sample_weight
ap = argparse.ArgumentParser(
    description='train xgboost model')
ap.add_argument('--inp', required=True, help='input directory')
ap.add_argument('--out', required=True, help='output file')
args = ap.parse_args()

assert path.dirname(args.out) == '' or path.isdir(path.dirname(args.out)), 'Output directory does not exist'

class Dataset:
    def __init__(self, x, y):
        x_size, y_size = os.stat(x).st_size, os.stat(y).st_size
        self.x = np.memmap(x, dtype=np.uint8, shape=(y_size, x_size // y_size))
        self.y = np.memmap(y, dtype=np.uint8, shape=(y_size,))
        self.iy = self.y
        
train = Dataset(path.join(args.inp, 'train-x.mmap'), path.join(args.inp, 'train-y.mmap'))
test = Dataset(path.join(args.inp, 'test-x.mmap'), path.join(args.inp, 'test-y.mmap'))

y_avg = sum(train.iy) / len(train.iy)
print('Data', train.x.shape, train.y.shape)
print('Yavg:', y_avg)
# print('weight', compute_sample_weight("balanced", train.iy)

print('To DMatrix')
dtrain = xgb.QuantileDMatrix(train.x, label=train.iy)
dtest = xgb.QuantileDMatrix(test.x, label=test.iy)

print('Training')
evallist = [(dtrain, 'train'), (dtest, 'eval')]
param = {
    'max_depth': 40,
    'eta': 0.01,
    'learning_rate':0.05,
    'objective': 'binary:logistic',
    'device' : 'cuda',
    'scale_pos_weight': y_avg / 2,
    'eval_metric': ['error'],
}

model = xgb.train(param, dtrain, 100, evals=evallist)

test_predf = model.predict(dtest)

test_pred = np.array(np.round(test_predf), dtype=int)
print("Classification report: \n", classification_report(test.iy,test_pred))

model.save_model(args.out)

