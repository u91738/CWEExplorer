#!/bin/sh

set -e

echo Run dependencies
echo sed
sed --version > /dev/null
echo jq
jq --version > /dev/null
echo wget
wget --version > /dev/null
echo unzip
unzip -v > /dev/null

mkdir -p data/juliet data/bin

if [ ! -f data/juliet.zip ]
then
    echo Download dataset
    wget -O data/juliet.zip https://samate.nist.gov/SARD/downloads/test-suites/2022-08-11-juliet-c-cplusplus-v1-3-1-with-extra-support.zip
fi

unzip data/juliet.zip -d data/juliet

echo Remove broken entries
rm -fr data/juliet/98281-v1.0.0 data/juliet/103336-v1.0.0

echo Remove Windows builds
find 'data/juliet' -mindepth 2 -maxdepth 2 -type f -name Makefile | \
while read i
do
    d=$(dirname $i)
    grep -qE 'TARGET\s*=\s*.*[.]exe' "$i" && rm -r "$d" || true
done

echo Allow override of CFLAGS, LDFLAGS, CC, CXX
find 'data/juliet' -mindepth 2 -maxdepth 2 -type f -name Makefile -exec \
    sed -i \
        -e 's/CFLAGS *=/CFLAGS +=/g'       \
        -e 's/LDFLAGS *=/LDFLAGS +=/g'     \
        -e 's/CC *= *g[+][+]/CC = $(CXX)/g'  \
        -e 's/CC *= *gcc/CC ?= gcc/g'      \
        -e 's/rm -r [$][(]BUILD[)]/rm -fr $(BUILD)/g' \
        {} \;

./cwe-gen.py
./cwe-stats.py
