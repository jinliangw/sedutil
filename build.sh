#!/bin/bash
set -e
set -x
git submodule init
git submodule update
autoreconf --install
LDFLAGS=-static ./configure
make -j
echo "Build done"
