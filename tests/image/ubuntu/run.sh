#!/bin/bash

set -exo pipefail

./bootstrap
./configure
make
make check
make install
ldconfig
