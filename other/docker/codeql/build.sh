#!/bin/bash
set -e
cmake -GNinja -B build -S .
cmake --build build --parallel "$(nproc)"
