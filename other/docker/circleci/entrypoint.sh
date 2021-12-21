#!/bin/sh

set -eu

SANITIZER="${1:-asan}"

cp -a /c-toxcore .
cd c-toxcore
.circleci/cmake-"$SANITIZER"
