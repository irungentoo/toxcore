#!/bin/sh

set -eux

SANITIZER="${1:-asan}"

cp -a /c-toxcore .
cd c-toxcore
.circleci/cmake-"$SANITIZER" || (cat /home/builder/c-toxcore/_build/CMakeFiles/CMakeError.log && false)
