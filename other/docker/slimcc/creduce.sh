#!/bin/sh

if ! gcc -I/work/c-toxcore/toxcore -fsyntax-only crash.c; then
  exit 1
fi
/work/slimcc/slimcc -I/work/c-toxcore/toxcore -c crash.c 2>&1 | grep "file_exists: Assertion"
