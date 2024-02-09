#!/usr/bin/env bash

# Common docker build script usable by many builds in the other/docker
# directory. We're using a common dockerignore that ignores everything except
# sources and CMake scripts. Subdirectories can contain a "dockerignore" file
# (note the missing "." at the start) that will be pasted to the end of the
# common dockerignore file. This way, we can use "COPY ." and get all the
# files we need at once, which is much faster, more flexible, and less
# error-prone than manually writing lots of COPY directives.

SOURCESDIR="$(dirname "${BASH_SOURCE[0]}")"
DOCKERDIR="$(dirname "${BASH_SOURCE[1]}")"
BUILD="$(basename "$DOCKERDIR")"

set -eux
cat "$SOURCESDIR/sources.Dockerfile.dockerignore" >"$DOCKERDIR/$BUILD.Dockerfile.dockerignore"
if [ -f "$DOCKERDIR/dockerignore" ]; then
  cat "$DOCKERDIR/dockerignore" >>"$DOCKERDIR/$BUILD.Dockerfile.dockerignore"
fi

docker build "${DOCKERFLAGS[@]}" -t "toxchat/c-toxcore:$BUILD" -f "other/docker/$BUILD/$BUILD.Dockerfile" .
