#!/usr/bin/env bash

set -eux -o pipefail

SYSTEM="$1"
ARCH="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DEP_PREFIX="$PWD/deps-prefix-$SYSTEM-$ARCH"

if [ -d "$DEP_PREFIX" ]; then
  exit 0
fi

if [ -d ../dockerfiles ]; then
  DOCKERFILES="$(realpath ../dockerfiles)"
else
  git clone --depth=1 https://github.com/TokTok/dockerfiles "$SCRIPT_DIR/dockerfiles"
  DOCKERFILES="$SCRIPT_DIR/dockerfiles"
fi

for dep in sodium opus vpx; do
  mkdir -p "external/$dep"
  pushd "external/$dep"
  SCRIPT="$DOCKERFILES/qtox/build_$dep.sh"
  "$SCRIPT" --arch "$SYSTEM-$ARCH" --libtype "static" --buildtype "release" --prefix "$DEP_PREFIX" --macos "10.15"
  popd
  rm -rf "external/$dep"
done
