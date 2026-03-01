#!/bin/sh

set -eux -o pipefail

GIT_ROOT="$(git rev-parse --show-toplevel)"
cd "$GIT_ROOT"

docker build \
  -t toxchat/bootstrap-node \
  -f other/bootstrap_daemon/docker/Dockerfile \
  --build-arg CHECK=true \
  .
