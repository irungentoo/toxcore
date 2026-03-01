#!/bin/sh

set -eux -o pipefail

GIT_ROOT="$(git rev-parse --show-toplevel)"

# Build bootstrap daemon first.
"$GIT_ROOT/other/bootstrap_daemon/docker/build.sh"

# Build websocket server.
cd "$GIT_ROOT/other/bootstrap_daemon/websocket"
docker build -t toxchat/bootstrap-node:latest-websocket .
