#!/bin/sh

NPROC=`nproc`

SCREEN_SESSION=freebsd
SSH_PORT=10022

RUN() {
  ssh -t -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@localhost -p $SSH_PORT "$@"
}
