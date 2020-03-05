#!/bin/sh

# Common variables and functions

NPROC=$(nproc)

SCREEN_SESSION=freebsd
SSH_PORT=10022

FREEBSD_VERSION="12.1"
IMAGE_NAME=FreeBSD-${FREEBSD_VERSION}-RELEASE-amd64.raw
# https://download.freebsd.org/ftp/releases/VM-IMAGES/12.1-RELEASE/amd64/Latest/
IMAGE_SHA512="a65da6260f5f894fc86fbe1f27dad7800906da7cffaa5077f82682ab74b6dd46c4ce87158c14b726d74ca3c6d611bea3bb336164da3f1cb990550310b110da22"

RUN() {
  ssh -t -o ConnectionAttempts=120 -o ConnectTimeout=2 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@localhost -p $SSH_PORT "$@"
}

start_vm() {
  screen -d -m qemu-system-x86_64 -curses -m 2048 -smp $NPROC -net user,hostfwd=tcp::${SSH_PORT}-:22 -net nic "$IMAGE_NAME"

  # Wait for ssh to start listening on the port
  while ! echo "exit" | nc localhost ${SSH_PORT} | grep 'OpenSSH'; do
    sleep 5
  done

  # Test that ssh works
  RUN uname -a
  RUN last
}

stop_vm()
{
  # Turn it off
  # We use this contraption because for some reason `shutdown -h now` and
  # `poweroff` result in FreeBSD not shutting down on Travis (they work on my
  # machine though)
  RUN "shutdown -p +5sec && sleep 30" || true

  # Wait for the qemu process to terminate
  while pgrep qemu; do
    sleep 5
  done
}
