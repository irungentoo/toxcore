#!/usr/bin/env bash

check_sha256() {
  [ "$ENABLE_HASH_VERIFICATION" = "true" ] && _check_sha256 "$@"
}

_check_sha256() {
  if ! (echo "$1  $2" | sha256sum -c --status -); then
    echo "Error: sha256 of $2 doesn't match the known one."
    echo "Expected: $1  $2"
    echo "Got: $(sha256sum "$2")"
    return 1
  fi
  echo "sha256 matches the expected one: $1"
  return 0
}
