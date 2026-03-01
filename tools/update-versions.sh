#!/usr/bin/env bash

set -eux -o pipefail

VERSION=$1

GIT_ROOT=$(git rev-parse --show-toplevel)
cd "$GIT_ROOT"

# Strip suffixes (e.g. "-rc.1") from the version for the toxcore version sync.
VERSION="${VERSION%-*}"

IFS="." read -ra version_parts <<<"$VERSION"

other/version-sync "$GIT_ROOT" "${version_parts[0]}" "${version_parts[1]}" "${version_parts[2]}"
