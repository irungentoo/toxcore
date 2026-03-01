#!/bin/sh

# Default values
TIMEOUT=300
RETRIES=3

# Automake calls LOG_COMPILER with any flags from AM_LOG_FLAGS and LOG_FLAGS,
# then the test program and its arguments.
# We want to be able to override these via environment variables too.

if [ -n "$TEST_TIMEOUT" ]; then
  TIMEOUT="$TEST_TIMEOUT"
fi

if [ -n "$TEST_RETRIES" ]; then
  RETRIES="$TEST_RETRIES"
fi

# In case we want to pass them as flags in AM_LOG_FLAGS
while true; do
  case "$1" in
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    --retries)
      RETRIES="$2"
      shift 2
      ;;
    *)
      break
      ;;
  esac
done

if [ $# -eq 0 ]; then
  echo "Usage: $0 [--timeout seconds] [--retries count] test-program [args...]"
  exit 1
fi

attempt=0
while [ "$attempt" -le "$RETRIES" ]; do
  if [ "$attempt" -gt 0 ]; then
    echo "Retry #$attempt for: $*"
  fi

  # Use timeout command if available
  if command -v timeout >/dev/null 2>&1; then
    # Use --foreground to avoid issues with signals in some environments
    # Use -s KILL to ensure it dies if it hangs
    timeout --foreground -s KILL "${TIMEOUT}s" "$@"
    status=$?
  else
    # Fallback if timeout is not available
    "$@"
    status=$?
  fi

  # status 0: success
  # status 77: skipped
  # status 99: hard error
  if [ "$status" -eq 0 ] || [ "$status" -eq 77 ] || [ "$status" -eq 99 ]; then
    exit "$status"
  fi

  # If it was timed out by GNU timeout, exit code is 124 (or 137 with -s KILL)
  if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
    echo "Test timed out after ${TIMEOUT}s: $*"
  else
    echo "Test failed with status $status: $*"
  fi

  attempt=$((attempt + 1))
done

exit "$status"
