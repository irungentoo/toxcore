#!/bin/bash

. .github/scripts/flags-clang.sh

add_ld_flag -Wl,-z,defs

# Make compilation error on a warning
add_flag -Werror

# Coverage flags.
add_flag --coverage

# Optimisation, but keep stack traces useful.
add_c_flag -fno-inline -fno-omit-frame-pointer

# Show useful stack traces on crash.
add_flag -fsanitize=undefined -fno-sanitize-recover=all -D_DEBUG

# In test code (_test.cc and libgtest), throw away all debug information.
# We only care about stack frames inside toxcore (which is C). Without this,
# mallocfail will spend a lot of time finding all the ways in which gtest can
# fail to allocate memory, which is not interesting to us.
add_cxx_flag -g0

# Continue executing code in error paths so we can see it cleanly exit (and the
# test code itself may abort).
add_flag -DABORT_ON_LOG_ERROR=false
