#!/bin/sh

. .travis/flags.sh

# Add all warning flags we can.
add_flag -Wall
add_flag -Wextra

# Disable specific warning flags for both C and C++.

# struct Foo foo = {0}; is a common idiom.
add_flag -Wno-missing-field-initializers
# TODO(iphydf): Clean these up. They are likely not bugs, but still
# potential issues and probably confusing.
add_flag -Wno-sign-compare
# File transfer code has this.
add_flag -Wno-type-limits
# Callbacks often don't use all their parameters.
add_flag -Wno-unused-parameter
