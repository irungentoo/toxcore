#!/bin/bash

. .github/scripts/flags.sh

# Add all warning flags we can.
add_flag -Wall
add_flag -Wextra

# Some additional warning flags not enabled by any of the above.
add_flag -Wbool-compare
add_flag -Wcast-align
add_flag -Wcast-qual
add_flag -Wchar-subscripts
add_flag -Wdouble-promotion
add_flag -Wduplicated-cond
add_flag -Wempty-body
add_flag -Wenum-compare
add_flag -Wfloat-equal
add_flag -Wformat=2
add_flag -Wframe-address
add_flag -Wframe-larger-than=9000
add_flag -Wignored-attributes
add_flag -Wignored-qualifiers
add_flag -Winit-self
add_flag -Winline
add_flag -Wlarger-than=530000
add_flag -Wmaybe-uninitialized
add_flag -Wmemset-transposed-args
add_flag -Wmisleading-indentation
add_flag -Wmissing-declarations
add_flag -Wnonnull
add_flag -Wnull-dereference
add_flag -Wodr
add_flag -Wredundant-decls
add_flag -Wreturn-type
add_flag -Wshadow
add_flag -Wsuggest-attribute=format
add_flag -Wundef
add_flag -Wunsafe-loop-optimizations
add_flag -Wunused-but-set-parameter
add_flag -Wunused-but-set-variable
add_flag -Wunused-label
add_flag -Wunused-local-typedefs
add_flag -Wunused-value

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
# cimple does this better
add_flag -Wno-unused-function
# struct Foo foo = {0}; is a common idiom. Missing braces means we'd need to
# write {{{0}}} in some cases, which is ugly and a maintenance burden.
add_flag -Wno-missing-braces
# __attribute__((nonnull)) causes this warning on defensive null checks.
add_flag -Wno-nonnull-compare
