#!/bin/bash

. .github/scripts/flags.sh

# Add all warning flags we can.
add_flag -Wall
add_flag -Wextra
add_flag -Weverything

# Disable specific warning flags for both C and C++.

# Very verbose, not very useful. This warns about things like int -> uint
# conversions that change sign without a cast and narrowing conversions.
add_flag -Wno-conversion
# TODO(iphydf): Check enum values when received from the user, then assume
# correctness and remove this suppression.
add_flag -Wno-covered-switch-default
# We use C99, so declarations can come after statements.
add_flag -Wno-declaration-after-statement
# Due to clang's tolower() macro being recursive
# https://github.com/TokTok/c-toxcore/pull/481
add_flag -Wno-disabled-macro-expansion
# We don't put __attribute__ on the public API.
add_flag -Wno-documentation-deprecated-sync
# Bootstrap daemon does this.
add_flag -Wno-format-nonliteral
# struct Foo foo = {0}; is a common idiom. Missing braces means we'd need to
# write {{{0}}} in some cases, which is ugly and a maintenance burden.
add_flag -Wno-missing-braces
add_flag -Wno-missing-field-initializers
# We don't use this attribute. It appears in the non-NDEBUG stderr logger.
add_flag -Wno-missing-noreturn
# Useful sometimes, but we accept padding in structs for clarity.
# Reordering fields to avoid padding will reduce readability.
add_flag -Wno-padded
# This warns on things like _XOPEN_SOURCE, which we currently need (we
# probably won't need these in the future).
add_flag -Wno-reserved-id-macro
# TODO(iphydf): Clean these up. They are likely not bugs, but still
# potential issues and probably confusing.
add_flag -Wno-sign-compare
# __attribute__((nonnull)) causes this warning on defensive null checks.
add_flag -Wno-tautological-pointer-compare
# Our use of mutexes results in a false positive, see 1bbe446.
add_flag -Wno-thread-safety-analysis
# File transfer code has this.
add_flag -Wno-type-limits
# Callbacks often don't use all their parameters.
add_flag -Wno-unused-parameter
# cimple does this better
add_flag -Wno-unused-function
# libvpx uses __attribute__((unused)) for "potentially unused" static
# functions to avoid unused static function warnings.
add_flag -Wno-used-but-marked-unused
# We use variable length arrays a lot.
add_flag -Wno-vla
# Disable warnings about unknown Doxygen commands
add_flag -Wno-documentation-unknown-command

# Disable specific warning flags for C++.

# Comma at end of enum is supported everywhere we run.
add_cxx_flag -Wno-c++98-compat-pedantic
# TODO(iphydf): Stop using flexible array members.
add_cxx_flag -Wno-c99-extensions
# We're C-compatible, so use C style casts.
add_cxx_flag -Wno-old-style-cast
# GTest does this.
add_cxx_flag -Wno-global-constructors

# Downgrade to warning so we still see it.
add_flag -Wno-error=unreachable-code
add_flag -Wno-error=unused-variable
