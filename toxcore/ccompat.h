/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2021 The TokTok team.
 */

/**
 * C language compatibility macros for varying compiler support.
 */
#ifndef C_TOXCORE_TOXCORE_CCOMPAT_H
#define C_TOXCORE_TOXCORE_CCOMPAT_H

#include <stdbool.h>

bool unused_for_tokstyle(void);

//!TOKSTYLE-

// Variable length arrays.
// VLA(type, name, size) allocates a variable length array with automatic
// storage duration. VLA_SIZE(name) evaluates to the runtime size of that array
// in bytes.
//
// If C99 VLAs are not available, an emulation using alloca (stack allocation
// "function") is used. Note the semantic difference: alloca'd memory does not
// get freed at the end of the declaration's scope. Do not use VLA() in loops or
// you may run out of stack space.
#if !defined(DISABLE_VLA) && !defined(_MSC_VER) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
// C99 VLAs.
#define VLA(type, name, size) type name[size]
#define SIZEOF_VLA sizeof
#else

// Emulation using alloca.
#ifdef _WIN32
#include <malloc.h>
#elif defined(__COMPCERT__)
// TODO(iphydf): This leaks memory like crazy, so compcert is useless for now.
// Once we're rid of VLAs, we can remove this and compcert becomes useful.
#define alloca malloc
#include <stdlib.h>
#elif defined(__linux__)
#include <alloca.h>
#else
#include <stdlib.h>
#if !defined(alloca) && defined(__GNUC__)
#define alloca __builtin_alloca
#endif
#endif

#define VLA(type, name, size)                           \
  const size_t name##_size = (size) * sizeof(type);     \
  type *const name = (type *)alloca(name##_size)
#define SIZEOF_VLA(name) name##_size

#endif

#if !defined(__cplusplus) || __cplusplus < 201103L
#define nullptr NULL
#ifndef static_assert
#define static_assert(cond, msg) extern const int unused_for_static_assert
#endif
#endif

#ifdef __GNUC__
#define GNU_PRINTF(f, a) __attribute__((__format__(__printf__, f, a)))
#else
#define GNU_PRINTF(f, a)
#endif

//!TOKSTYLE+

#endif // C_TOXCORE_TOXCORE_CCOMPAT_H
