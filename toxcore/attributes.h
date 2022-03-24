/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

/**
 * printf and nonnull attributes for GCC/Clang and Cimple.
 */
#ifndef C_TOXCORE_TOXCORE_ATTRIBUTES_H
#define C_TOXCORE_TOXCORE_ATTRIBUTES_H

/* No declarations here. */

//!TOKSTYLE-

#ifdef __GNUC__
#define GNU_PRINTF(f, a) __attribute__((__format__(__printf__, f, a)))
#else
#define GNU_PRINTF(f, a)
#endif

#if defined(__GNUC__) && defined(_DEBUG) && !defined(__OPTIMIZE__)
#define non_null(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
#define non_null(...)
#endif

#define nullable(...)

//!TOKSTYLE+

#endif // C_TOXCORE_TOXCORE_ATTRIBUTES_H
