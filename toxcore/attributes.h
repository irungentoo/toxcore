/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
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

#ifndef __clang__
#define _Nonnull
#define _Nullable
#endif

#ifdef SPARSE
#define bitwise __attribute__((bitwise))
#define force __attribute__((force))
#else
#define bitwise
#define force
#endif

//!TOKSTYLE+

#endif /* C_TOXCORE_TOXCORE_ATTRIBUTES_H */
