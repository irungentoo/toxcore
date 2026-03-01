/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

/**
 * nonnull attributes for GCC/Clang and Cimple.
 */
#ifndef C_TOXCORE_TOXCORE_TOX_ATTRIBUTES_H
#define C_TOXCORE_TOXCORE_TOX_ATTRIBUTES_H

/* No declarations here. */

//!TOKSTYLE-

#ifndef __clang__
#define _Nonnull
#define _Nullable
#endif

//!TOKSTYLE+

#endif /* C_TOXCORE_TOXCORE_TOX_ATTRIBUTES_H */
