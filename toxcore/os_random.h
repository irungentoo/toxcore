/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_RANDOM_H
#define C_TOXCORE_TOXCORE_OS_RANDOM_H

#include "rng.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const Random os_random_obj;

/** @brief System random number generator.
 *
 * Uses libsodium's CSPRNG (on Linux, `/dev/urandom`).
 */
const Random *_Nullable os_random(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_RANDOM_H */
