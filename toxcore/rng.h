/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_RNG_H
#define C_TOXCORE_TOXCORE_RNG_H

#include <stdint.h>

#include "attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Fill a byte array with random bytes.
 *
 * This is the key generator callback and as such must be a cryptographically
 * secure pseudo-random number generator (CSPRNG). The security of Tox heavily
 * depends on the security of this RNG.
 */
typedef void random_bytes_cb(void *_Nullable self, uint8_t *_Nonnull bytes, uint32_t length);

/** @brief Generate a random integer between 0 and @p upper_bound.
 *
 * Should produce a uniform random distribution, but Tox security does not
 * depend on this being correct. In principle, it could even be a non-CSPRNG.
 */
typedef uint32_t random_uniform_cb(void *_Nullable self, uint32_t upper_bound);

/** @brief Virtual function table for Random. */
typedef struct Random_Funcs {
    random_bytes_cb *_Nonnull bytes_callback;
    random_uniform_cb *_Nonnull uniform_callback;
} Random_Funcs;

/** @brief Random number generator object.
 *
 * Can be used by test code and fuzzers to make toxcore behave in specific
 * well-defined (non-random) ways. Production code ought to use libsodium's
 * CSPRNG and use `os_random` below.
 */
typedef struct Random {
    const Random_Funcs *_Nonnull funcs;
    void *_Nullable user_data;
} Random;

void rng_bytes(const Random *_Nonnull rng, uint8_t *_Nonnull bytes, uint32_t length);
uint32_t rng_uniform(const Random *_Nonnull rng, uint32_t upper_bound);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_RNG_H */
