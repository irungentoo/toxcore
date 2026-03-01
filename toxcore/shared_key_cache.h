/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_SHARED_KEY_CACHE_H
#define C_TOXCORE_TOXCORE_SHARED_KEY_CACHE_H

#include <stdint.h>     // uint*_t

#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This implements a cache for shared keys, since key generation is expensive.
 */

typedef struct Shared_Key_Cache Shared_Key_Cache;

/**
 * @brief Initializes a new shared key cache.
 * @param mono_time Time object for retrieving current time.
 * @param self_secret_key Our own secret key of length CRYPTO_SECRET_KEY_SIZE,
 * it must not change during the lifetime of the cache.
 * @param timeout Number of milliseconds, after which a key should be evicted.
 * @param keys_per_slot There are 256 slots, this controls how many keys are stored per slot and the size of the cache.
 * @return nullptr on error.
 */
Shared_Key_Cache *_Nullable shared_key_cache_new(const Logger *_Nonnull log, const Mono_Time *_Nonnull mono_time, const Memory *_Nonnull mem, const uint8_t *_Nonnull self_secret_key, uint64_t timeout,
        uint8_t keys_per_slot);

/**
 * @brief Deletes the cache and frees all resources.
 * @param cache Cache to delete or nullptr.
 */
void shared_key_cache_free(Shared_Key_Cache *_Nullable cache);
/**
 * @brief Looks up a key from the cache or computes it if it didn't exist yet.
 * @param cache Cache to perform the lookup on.
 * @param public_key Public key, used for the lookup and computation.
 *
 * @return The shared key of length CRYPTO_SHARED_KEY_SIZE, matching the public key and our secret key.
 * @return nullptr on error.
 */
const uint8_t *_Nullable shared_key_cache_lookup(Shared_Key_Cache *_Nonnull cache, const uint8_t public_key[_Nonnull CRYPTO_PUBLIC_KEY_SIZE]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_SHARED_KEY_CACHE_H */
