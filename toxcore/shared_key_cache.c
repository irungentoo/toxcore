/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "shared_key_cache.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>     // calloc(...)
#include <string.h>     // memcpy(...)

#include "ccompat.h"
#include "crypto_core.h"
#include "mono_time.h"

typedef struct Shared_Key {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint64_t time_last_requested;
} Shared_Key;

struct Shared_Key_Cache {
    Shared_Key *keys;
    const uint8_t* self_secret_key;
    uint64_t timeout; /** After this time (in seconds), a key is erased on the next housekeeping cycle */
    const Mono_Time *time;
    uint8_t keys_per_slot;
};

non_null()
static bool shared_key_is_empty(const Shared_Key *k) {
    assert(k != nullptr);
    /*
     * Since time can never be 0, we use that to determine if a key slot is empty.
     * Additionally this allows us to use crypto_memzero and leave the slot in a valid state.
     */
    return k->time_last_requested == 0;
}

non_null()
static void shared_key_set_empty(Shared_Key *k) {
    crypto_memzero(k, sizeof (Shared_Key));
    assert(shared_key_is_empty(k));
}

Shared_Key_Cache *shared_key_cache_new(const Mono_Time *time, const uint8_t *self_secret_key, uint64_t timeout, uint8_t keys_per_slot)
{
    if (time == nullptr || self_secret_key == nullptr || timeout == 0 || keys_per_slot == 0) {
        return nullptr;
    }

    // Time must not be zero, since we use that as special value for empty slots
    if (mono_time_get(time) == 0) {
        // Fail loudly in debug environments
        assert(false);
        return nullptr;
    }

    Shared_Key_Cache *res = (Shared_Key_Cache *)calloc(1, sizeof (Shared_Key_Cache));
    if (res == nullptr) {
        return nullptr;
    }

    res->self_secret_key = self_secret_key;
    res->time = time;
    res->keys_per_slot = keys_per_slot;
    // We take one byte from the public key for each bucket and store keys_per_slot elements there
    const size_t cache_size = 256 * keys_per_slot;
    res->keys = (Shared_Key *)calloc(cache_size, sizeof (Shared_Key));

    if (res->keys == nullptr) {
        free(res);
        return nullptr;
    }

    crypto_memlock(res->keys, cache_size * sizeof (Shared_Key));

    return res;
}

void shared_key_cache_free(Shared_Key_Cache *cache)
{
    if (cache == nullptr) {
        return;
    }

    const size_t cache_size = 256 * cache->keys_per_slot;
    // Don't leave key material in memory
    crypto_memzero(cache->keys, cache_size * sizeof (Shared_Key));
    crypto_memunlock(cache->keys, cache_size * sizeof (Shared_Key));
    free(cache->keys);
    free(cache);
}

/* NOTE: On each lookup housekeeping is performed to evict keys that did timeout. */
const uint8_t *shared_key_cache_lookup(Shared_Key_Cache *cache, const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE])
{
    // caching the time is not necessary, but calls to mono_time_get(...) are not free
    const uint64_t cur_time = mono_time_get(cache->time);
    // We can't use the first and last bytes because they are masked in curve25519. Selected 8 for good alignment.
    const uint8_t bucket_idx = public_key[8];
    Shared_Key* bucket_start = &cache->keys[bucket_idx*cache->keys_per_slot];

    const uint8_t* found = nullptr;

    // Perform lookup
    for(size_t i = 0; i < cache->keys_per_slot; ++i) {
        if (shared_key_is_empty(&bucket_start[i])) {
            continue;
        }

        if (pk_equal(public_key, bucket_start[i].public_key)) {
            found = bucket_start[i].shared_key;
            bucket_start[i].time_last_requested = cur_time;
            break;
        }
    }

    // Perform housekeeping for this bucket
    for (size_t i = 0; i < cache->keys_per_slot; ++i) {
        if (shared_key_is_empty(&bucket_start[i])) {
            continue;
        }

        const bool timed_out = (bucket_start[i].time_last_requested + cache->timeout) < cur_time;
        if (timed_out) {
            shared_key_set_empty(&bucket_start[i]);
        }
    }

    if (found == nullptr) {
        // Insert into cache

        uint64_t oldest_timestamp = UINT64_MAX;
        size_t oldest_index = 0;

        /*
         *  Find least recently used entry, unused entries are prioritised,
         *  because their time_last_requested field is zeroed.
         */
        for (size_t i = 0; i < cache->keys_per_slot; ++i) {
            if (bucket_start[i].time_last_requested < oldest_timestamp) {
                oldest_timestamp = bucket_start[i].time_last_requested;
                oldest_index = i;
            }
        }

        // Compute the shared key for the cache
        if (encrypt_precompute(public_key, cache->self_secret_key, bucket_start[oldest_index].shared_key) != 0) {
            // Don't put anything in the cache on error
            return nullptr;
        }

        // update cache entry
        memcpy(bucket_start[oldest_index].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
        bucket_start[oldest_index].time_last_requested = cur_time;
        found = bucket_start[oldest_index].shared_key;
    }

    return found;
}
