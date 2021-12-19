/* SPDX-License-Identifier: ISC
 * Copyright © 2016-2021 The TokTok team.
 */

#include "crypto_core.h"

#ifndef VANILLA_NACL
// We use libsodium by default.
#include <sodium.h>
#else
#include <string.h>
#endif


void crypto_memzero(void *data, size_t length)
{
#ifndef VANILLA_NACL
    sodium_memzero(data, length);
#else
    memset(data, 0, length);
#endif
}

/**
 * Locks `length` bytes of memory pointed to by `data`. This will attempt to prevent
 * the specified memory region from being swapped to disk.
 *
 * Returns true on success.
 */
bool crypto_memlock(void *data, size_t length)
{
#ifndef VANILLA_NACL

    if (sodium_mlock(data, length) != 0) {
        return false;
    }

    return true;
#else
    return false;
#endif
}

/**
 * Unlocks `length` bytes of memory pointed to by `data`. This allows the specified
 * memory region to be swapped to disk.
 *
 * This function call has the side effect of zeroing the specified memory region
 * whether or not it succeeds. Therefore it should only be used once the memory
 * is no longer in use.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
bool crypto_memunlock(void *data, size_t length)
{
#ifndef VANILLA_NACL

    if (sodium_munlock(data, length) != 0) {
        return false;
    }

    return true;
#else
    return false;
#endif
}
