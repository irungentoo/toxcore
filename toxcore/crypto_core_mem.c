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
