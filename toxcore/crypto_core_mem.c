/*
 * ISC License
 *
 * Copyright (c) 2013-2016
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "crypto_core.h"

#ifndef VANILLA_NACL
/* We use libsodium by default. */
#include <sodium.h>
#else
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
#include <windows.h>
#include <wincrypt.h>
#endif
#endif


void crypto_memzero(void *data, size_t length)
{
#ifndef VANILLA_NACL
    sodium_memzero(data, length);
#elif defined(_WIN32)
    SecureZeroMemory(data, length);
#elif defined(HAVE_MEMSET_S)

    if (length > 0U) {
        errno_t code = memset_s(data, (rsize_t) length, 0, (rsize_t) length);

        if (code != 0) {
            abort(); /* LCOV_EXCL_LINE */
        }
    }

#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(data, length);
#else
    //!TOKSTYLE-
    volatile uint8_t *volatile pnt = data;
    //!TOKSTYLE+
    size_t i = (size_t) 0U;

    while (i < length) {
        pnt[i] = 0U;
        ++i;
    }

#endif
}

int32_t crypto_memcmp(const uint8_t *p1, const uint8_t *p2, size_t length)
{
#ifndef VANILLA_NACL
    return sodium_memcmp(p1, p2, length);
#else
    //!TOKSTYLE-
    const volatile uint8_t *volatile b1 = p1;
    const volatile uint8_t *volatile b2 = p2;
    //!TOKSTYLE+

    size_t i;
    uint8_t d = (uint8_t) 0U;

    for (i = 0U; i < length; ++i) {
        d |= b1[i] ^ b2[i];
    }

    return (1 & ((d - 1) >> 8)) - 1;
#endif
}
