/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/*
 * Utilities.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto_core.h" /* for CRYPTO_PUBLIC_KEY_SIZE */


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src)
{
    return public_key_cmp(dest, src) == 0;
}

uint32_t id_copy(uint8_t *dest, const uint8_t *src)
{
    memcpy(dest, src, CRYPTO_PUBLIC_KEY_SIZE);
    return CRYPTO_PUBLIC_KEY_SIZE;
}

int create_recursive_mutex(pthread_mutex_t *mutex)
{
    pthread_mutexattr_t attr;

    if (pthread_mutexattr_init(&attr) != 0) {
        return -1;
    }

    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    /* Create queue mutex */
    if (pthread_mutex_init(mutex, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    pthread_mutexattr_destroy(&attr);

    return 0;
}

int16_t max_s16(int16_t a, int16_t b)
{
    return a > b ? a : b;
}
int32_t max_s32(int32_t a, int32_t b)
{
    return a > b ? a : b;
}
int64_t max_s64(int64_t a, int64_t b)
{
    return a > b ? a : b;
}

int16_t min_s16(int16_t a, int16_t b)
{
    return a < b ? a : b;
}
int32_t min_s32(int32_t a, int32_t b)
{
    return a < b ? a : b;
}
int64_t min_s64(int64_t a, int64_t b)
{
    return a < b ? a : b;
}

uint16_t max_u16(uint16_t a, uint16_t b)
{
    return a > b ? a : b;
}
uint32_t max_u32(uint32_t a, uint32_t b)
{
    return a > b ? a : b;
}
uint64_t max_u64(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

uint16_t min_u16(uint16_t a, uint16_t b)
{
    return a < b ? a : b;
}
uint32_t min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}
uint64_t min_u64(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}
