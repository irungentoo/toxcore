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

// Need dht because of ENC_SECRET_KEY and ENC_PUBLIC_KEY
#define ENC_PUBLIC_KEY CRYPTO_PUBLIC_KEY_SIZE
#define ENC_SECRET_KEY CRYPTO_SECRET_KEY_SIZE
#define SIG_PUBLIC_KEY CRYPTO_SIGN_PUBLIC_KEY_SIZE
#define SIG_SECRET_KEY CRYPTO_SIGN_SECRET_KEY_SIZE
#define CHAT_ID_SIZE SIG_PUBLIC_KEY

#include "crypto_core.h" /* for CRYPTO_PUBLIC_KEY_SIZE */
#include "network.h" /* for current_time_monotonic */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

bool is_power_of_2(uint64_t x)
{
    return x != 0 && (x & (~x + 1)) == x;
}


const uint8_t *get_enc_key(const uint8_t *key)
{
    return key;
}

const uint8_t *get_sig_pk(const uint8_t *key)
{
    return key + ENC_PUBLIC_KEY;
}

void set_sig_pk(uint8_t *key, const uint8_t *sig_pk)
{
    memcpy(key + ENC_PUBLIC_KEY, sig_pk, SIG_PUBLIC_KEY);
}

const uint8_t *get_sig_sk(const uint8_t *key)
{
    return key + ENC_SECRET_KEY;
}

void set_sig_sk(uint8_t *key, const uint8_t *sig_sk)
{
    memcpy(key + ENC_SECRET_KEY, sig_sk, SIG_SECRET_KEY);
}

const uint8_t *get_chat_id(const uint8_t *key)
{
    return key + ENC_PUBLIC_KEY;
}


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src)
{
    return public_key_cmp(dest, src) == 0;
}

bool chat_id_equal(const uint8_t *dest, const uint8_t *src)
{
    return memcmp(dest, src, CHAT_ID_SIZE) == 0;
}

uint32_t id_copy(uint8_t *dest, const uint8_t *src)
{
    memcpy(dest, src, CRYPTO_PUBLIC_KEY_SIZE);
    return CRYPTO_PUBLIC_KEY_SIZE;
}

char *id_toa(const uint8_t *id)
{
    char *str = (char *)malloc(CRYPTO_PUBLIC_KEY_SIZE * 2 + 1);

    for (int i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; ++i) {
        sprintf(str + 2 * i, "%02x", id[i]);
    }

    return str;
}

void host_to_net(uint8_t *num, uint16_t numbytes)
{
#ifndef WORDS_BIGENDIAN
    uint32_t i;
    VLA(uint8_t, buff, numbytes);

    for (i = 0; i < numbytes; ++i) {
        buff[i] = num[numbytes - i - 1];
    }

    memcpy(num, buff, numbytes);
#endif
}

void net_to_host(uint8_t *num, uint16_t numbytes)
{
    host_to_net(num, numbytes);
}

/* frees all pointers in a uint8_t pointer array, as well as the array itself. */
void free_uint8_t_pointer_array(uint8_t **ary, size_t n_items)
{
    if (ary == nullptr) {
        return;
    }

    size_t i;

    for (i = 0; i < n_items; ++i) {
        if (ary[i] != nullptr) {
            free(ary[i]);
        }
    }

    free(ary);
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

/* Returns a 32-bit hash of key of size len */
uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len)
{
    uint32_t hash = 0;

    for (uint32_t i = 0; i < len; ++i) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}
