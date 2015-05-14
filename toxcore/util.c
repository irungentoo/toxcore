/*
 * util.c -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

/* for CLIENT_ID_SIZE */
#include "DHT.h"

#include "util.h"


/* don't call into system billions of times for no reason */
static uint64_t unix_time_value;
static uint64_t unix_base_time_value;

void unix_time_update()
{
    if (unix_base_time_value == 0)
        unix_base_time_value = ((uint64_t)time(NULL) - (current_time_monotonic() / 1000ULL));

    unix_time_value = (current_time_monotonic() / 1000ULL) + unix_base_time_value;
}

uint64_t unix_time()
{
    return unix_time_value;
}

int is_timeout(uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= unix_time();
}


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src)
{
    return memcmp(dest, src, CLIENT_ID_SIZE) == 0;
}

bool chat_id_equal(const uint8_t *dest, const uint8_t *src)
{
    return memcmp(dest, src, CHAT_ID_SIZE) == 0;
}

uint32_t id_copy(uint8_t *dest, const uint8_t *src)
{
    memcpy(dest, src, CLIENT_ID_SIZE);
    return CLIENT_ID_SIZE;
}

STATIC_BUFFER_DEFINE(idtoa, CLIENT_ID_SIZE*2+1);

char *id_toa(const uint8_t *id)
{
    int i;
    char *str=STATIC_BUFFER_GETBUF(idtoa, CLIENT_ID_SIZE*2+1);

    str[CLIENT_ID_SIZE*2]=0;
    for (i=0;i<CLIENT_ID_SIZE;i++)
        sprintf(str+2*i,"%02x",id[i]);

    return str;
}

void host_to_net(uint8_t *num, uint16_t numbytes)
{
#ifndef WORDS_BIGENDIAN
    uint32_t i;
    uint8_t buff[numbytes];

    for (i = 0; i < numbytes; ++i) {
        buff[i] = num[numbytes - i - 1];
    }

    memcpy(num, buff, numbytes);
#endif
    return;
}

uint16_t lendian_to_host16(uint16_t lendian)
{
#ifdef WORDS_BIGENDIAN
    return  (lendian << 8) | (lendian >> 8 );
#else
    return lendian;
#endif
}

void host_to_lendian32(uint8_t *dest,  uint32_t num)
{
#ifdef WORDS_BIGENDIAN
    num = ((num << 8) & 0xFF00FF00 ) | ((num >> 8) & 0xFF00FF );
    num = (num << 16) | (num >> 16);
#endif
    memcpy(dest, &num, sizeof(uint32_t));
}

void lendian_to_host32(uint32_t *dest, const uint8_t *lendian)
{
    uint32_t d;
    memcpy(&d, lendian, sizeof(uint32_t));
#ifdef WORDS_BIGENDIAN
    d = ((d << 8) & 0xFF00FF00 ) | ((d >> 8) & 0xFF00FF );
    d = (d << 16) | (d >> 16);
#endif
    *dest = d;
}

/* state load/save */
int load_state(load_state_callback_func load_state_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner)
{
    if (!load_state_callback || !data) {
#ifdef DEBUG
        fprintf(stderr, "load_state() called with invalid args.\n");
#endif
        return -1;
    }


    uint16_t type;
    uint32_t length_sub, cookie_type;
    uint32_t size_head = sizeof(uint32_t) * 2;

    while (length >= size_head) {
        lendian_to_host32(&length_sub, data);
        lendian_to_host32(&cookie_type, data + sizeof(length_sub));
        data += size_head;
        length -= size_head;

        if (length < length_sub) {
            /* file truncated */
#ifdef DEBUG
            fprintf(stderr, "state file too short: %u < %u\n", length, length_sub);
#endif
            return -1;
        }

        if (lendian_to_host16((cookie_type >> 16)) != cookie_inner) {
            /* something is not matching up in a bad way, give up */
#ifdef DEBUG
            fprintf(stderr, "state file garbeled: %04hx != %04hx\n", (cookie_type >> 16), cookie_inner);
#endif
            return -1;
        }

        type = lendian_to_host16(cookie_type & 0xFFFF);

        if (-1 == load_state_callback(outer, data, length_sub, type))
            return -1;

        data += length_sub;
        length -= length_sub;
    }

    return length == 0 ? 0 : -1;
};

/* Converts 8 bytes to uint64_t */
inline void bytes_to_U64(uint64_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint64_t ) *   bytes )             |
        ( ( uint64_t ) * ( bytes + 1 ) << 8  ) |
        ( ( uint64_t ) * ( bytes + 2 ) << 16 ) |
        ( ( uint64_t ) * ( bytes + 3 ) << 24 ) |
        ( ( uint64_t ) * ( bytes + 4 ) << 32 ) |
        ( ( uint64_t ) * ( bytes + 5 ) << 40 ) |
        ( ( uint64_t ) * ( bytes + 6 ) << 48 ) |
        ( ( uint64_t ) * ( bytes + 7 ) << 56 ) ;
#else
        ( ( uint64_t ) *   bytes       << 56 ) |
        ( ( uint64_t ) * ( bytes + 1 ) << 48 ) |
        ( ( uint64_t ) * ( bytes + 2 ) << 40 ) |
        ( ( uint64_t ) * ( bytes + 3 ) << 32 ) |
        ( ( uint64_t ) * ( bytes + 4 ) << 24 ) |
        ( ( uint64_t ) * ( bytes + 5 ) << 16 ) |
        ( ( uint64_t ) * ( bytes + 6 ) << 8  ) |
        ( ( uint64_t ) * ( bytes + 7 ) ) ;
#endif
}

/* Converts 4 bytes to uint32_t */
inline void bytes_to_U32(uint32_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint32_t ) *   bytes )             |
        ( ( uint32_t ) * ( bytes + 1 ) << 8  ) |
        ( ( uint32_t ) * ( bytes + 2 ) << 16 ) |
        ( ( uint32_t ) * ( bytes + 3 ) << 24 ) ;
#else
        ( ( uint32_t ) *   bytes       << 24 ) |
        ( ( uint32_t ) * ( bytes + 1 ) << 16 ) |
        ( ( uint32_t ) * ( bytes + 2 ) << 8  ) |
        ( ( uint32_t ) * ( bytes + 3 ) ) ;
#endif
}

/* Converts 2 bytes to uint16_t */
inline void bytes_to_U16(uint16_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint16_t ) *   bytes )             |
        ( ( uint16_t ) * ( bytes + 1 ) << 8 )  ;
#else
        ( ( uint16_t ) *   bytes       << 8 )  |
        ( ( uint16_t ) * ( bytes + 1 ) ) ;
#endif
}

/* Convert uint64_t to byte string of size 8 */
inline void U64_to_bytes(uint8_t *dest, uint64_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8  );
    *(dest + 2) = ( value >> 16 );
    *(dest + 3) = ( value >> 24 );
    *(dest + 4) = ( value >> 32 );
    *(dest + 5) = ( value >> 40 );
    *(dest + 6) = ( value >> 48 );
    *(dest + 7) = ( value >> 56 );
#else
    *(dest)     = ( value >> 56 );
    *(dest + 1) = ( value >> 48 );
    *(dest + 2) = ( value >> 40 );
    *(dest + 3) = ( value >> 32 );
    *(dest + 4) = ( value >> 24 );
    *(dest + 5) = ( value >> 16 );
    *(dest + 6) = ( value >> 8  );
    *(dest + 7) = ( value );
#endif
}

/* Convert uint32_t to byte string of size 4 */
inline void U32_to_bytes(uint8_t *dest, uint32_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8  );
    *(dest + 2) = ( value >> 16 );
    *(dest + 3) = ( value >> 24 );
#else
    *(dest)     = ( value >> 24 );
    *(dest + 1) = ( value >> 16 );
    *(dest + 2) = ( value >> 8  );
    *(dest + 3) = ( value );
#endif
}

/* Convert uint16_t to byte string of size 2 */
inline void U16_to_bytes(uint8_t *dest, uint16_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8 );
#else
    *(dest)     = ( value >> 8 );
    *(dest + 1) = ( value );
#endif
}

int create_recursive_mutex(pthread_mutex_t *mutex)
{
    pthread_mutexattr_t attr;

    if (pthread_mutexattr_init(&attr) != 0)
        return -1;

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

/* Returns a 32-bit hash of key of size len */
uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len)
{
    uint32_t hash, i;

    for (hash = i = 0; i < len; ++i) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}
