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
#include <stdio.h>

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

/* extended id functions */
static unsigned keypos[] = { 
    0,                  /* ID_ALL_KEYS */
    0,                  /* ID_ENCRYPTION_KEY */
    SIG_PUBLIC_KEY,     /* ID_SIGNATURE_KEY */
};
static unsigned keylen[] = {
    EXT_PUBLIC_KEY, /* ID_ALL_KEYS */
    ENC_PUBLIC_KEY,     /* ID_ENCRYPTION_KEY */
    SIG_PUBLIC_KEY,/* ID_SIGNATURE_KEY */
};

bool id_equal2(const uint8_t *dest, const uint8_t *src, const enum id_key_t keytype)
{
    return memcmp(dest + keypos[keytype], src + keypos[keytype], keylen[keytype]) == 0;
}

uint32_t id_copy2(uint8_t *dest, const uint8_t *src, const enum id_key_t keytype)
{
    memcpy(dest + keypos[keytype], src + keypos[keytype], keylen[keytype]);
    return keylen[keytype];
}

STATIC_BUFFER_DEFINE(idtoa2, CLIENT_ID_EXT_SIZE*2+1);

char *id_toa2(const uint8_t *id, const enum id_key_t keytype)
{
    int i;
    char *str=STATIC_BUFFER_GETBUF(idtoa2, CLIENT_ID_EXT_SIZE*2+1);
    
    str[CLIENT_ID_EXT_SIZE*2]=0;
    for (i=0;i<keylen[keytype];i++)
        sprintf(str+2*i,"%02x",id[i + keypos[keytype]]);
    
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
        memcpy(&length_sub, data, sizeof(length_sub));
        memcpy(&cookie_type, data + sizeof(length_sub), sizeof(cookie_type));
        data += size_head;
        length -= size_head;

        if (length < length_sub) {
            /* file truncated */
#ifdef DEBUG
            fprintf(stderr, "state file too short: %u < %u\n", length, length_sub);
#endif
            return -1;
        }

        if ((cookie_type >> 16) != cookie_inner) {
            /* something is not matching up in a bad way, give up */
#ifdef DEBUG
            fprintf(stderr, "state file garbeled: %04hx != %04hx\n", (cookie_type >> 16), cookie_inner);
#endif
            return -1;
        }

        type = cookie_type & 0xFFFF;

        if (-1 == load_state_callback(outer, data, length_sub, type))
            return -1;

        data += length_sub;
        length -= length_sub;
    }

    return length == 0 ? 0 : -1;
};

/* Converts 8 bytes to uint64_t */
inline__ void bytes_to_U64(uint64_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint64_t ) *  bytes )              |
        ( ( uint64_t ) * ( bytes + 1 ) << 8 )  |
        ( ( uint64_t ) * ( bytes + 2 ) << 16 ) |
        ( ( uint64_t ) * ( bytes + 3 ) << 24 )  |
        ( ( uint64_t ) * ( bytes + 4 ) << 32 ) |
        ( ( uint64_t ) * ( bytes + 5 ) << 40 )  |
        ( ( uint64_t ) * ( bytes + 6 ) << 48 ) |
        ( ( uint64_t ) * ( bytes + 7 ) << 56 ) ;
#else
        ( ( uint64_t ) *  bytes        << 56 ) |
        ( ( uint64_t ) * ( bytes + 1 ) << 48 ) |
        ( ( uint64_t ) * ( bytes + 2 ) << 40 )  |
        ( ( uint64_t ) * ( bytes + 3 ) << 32 ) |
        ( ( uint64_t ) * ( bytes + 4 ) << 24 )  |
        ( ( uint64_t ) * ( bytes + 5 ) << 16 ) |
        ( ( uint64_t ) * ( bytes + 6 ) << 8 )  |
        ( ( uint64_t ) * ( bytes + 7 ) ) ;
#endif
}

/* Converts 4 bytes to uint32_t */
inline__ void bytes_to_U32(uint32_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint32_t ) *  bytes )              |
        ( ( uint32_t ) * ( bytes + 1 ) << 8 )  |
        ( ( uint32_t ) * ( bytes + 2 ) << 16 ) |
        ( ( uint32_t ) * ( bytes + 3 ) << 24 ) ;
#else
        ( ( uint32_t ) *  bytes        << 24 ) |
        ( ( uint32_t ) * ( bytes + 1 ) << 16 ) |
        ( ( uint32_t ) * ( bytes + 2 ) << 8 )  |
        ( ( uint32_t ) * ( bytes + 3 ) ) ;
#endif
}

/* Converts 2 bytes to uint16_t */
inline__ void bytes_to_U16(uint16_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint16_t ) *   bytes ) |
        ( ( uint16_t ) * ( bytes + 1 ) << 8 );
#else
        ( ( uint16_t ) *   bytes << 8 ) |
        ( ( uint16_t ) * ( bytes + 1 ) );
#endif
}

/* Convert uint64_t to byte string of size 8 */
inline__ void U64_to_bytes(uint8_t *dest, uint64_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8 );
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
    *(dest + 3) = ( value >> 42 );
    *(dest + 4) = ( value >> 24 );
    *(dest + 5) = ( value >> 16 );
    *(dest + 6) = ( value >> 8 );
    *(dest + 7) = ( value );
#endif
}

/* Convert uint32_t to byte string of size 4 */
inline__ void U32_to_bytes(uint8_t *dest, uint32_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8 );
    *(dest + 2) = ( value >> 16 );
    *(dest + 3) = ( value >> 24 );
#else
    *(dest)     = ( value >> 24 );
    *(dest + 1) = ( value >> 16 );
    *(dest + 2) = ( value >> 8 );
    *(dest + 3) = ( value );
#endif
}

/* Convert uint16_t to byte string of size 2 */
inline__ void U16_to_bytes(uint8_t *dest, uint16_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8 );
#else
    *(dest)     = ( value >> 8 );
    *(dest + 1) = ( value );
#endif
}