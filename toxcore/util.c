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

void unix_time_update()
{
    unix_time_value = (uint64_t)time(NULL);
}

uint64_t unix_time()
{
    return unix_time_value;
}

int is_timeout(uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= unix_time_value;
}


/* id functions */
bool id_equal(uint8_t *dest, uint8_t *src)
{
    return memcmp(dest, src, CLIENT_ID_SIZE) == 0;
}

uint32_t id_copy(uint8_t *dest, uint8_t *src)
{
    memcpy(dest, src, CLIENT_ID_SIZE);
    return CLIENT_ID_SIZE;
}

void host_to_net(uint8_t *num, uint16_t numbytes)
{
    union {
        uint32_t i;
        uint8_t c[4];
    } a;
    a.i = 1;

    if (a.c[0] == 1) {
        uint32_t i;
        uint8_t buff[numbytes];

        for (i = 0; i < numbytes; ++i) {
            buff[i] = num[numbytes - i - 1];
        }

        memcpy(num, buff, numbytes);
    }
}

/* state load/save */
int load_state(load_state_callback_func load_state_callback, void *outer,
               uint8_t *data, uint32_t length, uint16_t cookie_inner)
{
    if (!load_state_callback || !data) {
#ifdef DEBUG
        fprintf(stderr, "load_state() called with invalid args.\n");
#endif
        return -1;
    }


    uint16_t type;
    uint32_t length_sub, cookie_type;
    uint32_t size32 = sizeof(uint32_t), size_head = size32 * 2;

    while (length >= size_head) {
        length_sub = *(uint32_t *)data;
        cookie_type = *(uint32_t *)(data + size32);
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
