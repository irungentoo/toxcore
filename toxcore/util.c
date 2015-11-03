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

/* for crypto_box_PUBLICKEYBYTES */
#include "crypto_core.h"

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
    return memcmp(dest, src, crypto_box_PUBLICKEYBYTES) == 0;
}

uint32_t id_copy(uint8_t *dest, const uint8_t *src)
{
    memcpy(dest, src, crypto_box_PUBLICKEYBYTES);
    return crypto_box_PUBLICKEYBYTES;
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

        int ret = load_state_callback(outer, data, length_sub, type);

        if (ret == -1) {
            return -1;
        }

        /* -2 means end of save. */
        if (ret == -2)
            return 0;

        data += length_sub;
        length -= length_sub;
    }

    return length == 0 ? 0 : -1;
};

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


struct RingBuffer {
    uint16_t size; /* Max size */
    uint16_t start;
    uint16_t end;
    void   **data;
};

bool rb_full(const RingBuffer *b)
{
    return (b->end + 1) % b->size == b->start;
}
bool rb_empty(const RingBuffer *b)
{
    return b->end == b->start;
}
void* rb_write(RingBuffer *b, void *p)
{
    void* rc = NULL;
    if ((b->end + 1) % b->size == b->start) /* full */
        rc = b->data[b->start];
    
    b->data[b->end] = p;
    b->end = (b->end + 1) % b->size;

    if (b->end == b->start) 
        b->start = (b->start + 1) % b->size;
    
    return rc;
}
bool rb_read(RingBuffer *b, void **p)
{
    if (b->end == b->start) { /* Empty */
        *p = NULL;
        return false;
    }
    
    *p = b->data[b->start];
    b->start = (b->start + 1) % b->size;
    return true;
}
RingBuffer *rb_new(int size)
{
    RingBuffer *buf = calloc(sizeof(RingBuffer), 1);

    if (!buf) return NULL;

    buf->size = size + 1; /* include empty elem */

    if (!(buf->data = calloc(buf->size, sizeof(void *)))) {
        free(buf);
        return NULL;
    }

    return buf;
}
void rb_kill(RingBuffer *b)
{
    if (b) {
        free(b->data);
        free(b);
    }
}
uint16_t rb_size(const RingBuffer* b)
{ 
    if (rb_empty(b))
        return 0;
    
    return
    b->end > b->start ?
        b->end - b->start :
        (b->size - b->start) + b->end;
}
uint16_t rb_data(const RingBuffer* b, void** dest)
{
    uint16_t i = 0;
    for (; i < rb_size(b); i++)
        dest[i] = b->data[(b->start + i) % b->size];
    
    return i;
}
