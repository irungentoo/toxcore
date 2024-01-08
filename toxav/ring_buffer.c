/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */
#include "ring_buffer.h"

#include <stdlib.h>

#include "../toxcore/ccompat.h"

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

/**
 * @retval NULL on success
 * @return input value "p" on failure, so caller can free on failed rb_write
 */
void *rb_write(RingBuffer *b, void *p)
{
    if (b == nullptr) {
        return p;
    }

    void *rc = nullptr;

    if ((b->end + 1) % b->size == b->start) { /* full */
        rc = b->data[b->start];
    }

    b->data[b->end] = p;
    b->end = (b->end + 1) % b->size;

    if (b->end == b->start) {
        b->start = (b->start + 1) % b->size;
    }

    return rc;
}

bool rb_read(RingBuffer *b, void **p)
{
    if (b->end == b->start) { /* Empty */
        *p = nullptr;
        return false;
    }

    *p = b->data[b->start];
    b->start = (b->start + 1) % b->size;
    return true;
}

RingBuffer *rb_new(int size)
{
    RingBuffer *buf = (RingBuffer *)calloc(1, sizeof(RingBuffer));

    if (buf == nullptr) {
        return nullptr;
    }

    buf->size = size + 1; /* include empty elem */
    buf->data = (void **)calloc(buf->size, sizeof(void *));

    if (buf->data == nullptr) {
        free(buf);
        return nullptr;
    }

    return buf;
}

void rb_kill(RingBuffer *b)
{
    if (b != nullptr) {
        free(b->data);
        free(b);
    }
}

uint16_t rb_size(const RingBuffer *b)
{
    if (rb_empty(b)) {
        return 0;
    }

    return
        b->end > b->start ?
        b->end - b->start :
        (b->size - b->start) + b->end;
}

uint16_t rb_data(const RingBuffer *b, void **dest)
{
    uint16_t i;
    const uint16_t size = rb_size(b);

    for (i = 0; i < size; ++i) {
        dest[i] = b->data[(b->start + i) % b->size];
    }

    return i;
}
