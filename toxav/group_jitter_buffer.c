/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */
#include "group_jitter_buffer.h"

#include <stdlib.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/mono_time.h"

#define GROUP_JBUF_DEAD_SECONDS 4

struct Group_JitterBuffer {
    Group_Audio_Packet *_Nullable *_Nonnull queue;
    uint32_t size;
    uint32_t capacity;
    uint16_t bottom;
    uint16_t top;
    uint64_t last_queued_time;
};

void group_audio_packet_free(Group_Audio_Packet *_Nullable pk)
{
    if (pk == nullptr) {
        return;
    }

    free(pk->data);
    free(pk);
}

Group_JitterBuffer *_Nullable group_jbuf_new(unsigned int capacity)
{
    unsigned int size = 1;

    while (size <= capacity) {
        size *= 2;
    }

    Group_JitterBuffer *q = (Group_JitterBuffer *)calloc(1, sizeof(Group_JitterBuffer));

    if (q == nullptr) {
        return nullptr;
    }

    Group_Audio_Packet **queue = (Group_Audio_Packet **)calloc(size, sizeof(Group_Audio_Packet *));

    if (queue == nullptr) {
        free(q);
        return nullptr;
    }

    q->queue = queue;
    q->size = size;
    q->capacity = capacity;
    return q;
}

static void group_jbuf_clear(Group_JitterBuffer *_Nonnull q)
{
    while (q->bottom != q->top) {
        const size_t idx = q->bottom % q->size;
        group_audio_packet_free(q->queue[idx]);
        q->queue[idx] = nullptr;
        ++q->bottom;
    }
}

void group_jbuf_kill(Group_JitterBuffer *_Nullable q)
{
    if (q == nullptr) {
        return;
    }

    group_jbuf_clear(q);
    free(q->queue);
    free(q);
}

int group_jbuf_write(Group_JitterBuffer *_Nonnull q, const Mono_Time *_Nonnull mono_time, Group_Audio_Packet *_Nonnull pk)
{
    const uint16_t sequnum = pk->sequnum;

    const unsigned int num = sequnum % q->size;

    if (!mono_time_is_timeout(mono_time, q->last_queued_time, GROUP_JBUF_DEAD_SECONDS)) {
        if ((uint16_t)(sequnum - q->bottom) > (1 << 15)) {
            /* Drop old packet. */
            return -1;
        }
    }

    if ((uint16_t)(sequnum - q->bottom) > q->size) {
        group_jbuf_clear(q);
        q->bottom = sequnum - q->capacity;
        q->queue[num] = pk;
        q->top = sequnum + 1;
        q->last_queued_time = mono_time_get(mono_time);
        return 0;
    }

    if (q->queue[num] != nullptr) {
        return -1;
    }

    q->queue[num] = pk;

    if ((uint16_t)(sequnum - q->bottom) >= (uint16_t)(q->top - q->bottom)) {
        q->top = sequnum + 1;
    }

    q->last_queued_time = mono_time_get(mono_time);
    return 0;
}

Group_Audio_Packet *_Nullable group_jbuf_read(Group_JitterBuffer *_Nonnull q, int *_Nonnull success)
{
    if (q->top == q->bottom) {
        *success = 0;
        return nullptr;
    }

    const unsigned int num = q->bottom % q->size;

    if (q->queue[num] != nullptr) {
        Group_Audio_Packet *ret = q->queue[num];
        q->queue[num] = nullptr;
        ++q->bottom;
        *success = 1;
        return ret;
    }

    if ((uint16_t)(q->top - q->bottom) > q->capacity) {
        ++q->bottom;
        *success = 2;
        return nullptr;
    }

    *success = 0;
    return nullptr;
}
