/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Implementation of an efficient array to store that we pinged something.
 */
#include "ping_array.h"

#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "crypto_core.h"
#include "mono_time.h"
#include "util.h"

typedef struct Ping_Array_Entry {
    uint8_t *data;
    uint32_t length;
    uint64_t ping_time;
    uint64_t ping_id;
} Ping_Array_Entry;

struct Ping_Array {
    Ping_Array_Entry *entries;

    uint32_t last_deleted; /* number representing the next entry to be deleted. */
    uint32_t last_added;   /* number representing the last entry to be added. */
    uint32_t total_size;   /* The length of entries */
    uint32_t timeout;      /* The timeout after which entries are cleared. */
};

Ping_Array *ping_array_new(uint32_t size, uint32_t timeout)
{
    if (size == 0 || timeout == 0) {
        return nullptr;
    }

    if ((size & (size - 1)) != 0) {
        // Not a power of 2.
        return nullptr;
    }

    Ping_Array *const empty_array = (Ping_Array *)calloc(1, sizeof(Ping_Array));

    if (empty_array == nullptr) {
        return nullptr;
    }

    empty_array->entries = (Ping_Array_Entry *)calloc(size, sizeof(Ping_Array_Entry));

    if (empty_array->entries == nullptr) {
        free(empty_array);
        return nullptr;
    }

    empty_array->last_deleted = 0;
    empty_array->last_added = 0;
    empty_array->total_size = size;
    empty_array->timeout = timeout;
    return empty_array;
}

non_null()
static void clear_entry(Ping_Array *array, uint32_t index)
{
    const Ping_Array_Entry empty = {nullptr};
    free(array->entries[index].data);
    array->entries[index] = empty;
}

void ping_array_kill(Ping_Array *array)
{
    if (array == nullptr) {
        return;
    }

    while (array->last_deleted != array->last_added) {
        const uint32_t index = array->last_deleted % array->total_size;
        clear_entry(array, index);
        ++array->last_deleted;
    }

    free(array->entries);
    free(array);
}

/** Clear timed out entries. */
non_null()
static void ping_array_clear_timedout(Ping_Array *array, const Mono_Time *mono_time)
{
    while (array->last_deleted != array->last_added) {
        const uint32_t index = array->last_deleted % array->total_size;

        if (!mono_time_is_timeout(mono_time, array->entries[index].ping_time, array->timeout)) {
            break;
        }

        clear_entry(array, index);
        ++array->last_deleted;
    }
}

uint64_t ping_array_add(Ping_Array *array, const Mono_Time *mono_time, const Random *rng,
                        const uint8_t *data, uint32_t length)
{
    ping_array_clear_timedout(array, mono_time);
    const uint32_t index = array->last_added % array->total_size;

    if (array->entries[index].data != nullptr) {
        array->last_deleted = array->last_added - array->total_size;
        clear_entry(array, index);
    }

    array->entries[index].data = (uint8_t *)malloc(length);

    if (array->entries[index].data == nullptr) {
        return 0;
    }

    memcpy(array->entries[index].data, data, length);
    array->entries[index].length = length;
    array->entries[index].ping_time = mono_time_get(mono_time);
    ++array->last_added;
    uint64_t ping_id = random_u64(rng);
    ping_id /= array->total_size;
    ping_id *= array->total_size;
    ping_id += index;

    if (ping_id == 0) {
        ping_id += array->total_size;
    }

    array->entries[index].ping_id = ping_id;
    return ping_id;
}

int32_t ping_array_check(Ping_Array *array, const Mono_Time *mono_time, uint8_t *data,
                         size_t length, uint64_t ping_id)
{
    if (ping_id == 0) {
        return -1;
    }

    const uint32_t index = ping_id % array->total_size;

    if (array->entries[index].ping_id != ping_id) {
        return -1;
    }

    if (mono_time_is_timeout(mono_time, array->entries[index].ping_time, array->timeout)) {
        return -1;
    }

    if (array->entries[index].length > length) {
        return -1;
    }

    // TODO(iphydf): This can't happen? If it indeed can't, turn it into an assert.
    if (array->entries[index].data == nullptr) {
        return -1;
    }

    memcpy(data, array->entries[index].data, array->entries[index].length);
    const uint32_t len = array->entries[index].length;
    clear_entry(array, index);
    return len;
}
