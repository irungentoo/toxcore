/* ping_array.c
 *
 * Implementation of an efficient array to store that we pinged something.
 *
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ping_array.h"
#include "crypto_core.h"
#include "util.h"

static void clear_entry(Ping_Array *array, uint32_t index)
{
    free(array->entries[index].data);
    array->entries[index].data = NULL;
    array->entries[index].length =
        array->entries[index].time =
            array->entries[index].ping_id = 0;
}

/* Clear timed out entries.
 */
static void ping_array_clear_timedout(Ping_Array *array)
{
    while (array->last_deleted != array->last_added) {
        uint32_t index = array->last_deleted % array->total_size;

        if (!is_timeout(array->entries[index].time, array->timeout))
            break;

        clear_entry(array, index);
        ++array->last_deleted;
    }
}

/* Add a data with length to the Ping_Array list and return a ping_id.
 *
 * return ping_id on success.
 * return 0 on failure.
 */
uint64_t ping_array_add(Ping_Array *array, const uint8_t *data, uint32_t length)
{
    ping_array_clear_timedout(array);
    uint32_t index = array->last_added % array->total_size;

    if (array->entries[index].data != NULL) {
        array->last_deleted = array->last_added - array->total_size;
        clear_entry(array, index);
    }

    array->entries[index].data = malloc(length);

    if (array->entries[index].data == NULL)
        return 0;

    memcpy(array->entries[index].data, data, length);
    array->entries[index].length = length;
    array->entries[index].time = unix_time();
    ++array->last_added;
    uint64_t ping_id = random_64b();
    ping_id /= array->total_size;
    ping_id *= array->total_size;
    ping_id += index;

    if (ping_id == 0)
        ping_id += array->total_size;

    array->entries[index].ping_id = ping_id;
    return ping_id;
}


/* Check if ping_id is valid and not timed out.
 *
 * On success, copies the data into data of length,
 *
 * return length of data copied on success.
 * return -1 on failure.
 */
int ping_array_check(uint8_t *data, uint32_t length, Ping_Array *array, uint64_t ping_id)
{
    if (ping_id == 0)
        return -1;

    uint32_t index = ping_id % array->total_size;

    if (array->entries[index].ping_id != ping_id)
        return -1;

    if (is_timeout(array->entries[index].time, array->timeout))
        return -1;

    if (array->entries[index].length > length)
        return -1;

    if (array->entries[index].data == NULL)
        return -1;

    memcpy(data, array->entries[index].data, array->entries[index].length);
    uint32_t len = array->entries[index].length;
    clear_entry(array, index);
    return len;
}

/* Initialize a Ping_Array.
 * size represents the total size of the array and should be a power of 2.
 * timeout represents the maximum timeout in seconds for the entry.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int ping_array_init(Ping_Array *empty_array, uint32_t size, uint32_t timeout)
{
    if (size == 0 || timeout == 0 || empty_array == NULL)
        return -1;

    empty_array->entries = calloc(size, sizeof(Ping_Array_Entry));

    if (empty_array->entries == NULL)
        return -1;

    empty_array->last_deleted = empty_array->last_added = 0;
    empty_array->total_size = size;
    empty_array->timeout = timeout;
    return 0;
}

/* Free all the allocated memory in a Ping_Array.
 */
void ping_array_free_all(Ping_Array *array)
{
    while (array->last_deleted != array->last_added) {
        uint32_t index = array->last_deleted % array->total_size;
        clear_entry(array, index);
        ++array->last_deleted;
    }

    free(array->entries);
    array->entries = NULL;
}

