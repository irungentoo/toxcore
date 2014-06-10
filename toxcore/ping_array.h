/* ping_array.h
 *
 * Implementation of an efficient array to store that we pinged something.
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
 *
 */
#ifndef PING_ARRAY_H
#define PING_ARRAY_H

#include "network.h"

typedef struct {
    void *data;
    uint32_t length;
    uint64_t time;
    uint64_t ping_id;
} Ping_Array_Entry;


typedef struct {
    Ping_Array_Entry *entries;

    uint32_t last_deleted; /* number representing the next entry to be deleted. */
    uint32_t last_added; /* number representing the last entry to be added. */
    uint32_t total_size; /* The length of entries */
    uint32_t timeout; /* The timeout after which entries are cleared. */
} Ping_Array;


/* Add a data with length to the Ping_Array list and return a ping_id.
 *
 * return ping_id on success.
 * return 0 on failure.
 */
uint64_t ping_array_add(Ping_Array *array, const uint8_t *data, uint32_t length);

/* Check if ping_id is valid and not timed out.
 *
 * On success, copies the data into data of length,
 *
 * return length of data copied on success.
 * return -1 on failure.
 */
int ping_array_check(uint8_t *data, uint32_t length, Ping_Array *array, uint64_t ping_id);

/* Initialize a Ping_Array.
 * size represents the total size of the array and should be a power of 2.
 * timeout represents the maximum timeout in seconds for the entry.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int ping_array_init(Ping_Array *empty_array, uint32_t size, uint32_t timeout);

/* Free all the allocated memory in a Ping_Array.
 */
void ping_array_free_all(Ping_Array *array);

#endif
