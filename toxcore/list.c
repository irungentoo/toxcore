/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Simple struct with functions to create a list which associates ids with data
 * - Allows for finding ids associated with data such as IPs or public keys in a short time
 * - Should only be used if there are relatively few add/remove calls to the list
 */
#include "list.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "ccompat.h"

/**
 * Basically, the elements in the list are placed in order so that they can be searched for easily
 * - each element is seen as a big-endian integer when ordering them
 * - the ids array is maintained so that each id always matches
 * - the search algorithm cuts down the time to find the id associated with a piece of data
 *   at the cost of slow add/remove functions for large lists
 * - Starts at `1/2` of the array, compares the element in the array with the data,
 *   then moves `+/- 1/4` of the array depending on whether the value is greater or lower,
 *   then `+- 1/8`, etc, until the value is matched or its position where it should be in the array is found
 * - some considerations since the array size is never perfect
 */

static int32_t
list_index(uint32_t i)
{
    return ~i;
}

/** @brief Find data in list
 *
 * @retval >=0 index of data in array
 * @retval <0  no match, returns index (return value is `list_index(index)`) where
 *   the data should be inserted
 */
non_null()
static int find(const BS_List *list, const uint8_t *data)
{
    // should work well, but could be improved
    if (list->n == 0) {
        return list_index(0);
    }

    uint32_t i = list->n / 2; // current position in the array
    uint32_t delta = i / 2;   // how much we move in the array

    if (delta == 0) {
        delta = 1;
    }

    int d = -1; // used to determine if closest match is found
    // closest match is found if we move back to where we have already been

    while (true) {
        const int r = memcmp(data, list->data + list->element_size * i, list->element_size);

        if (r == 0) {
            return i;
        }

        if (r > 0) {
            // data is greater
            // move down
            i += delta;

            if (d == 0 || i == list->n) {
                // reached bottom of list, or closest match
                return list_index(i);
            }

            delta = delta / 2;

            if (delta == 0) {
                delta = 1;
                d = 1;
            }
        } else {
            // data is smaller
            if (d == 1 || i == 0) {
                // reached top or list or closest match
                return list_index(i);
            }

            // move up
            i -= delta;

            delta = delta / 2;

            if (delta == 0) {
                delta = 1;
                d = 0;
            }
        }
    }
}

/**
 * Resizes the list.
 *
 * @return true on success.
 */
non_null()
static bool resize(BS_List *list, uint32_t new_size)
{
    if (new_size == 0) {
        bs_list_free(list);
        return true;
    }

    uint8_t *data = (uint8_t *)realloc(list->data, list->element_size * new_size);

    if (data == nullptr) {
        return false;
    }

    list->data = data;

    int *ids = (int *)realloc(list->ids, sizeof(int) * new_size);

    if (ids == nullptr) {
        return false;
    }

    list->ids = ids;

    return true;
}


int bs_list_init(BS_List *list, uint32_t element_size, uint32_t initial_capacity)
{
    // set initial values
    list->n = 0;
    list->element_size = element_size;
    list->capacity = 0;
    list->data = nullptr;
    list->ids = nullptr;

    if (initial_capacity != 0) {
        if (!resize(list, initial_capacity)) {
            return 0;
        }
    }

    list->capacity = initial_capacity;

    return 1;
}

void bs_list_free(BS_List *list)
{
    if (list == nullptr) {
        return;
    }

    // free both arrays
    free(list->data);
    list->data = nullptr;

    free(list->ids);
    list->ids = nullptr;
}

int bs_list_find(const BS_List *list, const uint8_t *data)
{
    const int r = find(list, data);

    // return only -1 and positive values
    if (r < 0) {
        return -1;
    }

    return list->ids[r];
}

bool bs_list_add(BS_List *list, const uint8_t *data, int id)
{
    // find where the new element should be inserted
    // see: return value of find()
    int i = find(list, data);

    if (i >= 0) {
        // already in list
        return false;
    }

    i = ~i;

    // increase the size of the arrays if needed
    if (list->n == list->capacity) {
        // 1.5 * n + 1
        const uint32_t new_capacity = list->n + list->n / 2 + 1;

        if (!resize(list, new_capacity)) {
            return false;
        }

        list->capacity = new_capacity;
    }

    // insert data to element array
    memmove(list->data + (i + 1) * list->element_size, list->data + i * list->element_size,
            (list->n - i) * list->element_size);
    memcpy(list->data + i * list->element_size, data, list->element_size);

    // insert id to id array
    memmove(&list->ids[i + 1], &list->ids[i], (list->n - i) * sizeof(int));
    list->ids[i] = id;

    // increase n
    ++list->n;

    return true;
}

bool bs_list_remove(BS_List *list, const uint8_t *data, int id)
{
    const int i = find(list, data);

    if (i < 0) {
        return false;
    }

    if (list->ids[i] != id) {
        // this should never happen
        return false;
    }

    // decrease the size of the arrays if needed
    if (list->n < list->capacity / 2) {
        const uint32_t new_capacity = list->capacity / 2;

        if (resize(list, new_capacity)) {
            list->capacity = new_capacity;
        }
    }

    --list->n;

    memmove(list->data + i * list->element_size, list->data + (i + 1) * list->element_size,
            (list->n - i) * list->element_size);
    memmove(&list->ids[i], &list->ids[i + 1], (list->n - i) * sizeof(int));

    return true;
}
