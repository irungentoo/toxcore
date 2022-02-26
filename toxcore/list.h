/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Simple struct with functions to create a list which associates ids with data
 * -Allows for finding ids associated with data such as IPs or public keys in a short time
 * -Should only be used if there are relatively few add/remove calls to the list
 */
#ifndef C_TOXCORE_TOXCORE_LIST_H
#define C_TOXCORE_TOXCORE_LIST_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BS_List {
    uint32_t n; // number of elements
    uint32_t capacity; // number of elements memory is allocated for
    uint32_t element_size; // size of the elements
    uint8_t *data; // array of elements
    int *ids; // array of element ids
} BS_List;

/** Initialize a list, element_size is the size of the elements in the list and
 * initial_capacity is the number of elements the memory will be initially allocated for
 *
 * return value:
 *  1 : success
 *  0 : failure
 */
non_null()
int bs_list_init(BS_List *list, uint32_t element_size, uint32_t initial_capacity);

/** Free a list initiated with list_init */
non_null()
void bs_list_free(BS_List *list);

/** Retrieve the id of an element in the list
 *
 * return value:
 *  >= 0 : id associated with data
 *  -1   : failure
 */
non_null()
int bs_list_find(const BS_List *list, const uint8_t *data);

/** Add an element with associated id to the list
 *
 * return value:
 *  true  : success
 *  false : failure (data already in list)
 */
non_null()
bool bs_list_add(BS_List *list, const uint8_t *data, int id);

/** Remove element from the list
 *
 * return value:
 *  true  : success
 *  false : failure (element not found or id does not match)
 */
non_null()
bool bs_list_remove(BS_List *list, const uint8_t *data, int id);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
