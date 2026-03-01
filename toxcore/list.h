/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
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
#include <stddef.h>  // size_t
#include <stdint.h>

#include "attributes.h"
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int bs_list_cmp_cb(const void *_Nonnull a, const void *_Nonnull b, size_t size);

typedef struct BS_List {
    const Memory *_Nonnull mem;

    uint32_t n; // number of elements
    uint32_t capacity; // number of elements memory is allocated for
    uint32_t element_size; // size of the elements
    uint8_t *_Nullable data; // array of elements
    int *_Nullable ids; // array of element ids
    bs_list_cmp_cb *_Nullable cmp_callback;
} BS_List;

/** @brief Initialize a list.
 *
 * @param element_size is the size of the elements in the list.
 * @param initial_capacity is the number of elements the memory will be initially allocated for.
 *
 * @retval 1 success
 * @retval 0 failure
 */
int bs_list_init(BS_List *_Nonnull list, const Memory *_Nonnull mem, uint32_t element_size, uint32_t initial_capacity, bs_list_cmp_cb *_Nonnull cmp_callback);

/** Free a list initiated with list_init */
void bs_list_free(BS_List *_Nullable list);
/** @brief Retrieve the id of an element in the list
 *
 * @retval >=0 id associated with data
 * @retval -1 failure
 */
int bs_list_find(const BS_List *_Nonnull list, const uint8_t *_Nonnull data);

/** @brief Add an element with associated id to the list
 *
 * @retval true  success
 * @retval false failure (data already in list)
 */
bool bs_list_add(BS_List *_Nonnull list, const uint8_t *_Nonnull data, int id);

/** @brief Remove element from the list
 *
 * @retval true  success
 * @retval false failure (element not found or id does not match)
 */
bool bs_list_remove(BS_List *_Nonnull list, const uint8_t *_Nonnull data, int id);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_LIST_H */
