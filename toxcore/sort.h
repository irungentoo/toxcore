/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_SORT_H
#define C_TOXCORE_TOXCORE_SORT_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Compare elements with a less-than ordering: `a < b`. */
typedef bool sort_less_cb(const void *_Nonnull object, const void *_Nonnull a, const void *_Nonnull b);
/** @brief Get element from array at index. */
typedef const void *sort_get_cb(const void *_Nonnull arr, uint32_t index);
/** @brief Set element in array at index to new value (perform copy). */
typedef void sort_set_cb(void *_Nonnull arr, uint32_t index, const void *_Nonnull val);
/** @brief Get a sub-array at an index of a given size (mutable pointer).
 *
 * Used to index in the temporary array allocated by `sort_alloc_cb` and get
 * a sub-array for working memory.
 */
typedef void *sort_subarr_cb(void *_Nonnull arr, uint32_t index, uint32_t size);
/** @brief Allocate a new array of the element type.
 *
 * @param size The array size in elements of type T (not byte size). This value
 *   is always exactly the input array size as passed to `merge_sort`.
 */
typedef void *sort_alloc_cb(const void *_Nonnull object, uint32_t size);
/** @brief Free the element type array. */
typedef void sort_delete_cb(const void *_Nonnull object, void *_Nonnull arr, uint32_t size);

/** @brief Virtual function table for getting/setting elements in an array and
 * comparing them.
 *
 * Only the `less`, `alloc`, and `delete` functions get a `this`-pointer. We
 * assume that indexing in an array doesn't need any other information than the
 * array itself.
 *
 * For now, the `this`-pointer is const, because we assume sorting doesn't need
 * to mutate any state, but if necessary that can be changed in the future.
 */
typedef struct Sort_Funcs {
    sort_less_cb *_Nonnull less_callback;
    sort_get_cb *_Nonnull get_callback;
    sort_set_cb *_Nonnull set_callback;
    sort_subarr_cb *_Nonnull subarr_callback;
    sort_alloc_cb *_Nonnull alloc_callback;
    sort_delete_cb *_Nonnull delete_callback;
} Sort_Funcs;

/** @brief Non-recursive merge sort function to sort `arr[0...arr_size-1]`.
 *
 * Avoids `memcpy` and avoids treating elements as byte arrays. Instead, uses
 * callbacks to index in arrays and copy elements. This makes it quite a bit
 * slower than `qsort`, but works with elements that require special care when
 * being copied (e.g. if they are part of a graph or other data structure that
 * with pointers or other invariants).
 *
 * This function actually uses insertion sort for small arrays (up to 16
 * elements), which is faster than merge sort for small arrays, especially
 * when mostly sorted (a common use case in toxcore).
 *
 * Allocates a single temporary array with the provided alloc callback, and
 * frees it at the end. This is significantly faster than an in-place
 * implementation.
 *
 * Complexity:
 * - Space: `O(n) where n = array_size`.
 * - Time: `O(n * log n) where n = array_size`.
 *
 * Compared to `qsort`, this is about 60-70% slower for large arrays. For small
 * arrays (up to 16 elements), it's about 50% faster than `qsort`.
 *
 * @param[in,out] arr An array of type T.
 * @param arr_size Number of elements in @p arr (count, not byte size).
 * @param[in] object Comparator object.
 * @param[in] funcs Callback struct for elements of type T.
 */
bool merge_sort(void *_Nonnull arr, uint32_t arr_size, const void *_Nonnull object, const Sort_Funcs *_Nonnull funcs);

/**
 * @brief Merge sort like above but with a pre-allocated buffer.
 *
 * This function is the same as `merge_sort` but uses a pre-allocated buffer
 * for temporary storage. This can be useful if the caller wants to avoid
 * dynamic memory allocation.
 *
 * This function is 1-2% faster than `merge_sort` for small arrays up to 1000
 * elements, and about 5-10% faster for large arrays (2000+ elements).
 *
 * The main upside is that `alloc` and `delete` callbacks don't need to be
 * implemented, and the caller can use a stack-allocated buffer.
 *
 * @param[in,out] arr An array of type T.
 * @param arr_size Number of elements in @p arr (count, not byte size).
 * @param[in,out] tmp A buffer of size `tmp_size` for temporary storage.
 * @param tmp_size Number of elements in @p tmp (count, not byte size). Must be
 *   at least as large as `arr_size`.
 * @param[in] object Comparator object.
 * @param[in] funcs Callback struct for elements of type T.
 */
void merge_sort_with_buf(void *_Nonnull arr, uint32_t arr_size, void *_Nonnull tmp, uint32_t tmp_size, const void *_Nonnull object, const Sort_Funcs *_Nonnull funcs);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_SORT_H */
