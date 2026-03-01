/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#include "sort.h"

#include <assert.h>

#include "attributes.h"
#include "ccompat.h"
#include "util.h"

/**
 * @brief Threshold for when to switch to insertion sort.
 *
 * This is a trade-off between the complexity of insertion sort and the
 * overhead of merge sort. The threshold is chosen to be the smallest value
 * that gives a measurable speedup for insertion sort over merge sort. This is
 * based on measurements done in sort_bench.cc. Starting from 32 elements,
 * merge sort is faster than insertion sort in all our tests (both unsorted
 * and mostly-sorted).
 *
 * Toxcore has a lot of small arrays it wants to sort, so this optimisation
 * makes sense.
 */
#define SMALL_ARRAY_THRESHOLD 16

static void merge_sort_merge_back(void *_Nonnull arr, const void *_Nonnull l_arr, uint32_t l_arr_size, const void *_Nonnull r_arr, uint32_t r_arr_size, uint32_t left_start,
                                  const void *_Nonnull object, const Sort_Funcs *_Nonnull funcs)
{
    uint32_t li = 0;
    uint32_t ri = 0;
    uint32_t k = left_start;

    while (li < l_arr_size && ri < r_arr_size) {
        const void *l = funcs->get_callback(l_arr, li);
        const void *r = funcs->get_callback(r_arr, ri);
        // !(r < l) <=> (r >= l) <=> (l <= r)
        if (!funcs->less_callback(object, r, l)) {
            funcs->set_callback(arr, k, l);
            ++li;
        } else {
            funcs->set_callback(arr, k, r);
            ++ri;
        }
        ++k;
    }

    /* Copy the remaining elements of `l_arr[]`, if there are any. */
    while (li < l_arr_size) {
        funcs->set_callback(arr, k, funcs->get_callback(l_arr, li));
        ++li;
        ++k;
    }

    /* Copy the remaining elements of `r_arr[]`, if there are any. */
    while (ri < r_arr_size) {
        funcs->set_callback(arr, k, funcs->get_callback(r_arr, ri));
        ++ri;
        ++k;
    }
}

/** Function to merge the two haves `arr[left_start..mid]` and `arr[mid+1..right_end]` of array `arr[]`. */
static void merge_sort_merge(void *_Nonnull arr, uint32_t left_start, uint32_t mid, uint32_t right_end, void *_Nonnull tmp, const void *_Nonnull object, const Sort_Funcs *_Nonnull funcs)
{
    const uint32_t l_arr_size = mid - left_start + 1;
    const uint32_t r_arr_size = right_end - mid;

    /* Temporary arrays, using the tmp buffer created in `merge_sort` below. */
    void *l_arr = funcs->subarr_callback(tmp, 0, l_arr_size);
    void *r_arr = funcs->subarr_callback(tmp, l_arr_size, r_arr_size);

    /* Copy data to temp arrays `l_arr[]` and `r_arr[]`.
     *
     * This is iterating and repeatedly calling `get` and `set`, which sounds
     * slow, but is only marginally slower than having a `copy` callback. With
     * a `copy` callback, we'd save 3-4% in time.
     */
    for (uint32_t i = 0; i < l_arr_size; ++i) {
        funcs->set_callback(l_arr, i, funcs->get_callback(arr, left_start + i));
    }
    for (uint32_t i = 0; i < r_arr_size; ++i) {
        funcs->set_callback(r_arr, i, funcs->get_callback(arr, mid + 1 + i));
    }

    /* Merge the temp arrays back into `arr[left_start..right_end]`. */
    merge_sort_merge_back(arr, l_arr, l_arr_size, r_arr, r_arr_size, left_start, object, funcs);
}

static void insertion_sort_step(void *_Nonnull arr, void *_Nonnull tmp, uint32_t i, const void *_Nonnull object, const Sort_Funcs *_Nonnull funcs)
{
    funcs->set_callback(tmp, 0, funcs->get_callback(arr, i));
    uint32_t j = i;

    while (j > 0) {
        if (!funcs->less_callback(object, tmp, funcs->get_callback(arr, j - 1))) {
            break;
        }
        funcs->set_callback(arr, j, funcs->get_callback(arr, j - 1));
        --j;
    }

    funcs->set_callback(arr, j, tmp);
}

static void insertion_sort_with_buf(void *_Nonnull arr, uint32_t arr_size, void *_Nonnull tmp, uint32_t tmp_size, const void *_Nonnull object, const Sort_Funcs *_Nonnull funcs)
{
    for (uint32_t i = 1; i < arr_size; ++i) {
        insertion_sort_step(arr, tmp, i, object, funcs);
    }
}

static bool insertion_sort(void *_Nonnull arr, uint32_t arr_size, const void *_Nonnull object, const Sort_Funcs *_Nonnull funcs)
{
    void *tmp = funcs->alloc_callback(object, 1);

    if (tmp == nullptr) {
        return false;
    }

    insertion_sort_with_buf(arr, arr_size, tmp, 1, object, funcs);

    funcs->delete_callback(object, tmp, 1);
    return true;
}

void merge_sort_with_buf(void *arr, uint32_t arr_size, void *tmp, uint32_t tmp_size, const void *object, const Sort_Funcs *funcs)
{
    assert(tmp_size >= arr_size);

    if (arr_size <= SMALL_ARRAY_THRESHOLD) {
        assert(tmp_size >= 1);
        insertion_sort_with_buf(arr, arr_size, tmp, tmp_size, object, funcs);
        return;
    }

    // Merge subarrays in bottom up manner.  First merge subarrays of
    // size 1 to create sorted subarrays of size 2, then merge subarrays
    // of size 2 to create sorted subarrays of size 4, and so on.
    for (uint32_t curr_size = 1; curr_size <= arr_size - 1; curr_size = 2 * curr_size) {
        // Pick starting point of different subarrays of current size
        for (uint32_t left_start = 0; left_start < arr_size - 1; left_start += 2 * curr_size) {
            // Find ending point of left subarray. mid+1 is starting
            // point of right
            const uint32_t mid = min_u32(left_start + curr_size - 1, arr_size - 1);
            const uint32_t right_end = min_u32(left_start + 2 * curr_size - 1, arr_size - 1);

            // Merge Subarrays arr[left_start...mid] & arr[mid+1...right_end]
            merge_sort_merge(arr, left_start, mid, right_end, tmp, object, funcs);
        }
    }
}

bool merge_sort(void *arr, uint32_t arr_size, const void *object, const Sort_Funcs *funcs)
{
    if (arr_size <= SMALL_ARRAY_THRESHOLD) {
        return insertion_sort(arr, arr_size, object, funcs);
    }

    void *tmp = funcs->alloc_callback(object, arr_size);

    if (tmp == nullptr) {
        return false;
    }

    merge_sort_with_buf(arr, arr_size, tmp, arr_size, object, funcs);

    funcs->delete_callback(object, tmp, arr_size);
    return true;
}
