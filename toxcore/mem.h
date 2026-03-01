/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Memory allocation and deallocation functions.
 */
#ifndef C_TOXCORE_TOXCORE_MEM_H
#define C_TOXCORE_TOXCORE_MEM_H

#include <stdint.h>     // uint*_t

#include "attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Allocate a byte array, similar to malloc. */
typedef void *_Nullable memory_malloc_cb(void *_Nullable self, uint32_t size);
/** @brief Reallocate a byte array, similar to realloc. */
typedef void *_Nullable memory_realloc_cb(void *_Nullable self, void *_Nullable ptr, uint32_t size);
/**
 * @brief Deallocate a byte or object array, similar to free.
 */
typedef void memory_dealloc_cb(void *_Nullable self, void *_Nullable ptr);

/** @brief Functions wrapping standard C memory allocation functions. */
typedef struct Memory_Funcs {
    memory_malloc_cb *_Nonnull malloc_callback;
    memory_realloc_cb *_Nonnull realloc_callback;
    memory_dealloc_cb *_Nonnull dealloc_callback;
} Memory_Funcs;

typedef struct Memory {
    const Memory_Funcs *_Nonnull funcs;
    void *_Nullable user_data;
} Memory;

/**
 * @brief Allocate an array of a given size for built-in types.
 *
 * The array will not be initialised. Supported built-in types are
 * `uint8_t`, `int8_t`, and `int16_t`.
 */
void *_Nullable mem_balloc(const Memory *_Nonnull mem, uint32_t size);

/**
 * @brief Resize an array of a given size for built-in types.
 *
 * If used for a type other than byte-sized types, `size` needs to be manually
 * multiplied by the element size.
 */
void *_Nullable mem_brealloc(const Memory *_Nonnull mem, void *_Nullable ptr, uint32_t size);

/**
 * @brief Allocate a single zero-initialised object.
 *
 * Always use as `(T *)mem_alloc(mem, sizeof(T))`.
 *
 * @param mem The memory allocator.
 * @param size Size in bytes of each element.
 */
void *_Nullable mem_alloc(const Memory *_Nonnull mem, uint32_t size);

/**
 * @brief Allocate a vector (array) of objects.
 *
 * Always use as `(T *)mem_valloc(mem, N, sizeof(T))`.
 */
void *_Nullable mem_valloc(const Memory *_Nonnull mem, uint32_t nmemb, uint32_t size);

/**
 * @brief Resize an object vector.
 *
 * Changes the size of (and possibly moves) the memory block pointed to by
 * @p ptr to be large enough for an array of @p nmemb elements, each of which
 * is @p size bytes. It is similar to the call
 *
 * @code
 * realloc(ptr, nmemb * size);
 * @endcode
 *
 * However, unlike that `realloc()` call, `mem_vrealloc()` fails safely in the
 * case where the multiplication would overflow. If such an overflow occurs,
 * `mem_vrealloc()` returns `nullptr`.
 */
void *_Nullable mem_vrealloc(const Memory *_Nonnull mem, void *_Nullable ptr, uint32_t nmemb, uint32_t size);

/** @brief Free an array, object, or object vector. */
void mem_delete(const Memory *_Nonnull mem, void *_Nullable ptr);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_MEM_H */

