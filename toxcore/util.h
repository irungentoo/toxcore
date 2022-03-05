/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/**
 * Utilities.
 */
#ifndef C_TOXCORE_TOXCORE_UTIL_H
#define C_TOXCORE_TOXCORE_UTIL_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Equality function for public keys. */
non_null() bool pk_equal(const uint8_t *dest, const uint8_t *src);
/**
 * @brief Copy a public key from `src` to `dest`.
 */
non_null() void pk_copy(uint8_t *dest, const uint8_t *src);

/** Returns -1 if failed or 0 if success */
non_null() int create_recursive_mutex(pthread_mutex_t *mutex);

/**
 * @brief Checks whether two buffers are the same length and contents.
 *
 * Calls `memcmp` after checking the sizes are equal.
 *
 * @retval true if sizes and contents are equal.
 * @retval false otherwise.
 */
non_null() bool memeq(const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size);

// Safe min/max functions with specific types. This forces the conversion to the
// desired type before the comparison expression, giving the choice of
// conversion to the caller. Use these instead of inline comparisons or MIN/MAX
// macros (effectively inline comparisons).
int16_t max_s16(int16_t a, int16_t b);
int32_t max_s32(int32_t a, int32_t b);
int64_t max_s64(int64_t a, int64_t b);

int16_t min_s16(int16_t a, int16_t b);
int32_t min_s32(int32_t a, int32_t b);
int64_t min_s64(int64_t a, int64_t b);

uint16_t max_u16(uint16_t a, uint16_t b);
uint32_t max_u32(uint32_t a, uint32_t b);
uint64_t max_u64(uint64_t a, uint64_t b);

uint16_t min_u16(uint16_t a, uint16_t b);
uint32_t min_u32(uint32_t a, uint32_t b);
uint64_t min_u64(uint64_t a, uint64_t b);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_UTIL_H
