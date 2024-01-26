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
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

bool is_power_of_2(uint64_t x);

/** @brief Frees all pointers in a uint8_t pointer array, as well as the array itself. */
non_null(1) nullable(2)
void free_uint8_t_pointer_array(const Memory *mem, uint8_t **ary, size_t n_items);

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

/**
 * @brief Copies a byte array of a given size into a newly allocated one.
 *
 * @return nullptr on allocation failure or if the input data was nullptr or data_size was 0.
 */
nullable(1) uint8_t *memdup(const uint8_t *data, size_t data_size);

/**
 * @brief Set all bytes in `data` to 0.
 *
 * NOTE: This does not securely zero out data. DO NOT USE for sensitive data. Use
 * `crypto_memzero` from `crypto_core.h`, instead. This function is ok to use for
 * message buffers, public keys, encrypted data, etc. It is not ok for buffers
 * containing key material (secret keys, shared keys).
 */
nullable(1) void memzero(uint8_t *data, size_t data_size);

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

uint8_t max_u08(uint8_t a, uint8_t b);
uint16_t max_u16(uint16_t a, uint16_t b);
uint32_t max_u32(uint32_t a, uint32_t b);
uint64_t max_u64(uint64_t a, uint64_t b);

uint16_t min_u16(uint16_t a, uint16_t b);
uint32_t min_u32(uint32_t a, uint32_t b);
uint64_t min_u64(uint64_t a, uint64_t b);

// Comparison function: return -1 if a<b, 0 if a==b, 1 if a>b.
int cmp_uint(uint64_t a, uint64_t b);

/** @brief Returns a 32-bit hash of key of size len */
non_null()
uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len);

/** @brief Computes a checksum of a byte array.
 *
 * @param data The byte array used to compute the checksum.
 * @param length The length in bytes of the passed data.
 *
 * @retval The resulting checksum.
 */
non_null()
uint16_t data_checksum(const uint8_t *data, uint32_t length);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_UTIL_H */
