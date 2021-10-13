/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Implementation of an efficient array to store that we pinged something.
 */
#ifndef C_TOXCORE_TOXCORE_PING_ARRAY_H
#define C_TOXCORE_TOXCORE_PING_ARRAY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MONO_TIME_DEFINED
#define MONO_TIME_DEFINED
typedef struct Mono_Time Mono_Time;
#endif /* MONO_TIME_DEFINED */

#ifndef PING_ARRAY_DEFINED
#define PING_ARRAY_DEFINED
typedef struct Ping_Array Ping_Array;
#endif /* PING_ARRAY_DEFINED */

/**
 * Initialize a Ping_Array.
 *
 * @param size represents the total size of the array and should be a power of 2.
 * @param timeout represents the maximum timeout in seconds for the entry.
 *
 * @return 0 on success, -1 on failure.
 */
struct Ping_Array *ping_array_new(uint32_t size, uint32_t timeout);

/**
 * Free all the allocated memory in a Ping_Array.
 */
void ping_array_kill(struct Ping_Array *array);

/**
 * Add a data with length to the Ping_Array list and return a ping_id.
 *
 * @return ping_id on success, 0 on failure.
 */
uint64_t ping_array_add(struct Ping_Array *array, const struct Mono_Time *mono_time, const uint8_t *data,
                        uint32_t length);

/**
 * Check if ping_id is valid and not timed out.
 *
 * On success, copies the data into data of length,
 *
 * @return length of data copied on success, -1 on failure.
 */
int32_t ping_array_check(struct Ping_Array *array, const struct Mono_Time *mono_time, uint8_t *data, size_t length,
                         uint64_t ping_id);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_PING_ARRAY_H
