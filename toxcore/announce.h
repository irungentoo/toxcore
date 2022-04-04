/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_H

#include "forwarding.h"

#define MAX_ANNOUNCEMENT_SIZE 512

typedef void announce_on_retrieve_cb(void *object, const uint8_t *data, uint16_t length);

uint8_t announce_response_of_request_type(uint8_t request_type);

typedef struct Announcements Announcements;

non_null()
Announcements *new_announcements(const Logger *log, const Random *rng, const Mono_Time *mono_time, Forwarding *forwarding);

/**
 * @brief If data is stored, run `on_retrieve_callback` on it.
 *
 * @return true if data is stored, false otherwise.
 */
non_null(1, 2) nullable(3, 4)
bool announce_on_stored(const Announcements *announce, const uint8_t *data_public_key,
                        announce_on_retrieve_cb *on_retrieve_callback, void *object);

non_null()
void announce_set_synch_offset(Announcements *announce, int32_t synch_offset);

nullable(1)
void kill_announcements(Announcements *announce);


/* The declarations below are not public, they are exposed only for tests. */

/** @private
 * Return xor of first ANNOUNCE_BUCKET_PREFIX_LENGTH bits from one bit after
 * base and pk first differ
 */
non_null()
uint16_t announce_get_bucketnum(const uint8_t *base, const uint8_t *pk);

/** @private */
non_null(1, 2) nullable(3)
bool announce_store_data(Announcements *announce, const uint8_t *data_public_key,
                         const uint8_t *data, uint32_t length, uint32_t timeout);

/** @private */
#define MAX_MAX_ANNOUNCEMENT_TIMEOUT 900
#define MIN_MAX_ANNOUNCEMENT_TIMEOUT 10
#define MAX_ANNOUNCEMENT_TIMEOUT_UPTIME_RATIO 4

/** @private
 * For efficient lookup and updating, entries are stored as a hash table keyed
 * to the first ANNOUNCE_BUCKET_PREFIX_LENGTH bits starting from one bit after
 * the first bit in which data public key first differs from the dht key, with
 * (2-adically) closest keys preferentially stored within a given bucket. A
 * given key appears at most once (even if timed out).
 */
#define ANNOUNCE_BUCKET_SIZE 8
#define ANNOUNCE_BUCKET_PREFIX_LENGTH 5
#define ANNOUNCE_BUCKETS 32 // ANNOUNCE_BUCKETS = 2 ** ANNOUNCE_BUCKET_PREFIX_LENGTH

#endif
