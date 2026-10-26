/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H

#include <stdint.h>

#include "attributes.h"
#include "crypto_core.h"
#include "group_announce.h"
#include "mem.h"
#include "onion_announce.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum size of an announce response packet when the GCA extra-data callback
 * is active.
 *
 * The 1 here is the `num_nodes` byte (`want_node_count=true`).
 */
#define GCA_ANNOUNCE_RESPONSE_MAX_SIZE \
    (ONION_ANNOUNCE_RESPONSE_MIN_SIZE \
     + 1 \
     + MAX_SENT_NODES * PACKED_NODE_SIZE_IP6 \
     + GCA_MAX_SENT_ANNOUNCES * GCA_ANNOUNCE_MAX_SIZE)

void gca_onion_init(GC_Announces_List *_Nonnull group_announce, Onion_Announce *_Nonnull onion_a);

int create_gca_announce_request(const Memory *_Nonnull mem, const Random *_Nonnull rng, uint8_t *_Nonnull packet, uint16_t max_packet_length, const uint8_t *_Nonnull dest_client_id,
                                const uint8_t *_Nonnull public_key, const uint8_t *_Nonnull secret_key, const uint8_t *_Nonnull ping_id, const uint8_t *_Nonnull client_id, const uint8_t *_Nonnull data_public_key,
                                uint64_t sendback_data, const uint8_t *_Nonnull gc_data, uint16_t gc_data_length);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H */
