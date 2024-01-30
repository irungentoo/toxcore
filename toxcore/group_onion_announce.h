/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H

#include "attributes.h"
#include "crypto_core.h"
#include "group_announce.h"
#include "onion_announce.h"

non_null()
void gca_onion_init(GC_Announces_List *group_announce, Onion_Announce *onion_a);

non_null()
int create_gca_announce_request(
    const Random *rng, uint8_t *packet, uint16_t max_packet_length, const uint8_t *dest_client_id,
    const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *ping_id,
    const uint8_t *client_id, const uint8_t *data_public_key, uint64_t sendback_data,
    const uint8_t *gc_data, uint16_t gc_data_length);

#endif /* C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H */
