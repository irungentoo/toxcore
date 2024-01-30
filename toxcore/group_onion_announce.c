/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

#include "group_onion_announce.h"

#include <assert.h>
#include <string.h>

#include "DHT.h"
#include "attributes.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "group_announce.h"
#include "logger.h"
#include "mono_time.h"
#include "network.h"
#include "onion_announce.h"
#include "timed_auth.h"

static_assert(GCA_ANNOUNCE_MAX_SIZE <= ONION_MAX_EXTRA_DATA_SIZE,
              "GC_Announce does not fit into the onion packet extra data");

static pack_extra_data_cb pack_group_announces;
non_null()
static int pack_group_announces(void *object, const Logger *logger, const Mono_Time *mono_time,
                                uint8_t num_nodes, uint8_t *plain, uint16_t plain_size,
                                uint8_t *response, uint16_t response_size, uint16_t offset)
{
    GC_Announces_List *gc_announces_list = (GC_Announces_List *)object;
    GC_Public_Announce public_announce;

    if (gca_unpack_public_announce(logger, plain, plain_size,
                                   &public_announce) == -1) {
        LOGGER_WARNING(logger, "Failed to unpack public group announce");
        return -1;
    }

    const GC_Peer_Announce *new_announce = gca_add_announce(mono_time, gc_announces_list, &public_announce);

    if (new_announce == nullptr) {
        LOGGER_ERROR(logger, "Failed to add group announce");
        return -1;
    }

    GC_Announce gc_announces[GCA_MAX_SENT_ANNOUNCES];
    const int num_ann = gca_get_announces(gc_announces_list,
                                          gc_announces,
                                          GCA_MAX_SENT_ANNOUNCES,
                                          public_announce.chat_public_key,
                                          new_announce->base_announce.peer_public_key);

    if (num_ann < 0) {
        LOGGER_ERROR(logger, "failed to get group announce");
        return -1;
    }

    assert(num_ann <= UINT8_MAX);

    size_t announces_length = 0;

    if (gca_pack_announces_list(logger, response + offset, response_size - offset, gc_announces, (uint8_t)num_ann,
                                &announces_length) != num_ann) {
        LOGGER_WARNING(logger, "Failed to pack group announces list");
        return -1;
    }

    return announces_length;
}

void gca_onion_init(GC_Announces_List *group_announce, Onion_Announce *onion_a)
{
    onion_announce_extra_data_callback(onion_a, GCA_MAX_SENT_ANNOUNCES * sizeof(GC_Announce), pack_group_announces,
                                       group_announce);
}

int create_gca_announce_request(
    const Random *rng, uint8_t *packet, uint16_t max_packet_length, const uint8_t *dest_client_id,
    const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *ping_id,
    const uint8_t *client_id, const uint8_t *data_public_key, uint64_t sendback_data,
    const uint8_t *gc_data, uint16_t gc_data_length)
{
    if (max_packet_length < ONION_ANNOUNCE_REQUEST_MAX_SIZE || gc_data_length == 0) {
        return -1;
    }

    uint8_t plain[ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE +
                                     ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + GCA_ANNOUNCE_MAX_SIZE];
    uint8_t *position_in_plain = plain;
    const size_t encrypted_size = sizeof(plain) - GCA_ANNOUNCE_MAX_SIZE + gc_data_length;

    memcpy(plain, ping_id, ONION_PING_ID_SIZE);
    position_in_plain += ONION_PING_ID_SIZE;

    memcpy(position_in_plain, client_id, CRYPTO_PUBLIC_KEY_SIZE);
    position_in_plain += CRYPTO_PUBLIC_KEY_SIZE;

    memcpy(position_in_plain, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    position_in_plain += CRYPTO_PUBLIC_KEY_SIZE;

    memcpy(position_in_plain, &sendback_data, sizeof(sendback_data));
    position_in_plain += sizeof(sendback_data);

    memcpy(position_in_plain, gc_data, gc_data_length);

    packet[0] = NET_PACKET_ANNOUNCE_REQUEST;
    random_nonce(rng, packet + 1);
    memcpy(packet + 1 + CRYPTO_NONCE_SIZE, public_key, CRYPTO_PUBLIC_KEY_SIZE);

    const int len = encrypt_data(dest_client_id, secret_key, packet + 1, plain,
                                 encrypted_size, packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE);

    const uint32_t full_length = (uint32_t)len + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE;

    if (full_length != ONION_ANNOUNCE_REQUEST_MIN_SIZE + gc_data_length) {
        return -1;
    }

    return full_length;
}
