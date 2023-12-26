/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2022 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * The Tox private API (for tests).
 */
#include "tox_private.h"

#include <assert.h>

#include "DHT.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "group_chats.h"
#include "group_common.h"
#include "mem.h"
#include "net_crypto.h"
#include "network.h"
#include "tox.h"
#include "tox_struct.h"

#define SET_ERROR_PARAMETER(param, x) \
    do {                              \
        if (param != nullptr) {       \
            *param = x;               \
        }                             \
    } while (0)

Tox_System tox_default_system(void)
{
    const Tox_System sys = {
        nullptr,  // mono_time_callback
        nullptr,  // mono_time_user_data
        system_random(),
        system_network(),
        system_memory(),
    };
    return sys;
}

void tox_lock(const Tox *tox)
{
    if (tox->mutex != nullptr) {
        pthread_mutex_lock(tox->mutex);
    }
}

void tox_unlock(const Tox *tox)
{
    if (tox->mutex != nullptr) {
        pthread_mutex_unlock(tox->mutex);
    }
}

void tox_callback_friend_lossy_packet_per_pktid(Tox *tox, tox_friend_lossy_packet_cb *callback, uint8_t pktid)
{
    assert(tox != nullptr);

    if (pktid >= PACKET_ID_RANGE_LOSSY_START && pktid <= PACKET_ID_RANGE_LOSSY_END) {
        tox->friend_lossy_packet_callback_per_pktid[pktid] = callback;
    }
}

void tox_callback_friend_lossless_packet_per_pktid(Tox *tox, tox_friend_lossless_packet_cb *callback, uint8_t pktid)
{
    assert(tox != nullptr);

    if ((pktid >= PACKET_ID_RANGE_LOSSLESS_CUSTOM_START && pktid <= PACKET_ID_RANGE_LOSSLESS_CUSTOM_END)
            || pktid == PACKET_ID_MSI) {
        tox->friend_lossless_packet_callback_per_pktid[pktid] = callback;
    }
}

void tox_set_av_object(Tox *tox, void *object)
{
    assert(tox != nullptr);
    tox_lock(tox);
    tox->toxav_object = object;
    tox_unlock(tox);
}

void *tox_get_av_object(const Tox *tox)
{
    assert(tox != nullptr);
    tox_lock(tox);
    void *object = tox->toxav_object;
    tox_unlock(tox);
    return object;
}

void tox_callback_dht_get_nodes_response(Tox *tox, tox_dht_get_nodes_response_cb *callback)
{
    assert(tox != nullptr);
    tox->dht_get_nodes_response_callback = callback;
}

bool tox_dht_get_nodes(const Tox *tox, const uint8_t *public_key, const char *ip, uint16_t port,
                       const uint8_t *target_public_key, Tox_Err_Dht_Get_Nodes *error)
{
    assert(tox != nullptr);

    tox_lock(tox);

    if (tox->m->options.udp_disabled) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_GET_NODES_UDP_DISABLED);
        tox_unlock(tox);
        return false;
    }

    if (public_key == nullptr || ip == nullptr || target_public_key == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_GET_NODES_NULL);
        tox_unlock(tox);
        return false;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_GET_NODES_BAD_PORT);
        tox_unlock(tox);
        return false;
    }

    IP_Port *root;

    const int32_t count = net_getipport(tox->sys.mem, ip, &root, TOX_SOCK_DGRAM);

    if (count < 1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_GET_NODES_BAD_IP);
        net_freeipport(tox->sys.mem, root);
        tox_unlock(tox);
        return false;
    }

    bool success = false;

    for (int32_t i = 0; i < count; ++i) {
        root[i].port = net_htons(port);

        if (dht_getnodes(tox->m->dht, &root[i], public_key, target_public_key)) {
            success = true;
        }
    }

    tox_unlock(tox);

    net_freeipport(tox->sys.mem, root);

    if (!success) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_GET_NODES_FAIL);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_DHT_GET_NODES_OK);

    return true;
}

uint16_t tox_dht_get_num_closelist(const Tox *tox) {
    tox_lock(tox);
    const uint16_t num_total = dht_get_num_closelist(tox->m->dht);
    tox_unlock(tox);

    return num_total;
}

uint16_t tox_dht_get_num_closelist_announce_capable(const Tox *tox){
    tox_lock(tox);
    const uint16_t num_cap = dht_get_num_closelist_announce_capable(tox->m->dht);
    tox_unlock(tox);

    return num_cap;
}

size_t tox_group_peer_get_ip_address_size(const Tox *tox, uint32_t group_number, uint32_t peer_id,
                                          Tox_Err_Group_Peer_Query *error)
{
    assert(tox != nullptr);

    tox_lock(tox);
    const GC_Chat *chat = gc_get_group(tox->m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        tox_unlock(tox);
        return -1;
    }

    const int ret = gc_get_peer_ip_address_size(chat, peer_id);
    tox_unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return -1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
        return ret;
    }
}

bool tox_group_peer_get_ip_address(const Tox *tox, uint32_t group_number, uint32_t peer_id, uint8_t *ip_addr,
                               Tox_Err_Group_Peer_Query *error)
{
    assert(tox != nullptr);

    tox_lock(tox);
    const GC_Chat *chat = gc_get_group(tox->m->group_handler, group_number);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        tox_unlock(tox);
        return false;
    }

    const int ret = gc_get_peer_ip_address(chat, peer_id, ip_addr);
    tox_unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return true;
}
