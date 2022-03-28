/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2022 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * The Tox private API (for tests).
 */
#include "tox_private.h"

#include <assert.h>

#include "ccompat.h"
#include "network.h"
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

    const int32_t count = net_getipport(ip, &root, TOX_SOCK_DGRAM);

    if (count < 1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_GET_NODES_BAD_IP);
        net_freeipport(root);
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

    net_freeipport(root);

    if (!success) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_GET_NODES_FAIL);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_DHT_GET_NODES_OK);

    return true;
}
