/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * The Tox private API (for tests).
 */
#include "tox_private.h"

#include <assert.h>

#include "DHT.h"
#include "Messenger.h"
#include "TCP_server.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "group_chats.h"
#include "group_common.h"
#include "logger.h"
#include "mem.h"
#include "net.h"
#include "net_crypto.h"
#include "net_profile.h"
#include "network.h"
#include "os_memory.h"
#include "os_network.h"
#include "os_random.h"
#include "tox.h"
#include "tox_struct.h"  // IWYU pragma: keep

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
        os_random(),
        os_network(),
        os_memory(),
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

void tox_callback_dht_nodes_response(Tox *tox, tox_dht_nodes_response_cb *callback)
{
    assert(tox != nullptr);
    tox->dht_nodes_response_callback = callback;
}

bool tox_dht_send_nodes_request(const Tox *tox, const uint8_t *public_key, const char *ip, uint16_t port,
                                const uint8_t *target_public_key, Tox_Err_Dht_Send_Nodes_Request *error)
{
    assert(tox != nullptr);

    tox_lock(tox);

    if (tox->m->options.udp_disabled) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_SEND_NODES_REQUEST_UDP_DISABLED);
        tox_unlock(tox);
        return false;
    }

    if (public_key == nullptr || ip == nullptr || target_public_key == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_SEND_NODES_REQUEST_NULL);
        tox_unlock(tox);
        return false;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_SEND_NODES_REQUEST_BAD_PORT);
        tox_unlock(tox);
        return false;
    }

    IP_Port *root;

    const int32_t count = net_getipport(tox->sys.ns, tox->sys.mem, ip, &root, TOX_SOCK_DGRAM, tox->m->options.dns_enabled);

    if (count < 1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_SEND_NODES_REQUEST_BAD_IP);
        net_freeipport(tox->sys.mem, root);
        tox_unlock(tox);
        return false;
    }

    bool success = false;

    for (int32_t i = 0; i < count; ++i) {
        root[i].port = net_htons(port);

        if (dht_send_nodes_request(tox->m->dht, &root[i], public_key, target_public_key)) {
            success = true;
        }
    }

    tox_unlock(tox);

    net_freeipport(tox->sys.mem, root);

    if (!success) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DHT_SEND_NODES_REQUEST_FAIL);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_DHT_SEND_NODES_REQUEST_OK);

    return true;
}

uint16_t tox_dht_get_num_closelist(const Tox *tox)
{
    tox_lock(tox);
    const uint16_t num_total = dht_get_num_closelist(tox->m->dht);
    tox_unlock(tox);

    return num_total;
}

uint16_t tox_dht_get_num_closelist_announce_capable(const Tox *tox)
{
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

    const int ret = gc_get_peer_ip_address_size(chat, gc_peer_id_from_int(peer_id));
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

    const int ret = gc_get_peer_ip_address(chat, gc_peer_id_from_int(peer_id), ip_addr);
    tox_unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return true;
}

uint64_t tox_netprof_get_packet_id_count(const Tox *tox, Tox_Netprof_Packet_Type type, uint8_t id,
        Tox_Netprof_Direction direction)
{
    assert(tox != nullptr);

    tox_lock(tox);

    const Net_Profile *tcp_c_profile = tox->m->tcp_np;
    const Net_Profile *tcp_s_profile = tcp_server_get_net_profile(tox->m->tcp_server);

    const Packet_Direction dir = (Packet_Direction) direction;

    uint64_t count = 0;

    switch (type) {
        case TOX_NETPROF_PACKET_TYPE_TCP_CLIENT: {
            count = netprof_get_packet_count_id(tcp_c_profile, id, dir);
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_TCP_SERVER: {
            count = netprof_get_packet_count_id(tcp_s_profile, id, dir);
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_TCP: {
            const uint64_t tcp_c_count = netprof_get_packet_count_id(tcp_c_profile, id, dir);
            const uint64_t tcp_s_count = netprof_get_packet_count_id(tcp_s_profile, id, dir);
            count = tcp_c_count + tcp_s_count;
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_UDP: {
            const Net_Profile *udp_profile = net_get_net_profile(tox->m->net);
            count = netprof_get_packet_count_id(udp_profile, id, dir);
            break;
        }

        default: {
            LOGGER_ERROR(tox->m->log, "invalid packet type: %u", type);
            break;
        }
    }

    tox_unlock(tox);

    return count;
}

uint64_t tox_netprof_get_packet_total_count(const Tox *tox, Tox_Netprof_Packet_Type type,
        Tox_Netprof_Direction direction)
{
    assert(tox != nullptr);

    tox_lock(tox);

    const Net_Profile *tcp_c_profile = tox->m->tcp_np;
    const Net_Profile *tcp_s_profile = tcp_server_get_net_profile(tox->m->tcp_server);

    const Packet_Direction dir = (Packet_Direction) direction;

    uint64_t count = 0;

    switch (type) {
        case TOX_NETPROF_PACKET_TYPE_TCP_CLIENT: {
            count = netprof_get_packet_count_total(tcp_c_profile, dir);
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_TCP_SERVER: {
            count = netprof_get_packet_count_total(tcp_s_profile, dir);
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_TCP: {
            const uint64_t tcp_c_count = netprof_get_packet_count_total(tcp_c_profile, dir);
            const uint64_t tcp_s_count = netprof_get_packet_count_total(tcp_s_profile, dir);
            count = tcp_c_count + tcp_s_count;
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_UDP: {
            const Net_Profile *udp_profile = net_get_net_profile(tox->m->net);
            count = netprof_get_packet_count_total(udp_profile, dir);
            break;
        }

        default: {
            LOGGER_ERROR(tox->m->log, "invalid packet type: %u", type);
            break;
        }
    }

    tox_unlock(tox);

    return count;
}

uint64_t tox_netprof_get_packet_id_bytes(const Tox *tox, Tox_Netprof_Packet_Type type, uint8_t id,
        Tox_Netprof_Direction direction)
{
    assert(tox != nullptr);

    tox_lock(tox);

    const Net_Profile *tcp_c_profile = tox->m->tcp_np;
    const Net_Profile *tcp_s_profile = tcp_server_get_net_profile(tox->m->tcp_server);

    const Packet_Direction dir = (Packet_Direction) direction;

    uint64_t bytes = 0;

    switch (type) {
        case TOX_NETPROF_PACKET_TYPE_TCP_CLIENT: {
            bytes = netprof_get_bytes_id(tcp_c_profile, id, dir);
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_TCP_SERVER: {
            bytes = netprof_get_bytes_id(tcp_s_profile, id, dir);
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_TCP: {
            const uint64_t tcp_c_bytes = netprof_get_bytes_id(tcp_c_profile, id, dir);
            const uint64_t tcp_s_bytes = netprof_get_bytes_id(tcp_s_profile, id, dir);
            bytes = tcp_c_bytes + tcp_s_bytes;
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_UDP: {
            const Net_Profile *udp_profile = net_get_net_profile(tox->m->net);
            bytes = netprof_get_bytes_id(udp_profile, id, dir);
            break;
        }

        default: {
            LOGGER_ERROR(tox->m->log, "invalid packet type: %u", type);
            break;
        }
    }

    tox_unlock(tox);

    return bytes;
}

uint64_t tox_netprof_get_packet_total_bytes(const Tox *tox, Tox_Netprof_Packet_Type type,
        Tox_Netprof_Direction direction)
{
    assert(tox != nullptr);

    tox_lock(tox);

    const Net_Profile *tcp_c_profile = tox->m->tcp_np;
    const Net_Profile *tcp_s_profile = tcp_server_get_net_profile(tox->m->tcp_server);

    const Packet_Direction dir = (Packet_Direction) direction;

    uint64_t bytes = 0;

    switch (type) {
        case TOX_NETPROF_PACKET_TYPE_TCP_CLIENT: {
            bytes = netprof_get_bytes_total(tcp_c_profile, dir);
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_TCP_SERVER: {
            bytes = netprof_get_bytes_total(tcp_s_profile, dir);
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_TCP: {
            const uint64_t tcp_c_bytes = netprof_get_bytes_total(tcp_c_profile, dir);
            const uint64_t tcp_s_bytes = netprof_get_bytes_total(tcp_s_profile, dir);
            bytes = tcp_c_bytes + tcp_s_bytes;
            break;
        }

        case TOX_NETPROF_PACKET_TYPE_UDP: {
            const Net_Profile *udp_profile = net_get_net_profile(tox->m->net);
            bytes = netprof_get_bytes_total(udp_profile, dir);
            break;
        }

        default: {
            LOGGER_ERROR(tox->m->log, "invalid packet type: %u", type);
            break;
        }
    }

    tox_unlock(tox);

    return bytes;
}
