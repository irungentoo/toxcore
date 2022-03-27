/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/**
 * Buffered pinging using cyclic arrays.
 */
#include "ping.h"

#include <stdlib.h>
#include <string.h>

#include "DHT.h"
#include "ccompat.h"
#include "mono_time.h"
#include "network.h"
#include "ping_array.h"
#include "util.h"

#define PING_NUM_MAX 512

/** Maximum newly announced nodes to ping per TIME_TO_PING seconds. */
#define MAX_TO_PING 32

/** Ping newly announced nodes to ping per TIME_TO_PING seconds*/
#define TIME_TO_PING 2


struct Ping {
    const Mono_Time *mono_time;
    const Random *rng;
    DHT *dht;

    Ping_Array  *ping_array;
    Node_format to_ping[MAX_TO_PING];
    uint64_t    last_to_ping;
};


#define PING_PLAIN_SIZE (1 + sizeof(uint64_t))
#define DHT_PING_SIZE (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + PING_PLAIN_SIZE + CRYPTO_MAC_SIZE)
#define PING_DATA_SIZE (CRYPTO_PUBLIC_KEY_SIZE + sizeof(IP_Port))

void ping_send_request(Ping *ping, const IP_Port *ipp, const uint8_t *public_key)
{
    uint8_t   pk[DHT_PING_SIZE];
    int       rc;
    uint64_t  ping_id;

    if (pk_equal(public_key, dht_get_self_public_key(ping->dht))) {
        return;
    }

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    // generate key to encrypt ping_id with recipient privkey
    dht_get_shared_key_sent(ping->dht, shared_key, public_key);
    // Generate random ping_id.
    uint8_t data[PING_DATA_SIZE];
    pk_copy(data, public_key);
    memcpy(data + CRYPTO_PUBLIC_KEY_SIZE, ipp, sizeof(IP_Port));
    ping_id = ping_array_add(ping->ping_array, ping->mono_time, ping->rng, data, sizeof(data));

    if (ping_id == 0) {
        crypto_memzero(shared_key, sizeof(shared_key));
        return;
    }

    uint8_t ping_plain[PING_PLAIN_SIZE];
    ping_plain[0] = NET_PACKET_PING_REQUEST;
    memcpy(ping_plain + 1, &ping_id, sizeof(ping_id));

    pk[0] = NET_PACKET_PING_REQUEST;
    pk_copy(pk + 1, dht_get_self_public_key(ping->dht));     // Our pubkey
    random_nonce(ping->rng, pk + 1 + CRYPTO_PUBLIC_KEY_SIZE); // Generate new nonce


    rc = encrypt_data_symmetric(shared_key,
                                pk + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                ping_plain, sizeof(ping_plain),
                                pk + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);

    crypto_memzero(shared_key, sizeof(shared_key));

    if (rc != PING_PLAIN_SIZE + CRYPTO_MAC_SIZE) {
        return;
    }

    // We never check this return value and failures in sendpacket are already logged
    sendpacket(dht_get_net(ping->dht), ipp, pk, sizeof(pk));
}

non_null()
static int ping_send_response(const Ping *ping, const IP_Port *ipp, const uint8_t *public_key,
                              uint64_t ping_id, const uint8_t *shared_encryption_key)
{
    uint8_t pk[DHT_PING_SIZE];

    if (pk_equal(public_key, dht_get_self_public_key(ping->dht))) {
        return 1;
    }

    uint8_t ping_plain[PING_PLAIN_SIZE];
    ping_plain[0] = NET_PACKET_PING_RESPONSE;
    memcpy(ping_plain + 1, &ping_id, sizeof(ping_id));

    pk[0] = NET_PACKET_PING_RESPONSE;
    pk_copy(pk + 1, dht_get_self_public_key(ping->dht));     // Our pubkey
    random_nonce(ping->rng, pk + 1 + CRYPTO_PUBLIC_KEY_SIZE); // Generate new nonce

    // Encrypt ping_id using recipient privkey
    const int rc = encrypt_data_symmetric(shared_encryption_key,
                                          pk + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                          ping_plain, sizeof(ping_plain),
                                          pk + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);

    if (rc != PING_PLAIN_SIZE + CRYPTO_MAC_SIZE) {
        return 1;
    }

    return sendpacket(dht_get_net(ping->dht), ipp, pk, sizeof(pk));
}

non_null()
static int handle_ping_request(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                               void *userdata)
{
    DHT *dht = (DHT *)object;

    if (length != DHT_PING_SIZE) {
        return 1;
    }

    Ping *ping = dht_get_ping(dht);

    if (pk_equal(packet + 1, dht_get_self_public_key(ping->dht))) {
        return 1;
    }

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t ping_plain[PING_PLAIN_SIZE];

    // Decrypt ping_id
    dht_get_shared_key_recv(dht, shared_key, packet + 1);
    const int rc = decrypt_data_symmetric(shared_key,
                                          packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                          packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                                          PING_PLAIN_SIZE + CRYPTO_MAC_SIZE,
                                          ping_plain);

    if (rc != sizeof(ping_plain)) {
        crypto_memzero(shared_key, sizeof(shared_key));
        return 1;
    }

    if (ping_plain[0] != NET_PACKET_PING_REQUEST) {
        crypto_memzero(shared_key, sizeof(shared_key));
        return 1;
    }

    uint64_t ping_id;
    memcpy(&ping_id, ping_plain + 1, sizeof(ping_id));
    // Send response
    ping_send_response(ping, source, packet + 1, ping_id, shared_key);
    ping_add(ping, packet + 1, source);

    crypto_memzero(shared_key, sizeof(shared_key));

    return 0;
}

non_null()
static int handle_ping_response(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                                void *userdata)
{
    DHT      *dht = (DHT *)object;
    int       rc;

    if (length != DHT_PING_SIZE) {
        return 1;
    }

    Ping *ping = dht_get_ping(dht);

    if (pk_equal(packet + 1, dht_get_self_public_key(ping->dht))) {
        return 1;
    }

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    // generate key to encrypt ping_id with recipient privkey
    dht_get_shared_key_sent(ping->dht, shared_key, packet + 1);

    uint8_t ping_plain[PING_PLAIN_SIZE];
    // Decrypt ping_id
    rc = decrypt_data_symmetric(shared_key,
                                packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                                PING_PLAIN_SIZE + CRYPTO_MAC_SIZE,
                                ping_plain);

    crypto_memzero(shared_key, sizeof(shared_key));

    if (rc != sizeof(ping_plain)) {
        return 1;
    }

    if (ping_plain[0] != NET_PACKET_PING_RESPONSE) {
        return 1;
    }

    uint64_t   ping_id;
    memcpy(&ping_id, ping_plain + 1, sizeof(ping_id));
    uint8_t data[PING_DATA_SIZE];

    if (ping_array_check(ping->ping_array, ping->mono_time, data, sizeof(data), ping_id) != sizeof(data)) {
        return 1;
    }

    if (!pk_equal(packet + 1, data)) {
        return 1;
    }

    IP_Port ipp;
    memcpy(&ipp, data + CRYPTO_PUBLIC_KEY_SIZE, sizeof(IP_Port));

    if (!ipport_equal(&ipp, source)) {
        return 1;
    }

    addto_lists(dht, source, packet + 1);
    return 0;
}

/** @brief Check if public_key with ip_port is in the list.
 *
 * return true if it is.
 * return false if it isn't.
 */
non_null()
static bool in_list(const Client_data *list, uint16_t length, const Mono_Time *mono_time, const uint8_t *public_key,
                    const IP_Port *ip_port)
{
    for (unsigned int i = 0; i < length; ++i) {
        if (pk_equal(list[i].public_key, public_key)) {
            const IPPTsPng *ipptp;

            if (net_family_is_ipv4(ip_port->ip.family)) {
                ipptp = &list[i].assoc4;
            } else {
                ipptp = &list[i].assoc6;
            }

            if (!mono_time_is_timeout(mono_time, ipptp->timestamp, BAD_NODE_TIMEOUT)
                    && ipport_equal(&ipptp->ip_port, ip_port)) {
                return true;
            }
        }
    }

    return false;
}

/** @brief Add nodes to the to_ping list.
 * All nodes in this list are pinged every TIME_TO_PING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our public_key are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 * @retval 0 if node was added.
 * @retval -1 if node was not added.
 */
int32_t ping_add(Ping *ping, const uint8_t *public_key, const IP_Port *ip_port)
{
    if (!ip_isset(&ip_port->ip)) {
        return -1;
    }

    if (!node_addable_to_close_list(ping->dht, public_key, ip_port)) {
        return -1;
    }

    if (in_list(dht_get_close_clientlist(ping->dht), LCLIENT_LIST, ping->mono_time, public_key, ip_port)) {
        return -1;
    }

    IP_Port temp;

    if (dht_getfriendip(ping->dht, public_key, &temp) == 0) {
        ping_send_request(ping, ip_port, public_key);
        return -1;
    }

    for (unsigned int i = 0; i < MAX_TO_PING; ++i) {
        if (!ip_isset(&ping->to_ping[i].ip_port.ip)) {
            memcpy(ping->to_ping[i].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
            ipport_copy(&ping->to_ping[i].ip_port, ip_port);
            return 0;
        }

        if (pk_equal(ping->to_ping[i].public_key, public_key)) {
            return -1;
        }
    }

    if (add_to_list(ping->to_ping, MAX_TO_PING, public_key, ip_port, dht_get_self_public_key(ping->dht))) {
        return 0;
    }

    return -1;
}


/** @brief Ping all the valid nodes in the to_ping list every TIME_TO_PING seconds.
 * This function must be run at least once every TIME_TO_PING seconds.
 */
void ping_iterate(Ping *ping)
{
    if (!mono_time_is_timeout(ping->mono_time, ping->last_to_ping, TIME_TO_PING)) {
        return;
    }

    if (!ip_isset(&ping->to_ping[0].ip_port.ip)) {
        return;
    }

    unsigned int i;

    for (i = 0; i < MAX_TO_PING; ++i) {
        if (!ip_isset(&ping->to_ping[i].ip_port.ip)) {
            break;
        }

        if (!node_addable_to_close_list(ping->dht, ping->to_ping[i].public_key, &ping->to_ping[i].ip_port)) {
            continue;
        }

        ping_send_request(ping, &ping->to_ping[i].ip_port, ping->to_ping[i].public_key);
        ip_reset(&ping->to_ping[i].ip_port.ip);
    }

    if (i != 0) {
        ping->last_to_ping = mono_time_get(ping->mono_time);
    }
}


Ping *ping_new(const Mono_Time *mono_time, const Random *rng, DHT *dht)
{
    Ping *ping = (Ping *)calloc(1, sizeof(Ping));

    if (ping == nullptr) {
        return nullptr;
    }

    ping->ping_array = ping_array_new(PING_NUM_MAX, PING_TIMEOUT);

    if (ping->ping_array == nullptr) {
        free(ping);
        return nullptr;
    }

    ping->mono_time = mono_time;
    ping->rng = rng;
    ping->dht = dht;
    networking_registerhandler(dht_get_net(ping->dht), NET_PACKET_PING_REQUEST, &handle_ping_request, dht);
    networking_registerhandler(dht_get_net(ping->dht), NET_PACKET_PING_RESPONSE, &handle_ping_response, dht);

    return ping;
}

void ping_kill(Ping *ping)
{
    if (ping == nullptr) {
        return;
    }

    networking_registerhandler(dht_get_net(ping->dht), NET_PACKET_PING_REQUEST, nullptr, nullptr);
    networking_registerhandler(dht_get_net(ping->dht), NET_PACKET_PING_RESPONSE, nullptr, nullptr);
    ping_array_kill(ping->ping_array);

    free(ping);
}
