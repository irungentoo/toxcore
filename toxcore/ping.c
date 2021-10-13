/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/*
 * Buffered pinging using cyclic arrays.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ping.h"

#include <stdlib.h>
#include <string.h>

#include "DHT.h"
#include "mono_time.h"
#include "network.h"
#include "ping_array.h"
#include "util.h"

#define PING_NUM_MAX 512

/* Maximum newly announced nodes to ping per TIME_TO_PING seconds. */
#define MAX_TO_PING 32

/* Ping newly announced nodes to ping per TIME_TO_PING seconds*/
#define TIME_TO_PING 2


struct Ping {
    const Mono_Time *mono_time;
    DHT *dht;

    Ping_Array  *ping_array;
    Node_format to_ping[MAX_TO_PING];
    uint64_t    last_to_ping;
};


#define PING_PLAIN_SIZE (1 + sizeof(uint64_t))
#define DHT_PING_SIZE (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + PING_PLAIN_SIZE + CRYPTO_MAC_SIZE)
#define PING_DATA_SIZE (CRYPTO_PUBLIC_KEY_SIZE + sizeof(IP_Port))

int32_t ping_send_request(Ping *ping, IP_Port ipp, const uint8_t *public_key)
{
    uint8_t   pk[DHT_PING_SIZE];
    int       rc;
    uint64_t  ping_id;

    if (id_equal(public_key, dht_get_self_public_key(ping->dht))) {
        return 1;
    }

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    // generate key to encrypt ping_id with recipient privkey
    dht_get_shared_key_sent(ping->dht, shared_key, public_key);
    // Generate random ping_id.
    uint8_t data[PING_DATA_SIZE];
    id_copy(data, public_key);
    memcpy(data + CRYPTO_PUBLIC_KEY_SIZE, &ipp, sizeof(IP_Port));
    ping_id = ping_array_add(ping->ping_array, ping->mono_time, data, sizeof(data));

    if (ping_id == 0) {
        return 1;
    }

    uint8_t ping_plain[PING_PLAIN_SIZE];
    ping_plain[0] = NET_PACKET_PING_REQUEST;
    memcpy(ping_plain + 1, &ping_id, sizeof(ping_id));

    pk[0] = NET_PACKET_PING_REQUEST;
    id_copy(pk + 1, dht_get_self_public_key(ping->dht));     // Our pubkey
    random_nonce(pk + 1 + CRYPTO_PUBLIC_KEY_SIZE); // Generate new nonce


    rc = encrypt_data_symmetric(shared_key,
                                pk + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                ping_plain, sizeof(ping_plain),
                                pk + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);

    if (rc != PING_PLAIN_SIZE + CRYPTO_MAC_SIZE) {
        return 1;
    }

    return sendpacket(dht_get_net(ping->dht), ipp, pk, sizeof(pk));
}

static int ping_send_response(Ping *ping, IP_Port ipp, const uint8_t *public_key, uint64_t ping_id,
                              uint8_t *shared_encryption_key)
{
    uint8_t   pk[DHT_PING_SIZE];
    int       rc;

    if (id_equal(public_key, dht_get_self_public_key(ping->dht))) {
        return 1;
    }

    uint8_t ping_plain[PING_PLAIN_SIZE];
    ping_plain[0] = NET_PACKET_PING_RESPONSE;
    memcpy(ping_plain + 1, &ping_id, sizeof(ping_id));

    pk[0] = NET_PACKET_PING_RESPONSE;
    id_copy(pk + 1, dht_get_self_public_key(ping->dht));     // Our pubkey
    random_nonce(pk + 1 + CRYPTO_PUBLIC_KEY_SIZE); // Generate new nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data_symmetric(shared_encryption_key,
                                pk + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                ping_plain, sizeof(ping_plain),
                                pk + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);

    if (rc != PING_PLAIN_SIZE + CRYPTO_MAC_SIZE) {
        return 1;
    }

    return sendpacket(dht_get_net(ping->dht), ipp, pk, sizeof(pk));
}

static int handle_ping_request(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    DHT       *dht = (DHT *)object;
    int        rc;

    if (length != DHT_PING_SIZE) {
        return 1;
    }

    Ping *ping = dht_get_ping(dht);

    if (id_equal(packet + 1, dht_get_self_public_key(ping->dht))) {
        return 1;
    }

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    uint8_t ping_plain[PING_PLAIN_SIZE];
    // Decrypt ping_id
    dht_get_shared_key_recv(dht, shared_key, packet + 1);
    rc = decrypt_data_symmetric(shared_key,
                                packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                                PING_PLAIN_SIZE + CRYPTO_MAC_SIZE,
                                ping_plain);

    if (rc != sizeof(ping_plain)) {
        return 1;
    }

    if (ping_plain[0] != NET_PACKET_PING_REQUEST) {
        return 1;
    }

    uint64_t   ping_id;
    memcpy(&ping_id, ping_plain + 1, sizeof(ping_id));
    // Send response
    ping_send_response(ping, source, packet + 1, ping_id, shared_key);
    ping_add(ping, packet + 1, source);

    return 0;
}

static int handle_ping_response(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    DHT      *dht = (DHT *)object;
    int       rc;

    if (length != DHT_PING_SIZE) {
        return 1;
    }

    Ping *ping = dht_get_ping(dht);

    if (id_equal(packet + 1, dht_get_self_public_key(ping->dht))) {
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

    if (!id_equal(packet + 1, data)) {
        return 1;
    }

    IP_Port ipp;
    memcpy(&ipp, data + CRYPTO_PUBLIC_KEY_SIZE, sizeof(IP_Port));

    if (!ipport_equal(&ipp, &source)) {
        return 1;
    }

    addto_lists(dht, source, packet + 1);
    return 0;
}

/* Check if public_key with ip_port is in the list.
 *
 * return 1 if it is.
 * return 0 if it isn't.
 */
static int in_list(const Client_data *list, uint16_t length, const Mono_Time *mono_time, const uint8_t *public_key,
                   IP_Port ip_port)
{
    unsigned int i;

    for (i = 0; i < length; ++i) {
        if (id_equal(list[i].public_key, public_key)) {
            const IPPTsPng *ipptp;

            if (net_family_is_ipv4(ip_port.ip.family)) {
                ipptp = &list[i].assoc4;
            } else {
                ipptp = &list[i].assoc6;
            }

            if (!mono_time_is_timeout(mono_time, ipptp->timestamp, BAD_NODE_TIMEOUT) && ipport_equal(&ipptp->ip_port, &ip_port)) {
                return 1;
            }
        }
    }

    return 0;
}

/* Add nodes to the to_ping list.
 * All nodes in this list are pinged every TIME_TO_PING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our public_key are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int32_t ping_add(Ping *ping, const uint8_t *public_key, IP_Port ip_port)
{
    if (!ip_isset(&ip_port.ip)) {
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

    unsigned int i;

    for (i = 0; i < MAX_TO_PING; ++i) {
        if (!ip_isset(&ping->to_ping[i].ip_port.ip)) {
            memcpy(ping->to_ping[i].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
            ipport_copy(&ping->to_ping[i].ip_port, &ip_port);
            return 0;
        }

        if (public_key_cmp(ping->to_ping[i].public_key, public_key) == 0) {
            return -1;
        }
    }

    if (add_to_list(ping->to_ping, MAX_TO_PING, public_key, ip_port, dht_get_self_public_key(ping->dht))) {
        return 0;
    }

    return -1;
}


/* Ping all the valid nodes in the to_ping list every TIME_TO_PING seconds.
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

        if (!node_addable_to_close_list(ping->dht, ping->to_ping[i].public_key, ping->to_ping[i].ip_port)) {
            continue;
        }

        ping_send_request(ping, ping->to_ping[i].ip_port, ping->to_ping[i].public_key);
        ip_reset(&ping->to_ping[i].ip_port.ip);
    }

    if (i != 0) {
        ping->last_to_ping = mono_time_get(ping->mono_time);
    }
}


Ping *ping_new(const Mono_Time *mono_time, DHT *dht)
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
