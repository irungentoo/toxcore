/*
 * ping.c -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "DHT.h"
#include "ping.h"

#include "network.h"
#include "util.h"
#include "ping_array.h"

#define PING_NUM_MAX 512

/* Maximum newly announced nodes to ping per TIME_TO_PING seconds. */
#define MAX_TO_PING 16

/* Ping newly announced nodes to ping per TIME_TO_PING seconds*/
#define TIME_TO_PING 4


struct PING {
    DHT *dht;

    Ping_Array  ping_array;
    Node_format to_ping[MAX_TO_PING];
    uint64_t    last_to_ping;
};


#define PING_PLAIN_SIZE (1 + sizeof(uint64_t))
#define DHT_PING_SIZE (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + PING_PLAIN_SIZE + crypto_box_MACBYTES)
#define PING_DATA_SIZE (CLIENT_ID_SIZE + sizeof(IP_Port))

int send_ping_request(PING *ping, IP_Port ipp, const uint8_t *client_id)
{
    uint8_t   pk[DHT_PING_SIZE];
    int       rc;
    uint64_t  ping_id;

    if (id_equal(client_id, ping->dht->self_public_key))
        return 1;

    uint8_t shared_key[crypto_box_BEFORENMBYTES];

    // generate key to encrypt ping_id with recipient privkey
    DHT_get_shared_key_sent(ping->dht, shared_key, client_id);
    // Generate random ping_id.
    uint8_t data[PING_DATA_SIZE];
    id_copy(data, client_id);
    memcpy(data + CLIENT_ID_SIZE, &ipp, sizeof(IP_Port));
    ping_id = ping_array_add(&ping->ping_array, data, sizeof(data));

    if (ping_id == 0)
        return 1;

    uint8_t ping_plain[PING_PLAIN_SIZE];
    ping_plain[0] = NET_PACKET_PING_REQUEST;
    memcpy(ping_plain + 1, &ping_id, sizeof(ping_id));

    pk[0] = NET_PACKET_PING_REQUEST;
    id_copy(pk + 1, ping->dht->self_public_key);     // Our pubkey
    new_nonce(pk + 1 + CLIENT_ID_SIZE); // Generate new nonce


    rc = encrypt_data_symmetric(shared_key,
                                pk + 1 + CLIENT_ID_SIZE,
                                ping_plain, sizeof(ping_plain),
                                pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES);

    if (rc != PING_PLAIN_SIZE + crypto_box_MACBYTES)
        return 1;

    return sendpacket(ping->dht->net, ipp, pk, sizeof(pk));
}

static int send_ping_response(PING *ping, IP_Port ipp, const uint8_t *client_id, uint64_t ping_id,
                              uint8_t *shared_encryption_key)
{
    uint8_t   pk[DHT_PING_SIZE];
    int       rc;

    if (id_equal(client_id, ping->dht->self_public_key))
        return 1;

    uint8_t ping_plain[PING_PLAIN_SIZE];
    ping_plain[0] = NET_PACKET_PING_RESPONSE;
    memcpy(ping_plain + 1, &ping_id, sizeof(ping_id));

    pk[0] = NET_PACKET_PING_RESPONSE;
    id_copy(pk + 1, ping->dht->self_public_key);     // Our pubkey
    new_nonce(pk + 1 + CLIENT_ID_SIZE); // Generate new nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data_symmetric(shared_encryption_key,
                                pk + 1 + CLIENT_ID_SIZE,
                                ping_plain, sizeof(ping_plain),
                                pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES );

    if (rc != PING_PLAIN_SIZE + crypto_box_MACBYTES)
        return 1;

    return sendpacket(ping->dht->net, ipp, pk, sizeof(pk));
}

static int handle_ping_request(void *_dht, IP_Port source, const uint8_t *packet, uint16_t length)
{
    DHT       *dht = _dht;
    int        rc;

    if (length != DHT_PING_SIZE)
        return 1;

    PING *ping = dht->ping;

    if (id_equal(packet + 1, ping->dht->self_public_key))
        return 1;

    uint8_t shared_key[crypto_box_BEFORENMBYTES];

    uint8_t ping_plain[PING_PLAIN_SIZE];
    // Decrypt ping_id
    DHT_get_shared_key_recv(dht, shared_key, packet + 1);
    rc = decrypt_data_symmetric(shared_key,
                                packet + 1 + CLIENT_ID_SIZE,
                                packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                                PING_PLAIN_SIZE + crypto_box_MACBYTES,
                                ping_plain );

    if (rc != sizeof(ping_plain))
        return 1;

    if (ping_plain[0] != NET_PACKET_PING_REQUEST)
        return 1;

    uint64_t   ping_id;
    memcpy(&ping_id, ping_plain + 1, sizeof(ping_id));
    // Send response
    send_ping_response(ping, source, packet + 1, ping_id, shared_key);
    add_to_ping(ping, packet + 1, source);

    return 0;
}

static int handle_ping_response(void *_dht, IP_Port source, const uint8_t *packet, uint16_t length)
{
    DHT      *dht = _dht;
    int       rc;

    if (length != DHT_PING_SIZE)
        return 1;

    PING *ping = dht->ping;

    if (id_equal(packet + 1, ping->dht->self_public_key))
        return 1;

    uint8_t shared_key[crypto_box_BEFORENMBYTES];

    // generate key to encrypt ping_id with recipient privkey
    DHT_get_shared_key_sent(ping->dht, shared_key, packet + 1);

    uint8_t ping_plain[PING_PLAIN_SIZE];
    // Decrypt ping_id
    rc = decrypt_data_symmetric(shared_key,
                                packet + 1 + CLIENT_ID_SIZE,
                                packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                                PING_PLAIN_SIZE + crypto_box_MACBYTES,
                                ping_plain);

    if (rc != sizeof(ping_plain))
        return 1;

    if (ping_plain[0] != NET_PACKET_PING_RESPONSE)
        return 1;

    uint64_t   ping_id;
    memcpy(&ping_id, ping_plain + 1, sizeof(ping_id));
    uint8_t data[PING_DATA_SIZE];

    if (ping_array_check(data, sizeof(data), &ping->ping_array, ping_id) != sizeof(data))
        return 1;

    if (!id_equal(packet + 1, data))
        return 1;

    IP_Port ipp;
    memcpy(&ipp, data + CLIENT_ID_SIZE, sizeof(IP_Port));

    if (!ipport_equal(&ipp, &source))
        return 1;

    addto_lists(dht, source, packet + 1);
    return 0;
}

/* Check if client_id with ip_port is in the list.
 *
 * return 1 if it is.
 * return 0 if it isn't.
 */
static int in_list(const Client_data *list, uint16_t length, const uint8_t *client_id, IP_Port ip_port)
{
    uint32_t i;

    for (i = 0; i < length; ++i) {
        if (id_equal(list[i].client_id, client_id)) {
            const IPPTsPng *ipptp;

            if (ip_port.ip.family == AF_INET) {
                ipptp = &list[i].assoc4;
            } else {
                ipptp = &list[i].assoc6;
            }

            if (!is_timeout(ipptp->timestamp, BAD_NODE_TIMEOUT) && ipport_equal(&ipptp->ip_port, &ip_port))
                return 1;
        }
    }

    return 0;
}

/* Add nodes to the to_ping list.
 * All nodes in this list are pinged every TIME_TO_PING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our client_id are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int add_to_ping(PING *ping, const uint8_t *client_id, IP_Port ip_port)
{
    if (!ip_isset(&ip_port.ip))
        return -1;

    if (in_list(ping->dht->close_clientlist, LCLIENT_LIST, client_id, ip_port))
        return -1;

    uint32_t i;

    for (i = 0; i < MAX_TO_PING; ++i) {
        if (!ip_isset(&ping->to_ping[i].ip_port.ip)) {
            memcpy(ping->to_ping[i].public_key, client_id, CLIENT_ID_SIZE);
            ipport_copy(&ping->to_ping[i].ip_port, &ip_port);
            return 0;
        }

        if (memcmp(ping->to_ping[i].public_key, client_id, CLIENT_ID_SIZE) == 0) {
            return -1;
        }
    }

    uint32_t r = rand();

    for (i = 0; i < MAX_TO_PING; ++i) {
        if (id_closest(ping->dht->self_public_key, ping->to_ping[(i + r) % MAX_TO_PING].public_key, client_id) == 2) {
            memcpy(ping->to_ping[(i + r) % MAX_TO_PING].public_key, client_id, CLIENT_ID_SIZE);
            ipport_copy(&ping->to_ping[(i + r) % MAX_TO_PING].ip_port, &ip_port);
            return 0;
        }
    }

    return -1;
}


/* Ping all the valid nodes in the to_ping list every TIME_TO_PING seconds.
 * This function must be run at least once every TIME_TO_PING seconds.
 */
void do_to_ping(PING *ping)
{
    if (!is_timeout(ping->last_to_ping, TIME_TO_PING))
        return;

    if (!ip_isset(&ping->to_ping[0].ip_port.ip))
        return;

    uint32_t i;

    for (i = 0; i < MAX_TO_PING; ++i) {
        if (!ip_isset(&ping->to_ping[i].ip_port.ip))
            break;

        send_ping_request(ping, ping->to_ping[i].ip_port, ping->to_ping[i].public_key);
        ip_reset(&ping->to_ping[i].ip_port.ip);
    }

    if (i != 0)
        ping->last_to_ping = unix_time();
}


PING *new_ping(DHT *dht)
{
    PING *ping = calloc(1, sizeof(PING));

    if (ping == NULL)
        return NULL;

    if (ping_array_init(&ping->ping_array, PING_NUM_MAX, PING_TIMEOUT) != 0) {
        free(ping);
        return NULL;
    }

    ping->dht = dht;
    networking_registerhandler(ping->dht->net, NET_PACKET_PING_REQUEST, &handle_ping_request, dht);
    networking_registerhandler(ping->dht->net, NET_PACKET_PING_RESPONSE, &handle_ping_response, dht);

    return ping;
}

void kill_ping(PING *ping)
{
    networking_registerhandler(ping->dht->net, NET_PACKET_PING_REQUEST, NULL, NULL);
    networking_registerhandler(ping->dht->net, NET_PACKET_PING_RESPONSE, NULL, NULL);
    ping_array_free_all(&ping->ping_array);

    free(ping);
}
