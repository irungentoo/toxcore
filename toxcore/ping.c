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

#define PING_NUM_MAX 384

/* Ping newly announced nodes to ping per TIME_TOPING seconds*/
#define TIME_TOPING 5

typedef struct {
    IP_Port  ip_port;
    uint64_t id;
    uint64_t timestamp;
} pinged_t;

struct PING {
    DHT *dht;

    pinged_t    pings[PING_NUM_MAX];
    size_t      num_pings;
    size_t      pos_pings;

    Node_format toping[MAX_TOPING];
    uint64_t    last_toping;
};

static int is_ping_timeout(uint64_t time)
{
    return is_timeout(time, PING_TIMEOUT);
}

static void remove_timeouts(PING *ping)    // O(n)
{
    size_t i, id;
    size_t new_pos = ping->pos_pings;
    size_t new_num = ping->num_pings;

    // Loop through buffer, oldest first.
    for (i = 0; i < ping->num_pings; i++) {
        id = (ping->pos_pings + i) % PING_NUM_MAX;

        if (is_ping_timeout(ping->pings[id].timestamp)) {
            new_pos++;
            new_num--;
        }
        // Break here because list is sorted.
        else {
            break;
        }
    }

    ping->num_pings = new_num;
    ping->pos_pings = new_pos % PING_NUM_MAX;
}

static uint64_t add_ping(PING *ping, IP_Port ipp)  // O(n)
{
    size_t p;

    remove_timeouts(ping);

    /* Remove oldest ping if full buffer. */
    if (ping->num_pings == PING_NUM_MAX) {
        ping->num_pings--;
        ping->pos_pings = (ping->pos_pings + 1) % PING_NUM_MAX;
    }

    /* Insert new ping at end of list. */
    p = (ping->pos_pings + ping->num_pings) % PING_NUM_MAX;

    ping->pings[p].ip_port   = ipp;
    ping->pings[p].timestamp = unix_time();
    ping->pings[p].id        = random_64b();

    ping->num_pings++;
    return ping->pings[p].id;
}

/* checks if ip/port or ping_id are already in the list to ping
 * if both are set, both must match, otherwise the set must match
 *
 *  returns 0 if neither is set or no match was found
 *  returns the (index + 1) of the match if one was found
 */
static int is_pinging(PING *ping, IP_Port ipp, uint64_t ping_id)
{
    // O(n) TODO: Replace this with something else.

    /* at least one MUST be set */
    uint8_t ip_valid = ip_isset(&ipp.ip);

    if (!ip_valid && !ping_id)
        return 0;

    size_t i;

    remove_timeouts(ping);

    for (i = 0; i < ping->num_pings; i++) {
        size_t id = (ping->pos_pings + i) % PING_NUM_MAX;

        if (!ping_id || (ping->pings[id].id == ping_id))
            if (!ip_valid || ipport_equal(&ping->pings[id].ip_port, &ipp))
                return id + 1;
    }

    return 0;
}

#define DHT_PING_SIZE (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(uint64_t) + crypto_box_MACBYTES)

int send_ping_request(PING *ping, IP_Port ipp, uint8_t *client_id)
{
    uint8_t   pk[DHT_PING_SIZE];
    int       rc;
    uint64_t  ping_id;

    if (is_pinging(ping, ipp, 0) || id_equal(client_id, ping->dht->self_public_key))
        return 1;

    // Generate random ping_id.
    ping_id = add_ping(ping, ipp);

    pk[0] = NET_PACKET_PING_REQUEST;
    id_copy(pk + 1, ping->dht->self_public_key);     // Our pubkey
    new_nonce(pk + 1 + CLIENT_ID_SIZE); // Generate new nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data(client_id,
                      ping->dht->self_secret_key,
                      pk + 1 + CLIENT_ID_SIZE,
                      (uint8_t *) &ping_id, sizeof(ping_id),
                      pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES);

    if (rc != sizeof(ping_id) + crypto_box_MACBYTES)
        return 1;

    return sendpacket(ping->dht->net, ipp, pk, sizeof(pk));
}

static int send_ping_response(PING *ping, IP_Port ipp, uint8_t *client_id, uint64_t ping_id)
{
    uint8_t   pk[DHT_PING_SIZE];
    int       rc;

    if (id_equal(client_id, ping->dht->self_public_key))
        return 1;

    pk[0] = NET_PACKET_PING_RESPONSE;
    id_copy(pk + 1, ping->dht->self_public_key);     // Our pubkey
    new_nonce(pk + 1 + CLIENT_ID_SIZE); // Generate new nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data(client_id,
                      ping->dht->self_secret_key,
                      pk + 1 + CLIENT_ID_SIZE,
                      (uint8_t *) &ping_id, sizeof(ping_id),
                      pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES);

    if (rc != sizeof(ping_id) + crypto_box_MACBYTES)
        return 1;

    return sendpacket(ping->dht->net, ipp, pk, sizeof(pk));
}

static int handle_ping_request(void *_dht, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT       *dht = _dht;
    int        rc;
    uint64_t   ping_id;

    if (length != DHT_PING_SIZE)
        return 1;

    PING *ping = dht->ping;

    if (id_equal(packet + 1, ping->dht->self_public_key))
        return 1;

    // Decrypt ping_id
    rc = decrypt_data(packet + 1,
                      ping->dht->self_secret_key,
                      packet + 1 + CLIENT_ID_SIZE,
                      packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                      sizeof(ping_id) + crypto_box_MACBYTES,
                      (uint8_t *) &ping_id);

    if (rc != sizeof(ping_id))
        return 1;

    // Send response
    send_ping_response(ping, source, packet + 1, ping_id);
    add_toping(ping, packet + 1, source);

    return 0;
}

static int handle_ping_response(void *_dht, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT      *dht = _dht;
    int       rc;
    uint64_t  ping_id;

    if (length != DHT_PING_SIZE)
        return 1;

    PING *ping = dht->ping;

    if (id_equal(packet + 1, ping->dht->self_public_key))
        return 1;

    // Decrypt ping_id
    rc = decrypt_data(packet + 1,
                      ping->dht->self_secret_key,
                      packet + 1 + CLIENT_ID_SIZE,
                      packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                      sizeof(ping_id) + crypto_box_MACBYTES,
                      (uint8_t *) &ping_id);

    if (rc != sizeof(ping_id))
        return 1;

    /* Make sure ping_id is correct. */
    int ping_index = is_pinging(ping, source, ping_id);

    if (!ping_index)
        return 1;

    addto_lists(dht, source, packet + 1);

    return 0;
}


/* Add nodes to the toping list.
 * All nodes in this list are pinged every TIME_TOPING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our client_id are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int add_toping(PING *ping, uint8_t *client_id, IP_Port ip_port)
{
    if (!ip_isset(&ip_port.ip))
        return -1;

    uint32_t i;

    for (i = 0; i < MAX_TOPING; ++i) {
        if (!ip_isset(&ping->toping[i].ip_port.ip)) {
            memcpy(ping->toping[i].client_id, client_id, CLIENT_ID_SIZE);
            ipport_copy(&ping->toping[i].ip_port, &ip_port);
            return 0;
        }
    }

    for (i = 0; i < MAX_TOPING; ++i) {
        if (id_closest(ping->dht->self_public_key, ping->toping[i].client_id, client_id) == 2) {
            memcpy(ping->toping[i].client_id, client_id, CLIENT_ID_SIZE);
            ipport_copy(&ping->toping[i].ip_port, &ip_port);
            return 0;
        }
    }

    return -1;
}


/* Ping all the valid nodes in the toping list every TIME_TOPING seconds.
 * This function must be run at least once every TIME_TOPING seconds.
 */
void do_toping(PING *ping)
{
    if (!is_timeout(ping->last_toping, TIME_TOPING))
        return;

    ping->last_toping = unix_time();
    uint32_t i;

    for (i = 0; i < MAX_TOPING; ++i) {
        if (!ip_isset(&ping->toping[i].ip_port.ip))
            return;

        send_ping_request(ping, ping->toping[i].ip_port, ping->toping[i].client_id);
        ip_reset(&ping->toping[i].ip_port.ip);
    }
}


PING *new_ping(DHT *dht)
{
    PING *ping = calloc(1, sizeof(PING));

    if (ping == NULL)
        return NULL;

    ping->dht = dht;
    networking_registerhandler(ping->dht->net, NET_PACKET_PING_REQUEST, &handle_ping_request, dht);
    networking_registerhandler(ping->dht->net, NET_PACKET_PING_RESPONSE, &handle_ping_response, dht);

    return ping;
}

void kill_ping(PING *ping)
{
    networking_registerhandler(ping->dht->net, NET_PACKET_PING_REQUEST, NULL, NULL);
    networking_registerhandler(ping->dht->net, NET_PACKET_PING_RESPONSE, NULL, NULL);

    free(ping);
}
