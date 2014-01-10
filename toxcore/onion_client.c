/*
* onion_client.c -- Implementation of the client part of docs/Prevent_Tracking.txt
*                   (The part that uses the onion stuff to connect to the friend)
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

#include "onion_client.h"
#include "util.h"

#define ANNOUNCE_TIMEOUT 10

/* Creates a sendback for use in an announce request.
 * Public key is the key we will be sending it to.
 *
 * sendback must be at least ONION_ANNOUNCE_SENDBACK_DATA_LENGTH big
 *
 * return -1 on failure
 * return 0 on success
 *
 */
static int new_sendback(Onion_Client *onion_c, uint8_t *public_key, uint8_t *sendback)
{
    uint8_t plain[sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES];
    uint64_t time = unix_time();
    memcpy(plain, &time, sizeof(uint64_t));
    memcpy(plain + sizeof(uint64_t), public_key, crypto_box_PUBLICKEYBYTES);

    int len = encrypt_data_symmetric(onion_c->secret_symmetric_key, sendback, plain, sizeof(plain),
                                     sendback + crypto_secretbox_NONCEBYTES);

    if ((uint32_t)len + crypto_secretbox_NONCEBYTES != ONION_ANNOUNCE_SENDBACK_DATA_LENGTH)
        return -1;

    return 0;
}

/* Checks if the sendback is valid and returns the public key contained in it in returned_pubkey
 *
 * sendback is the sendback ONION_ANNOUNCE_SENDBACK_DATA_LENGTH big
 * returned_pubkey must be at least crypto_box_PUBLICKEYBYTES big
 *
 * return -1 on failure
 * return 0 on success
 */
static int check_sendback(Onion_Client *onion_c, uint8_t *sendback, uint8_t *returned_pubkey)
{
    uint8_t plain[sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES];
    int len = decrypt_data_symmetric(onion_c->secret_symmetric_key, sendback, sendback + crypto_secretbox_NONCEBYTES,
                                     ONION_ANNOUNCE_SENDBACK_DATA_LENGTH - crypto_secretbox_NONCEBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return -1;

    uint64_t timestamp;
    memcpy(&timestamp, plain, sizeof(uint64_t));
    uint64_t temp_time = unix_time();

    if (timestamp + ANNOUNCE_TIMEOUT < temp_time || temp_time < timestamp)
        return -1;

    memcpy(returned_pubkey, plain + sizeof(uint64_t), crypto_box_PUBLICKEYBYTES);
    return 0;
}

static int handle_announce_response(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Client *onion_c = object;

    if (length < ONION_ANNOUNCE_RESPONSE_MIN_SIZE || length > ONION_ANNOUNCE_RESPONSE_MAX_SIZE)
        return 1;

    if ((length - ONION_ANNOUNCE_RESPONSE_MIN_SIZE) % sizeof(Node_format) != 0)
        return 1;

    uint16_t num_nodes = (length - ONION_ANNOUNCE_RESPONSE_MIN_SIZE) / sizeof(Node_format);

    uint8_t public_key[crypto_box_PUBLICKEYBYTES];

    if (check_sendback(onion_c, packet + 1, public_key) == -1)
        return 1;

    uint8_t plain[ONION_PING_ID_SIZE + num_nodes * sizeof(Node_format)];

    //int len = decrypt_data(uint8_t *public_key, uint8_t *secret_key, uint8_t *nonce, uint8_t *encrypted, uint32_t length, uint8_t *plain);
    //TODO
    return 0;
}

static int handle_data_response(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Client *onion_c = object;

    return 0;
}

/* Takes 3 random nodes that we know and puts them in nodes
 *
 * nodes must be longer than 3.
 *
 * return -1 on failure
 * return 0 on success
 *
 */
int random_path(Onion_Client *onion_c, Node_format *nodes)
{

    return -1;
}

static void do_friend(Onion_Client *onion_c, uint16_t friendnum)
{


}

static void do_announce(Onion_Client *onion_c)
{
    uint32_t i;

    for (i = 0; i < MAX_ONION_CLIENTS; ++i) {

    }
}

void do_onion_client(Onion_Client *onion_c)
{
    uint32_t i;
    do_announce(onion_c);

    for (i = 0; i < onion_c->num_friends; ++i) {
        do_friend(onion_c, i);
    }
}

Onion_Client *new_onion_client(DHT *dht)
{
    if (dht == NULL)
        return NULL;

    Onion_Client *onion_c = calloc(1, sizeof(Onion_Client));

    if (onion_c == NULL)
        return NULL;

    onion_c->dht = dht;
    onion_c->net = dht->c->lossless_udp->net;
    new_symmetric_key(onion_c->secret_symmetric_key);

    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, &handle_announce_response, onion_c);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, &handle_data_response, onion_c);

    return onion_c;
}

void kill_onion_client(Onion_Client *onion_c)
{
    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, NULL, NULL);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, NULL, NULL);
    free(onion_c);
}
