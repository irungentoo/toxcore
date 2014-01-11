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
 *
 * num is 0 if we used our secret public key for the announce
 * num is 1 + friendnum if we use a temporary one.
 *
 * Public key is the key we will be sending it to.
 *
 * sendback must be at least ONION_ANNOUNCE_SENDBACK_DATA_LENGTH big
 *
 * return -1 on failure
 * return 0 on success
 *
 */
static int new_sendback(Onion_Client *onion_c, uint32_t num, uint8_t *public_key, uint8_t *sendback)
{
    uint8_t plain[sizeof(uint32_t) + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES];
    uint64_t time = unix_time();
    memcpy(plain, &num, sizeof(uint32_t));
    memcpy(plain + sizeof(uint32_t), &time, sizeof(uint64_t));
    memcpy(plain + sizeof(uint32_t) + sizeof(uint64_t), public_key, crypto_box_PUBLICKEYBYTES);

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
 * return ~0 on failure
 * return num (see new_sendback(...)) on success
 */
static uint32_t check_sendback(Onion_Client *onion_c, uint8_t *sendback, uint8_t *returned_pubkey)
{
    uint8_t plain[sizeof(uint32_t) + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES];
    int len = decrypt_data_symmetric(onion_c->secret_symmetric_key, sendback, sendback + crypto_secretbox_NONCEBYTES,
                                     ONION_ANNOUNCE_SENDBACK_DATA_LENGTH - crypto_secretbox_NONCEBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return -1;

    uint64_t timestamp;
    memcpy(&timestamp, plain + sizeof(uint32_t), sizeof(uint64_t));
    uint64_t temp_time = unix_time();

    if (timestamp + ANNOUNCE_TIMEOUT < temp_time || temp_time < timestamp)
        return -1;

    memcpy(returned_pubkey, plain + sizeof(uint32_t) + sizeof(uint64_t), crypto_box_PUBLICKEYBYTES);
    uint32_t num;
    memcpy(&num, plain, sizeof(uint32_t));
    return plain[0];
}

static int client_send_announce_request(Onion_Client *onion_c, uint32_t num, IP_Port dest, uint8_t *dest_pubkey,
                                        uint8_t *ping_id)
{
    if (num > onion_c->num_friends)
        return -1;

    uint8_t sendback[ONION_ANNOUNCE_SENDBACK_DATA_LENGTH];

    if (new_sendback(onion_c, 0, dest_pubkey, sendback) == -1)
        return -1;

    uint8_t zero_ping_id[ONION_PING_ID_SIZE] = {0};

    if (ping_id == NULL)
        ping_id = zero_ping_id;

    Node_format nodes[4];

    if (random_path(onion_c, nodes) == -1)
        return -1;

    nodes[3].ip_port = dest;
    memcpy(nodes[3].client_id, dest_pubkey, crypto_box_PUBLICKEYBYTES);

    if (num == 0) {
        return send_announce_request(onion_c->dht, nodes, onion_c->dht->c->self_public_key,
                                     onion_c->dht->c->self_secret_key, ping_id,
                                     onion_c->dht->c->self_public_key, sendback);
    } else {
        return send_announce_request(onion_c->dht, nodes, onion_c->friends_list[num - 1].temp_public_key,
                                     onion_c->friends_list[num - 1].temp_secret_key, ping_id,
                                     onion_c->friends_list[num - 1].fake_client_id, sendback);
    }
}

static int client_add_to_list(Onion_Client *onion_c, uint32_t num, uint8_t *public_key, IP_Port ip_port,
                              uint8_t *ping_id)
{

    return 0;
}

static int client_ping_nodes(Onion_Client *onion_c, uint32_t num, Node_format *nodes, uint16_t num_nodes)
{
    if (num > onion_c->num_friends)
        return -1;

    if (num_nodes == 0)
        return 0;

    Onion_Node *list_nodes = NULL;
    uint8_t *reference_id = NULL;

    if (num == 0) {
        list_nodes = onion_c->clients_announce_list;
        reference_id = onion_c->dht->c->self_public_key;
    } else {
        list_nodes = onion_c->friends_list[num - 1].clients_list;
        reference_id = onion_c->friends_list[num - 1].real_client_id;
    }

    uint32_t i;

    for (i = 0; i < num_nodes; ++i) {
        if (is_timeout(list_nodes[0].timestamp, ONION_NODE_TIMEOUT)
                || id_closest(reference_id, list_nodes[0].client_id, nodes[i].client_id) == 2) {
            client_send_announce_request(onion_c, num, nodes[i].ip_port, nodes[i].client_id, NULL);
        }
    }

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

    uint32_t num = check_sendback(onion_c, packet + 1, public_key);

    if (num > onion_c->num_friends)
        return 1;

    uint8_t plain[ONION_PING_ID_SIZE + num_nodes * sizeof(Node_format)];
    int len = -1;

    if (num == 0) {
        len = decrypt_data(public_key, onion_c->dht->c->self_secret_key, packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES,
                           length - (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES), plain);
    } else {
        if (onion_c->friends_list[num - 1].status == 0)
            return 1;

        len = decrypt_data(public_key, onion_c->friends_list[num - 1].temp_secret_key,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES,
                           length - (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES), plain);
    }

    if ((uint32_t)len != sizeof(plain))
        return 1;

    //TODO
    //if (client_add_to_list(onion_c, num, uint8_t *public_key, IP_Port ip_port, plain) == -1)
    //    return 1;

    if (client_ping_nodes(onion_c, num, (Node_format *)plain + ONION_PING_ID_SIZE, num_nodes) == -1)
        return 1;

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
