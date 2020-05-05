/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Implementation of the announce part of docs/Prevent_Tracking.txt
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "onion_announce.h"

#include <stdlib.h>
#include <string.h>

#include "LAN_discovery.h"
#include "mono_time.h"
#include "util.h"

#define PING_ID_TIMEOUT ONION_ANNOUNCE_TIMEOUT

#define ANNOUNCE_REQUEST_SIZE_RECV (ONION_ANNOUNCE_REQUEST_SIZE + ONION_RETURN_3)

#define DATA_REQUEST_MIN_SIZE ONION_DATA_REQUEST_MIN_SIZE
#define DATA_REQUEST_MIN_SIZE_RECV (DATA_REQUEST_MIN_SIZE + ONION_RETURN_3)

typedef struct Onion_Announce_Entry {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    IP_Port ret_ip_port;
    uint8_t ret[ONION_RETURN_3];
    uint8_t data_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint64_t time;
} Onion_Announce_Entry;

struct Onion_Announce {
    Mono_Time *mono_time;
    DHT     *dht;
    Networking_Core *net;
    Onion_Announce_Entry entries[ONION_ANNOUNCE_MAX_ENTRIES];
    /* This is CRYPTO_SYMMETRIC_KEY_SIZE long just so we can use new_symmetric_key() to fill it */
    uint8_t secret_bytes[CRYPTO_SYMMETRIC_KEY_SIZE];

    Shared_Keys shared_keys_recv;
};

uint8_t *onion_announce_entry_public_key(Onion_Announce *onion_a, uint32_t entry)
{
    return onion_a->entries[entry].public_key;
}

void onion_announce_entry_set_time(Onion_Announce *onion_a, uint32_t entry, uint64_t time)
{
    onion_a->entries[entry].time = time;
}

/* Create an onion announce request packet in packet of max_packet_length (recommended size ONION_ANNOUNCE_REQUEST_SIZE).
 *
 * dest_client_id is the public key of the node the packet will be sent to.
 * public_key and secret_key is the kepair which will be used to encrypt the request.
 * ping_id is the ping id that will be sent in the request.
 * client_id is the client id of the node we are searching for.
 * data_public_key is the public key we want others to encrypt their data packets with.
 * sendback_data is the data of ONION_ANNOUNCE_SENDBACK_DATA_LENGTH length that we expect to
 * receive back in the response.
 *
 * return -1 on failure.
 * return packet length on success.
 */
int create_announce_request(uint8_t *packet, uint16_t max_packet_length, const uint8_t *dest_client_id,
                            const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *ping_id, const uint8_t *client_id,
                            const uint8_t *data_public_key, uint64_t sendback_data)
{
    if (max_packet_length < ONION_ANNOUNCE_REQUEST_SIZE) {
        return -1;
    }

    uint8_t plain[ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE +
                                     ONION_ANNOUNCE_SENDBACK_DATA_LENGTH];
    memcpy(plain, ping_id, ONION_PING_ID_SIZE);
    memcpy(plain + ONION_PING_ID_SIZE, client_id, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE, &sendback_data,
           sizeof(sendback_data));

    packet[0] = NET_PACKET_ANNOUNCE_REQUEST;
    random_nonce(packet + 1);

    int len = encrypt_data(dest_client_id, secret_key, packet + 1, plain, sizeof(plain),
                           packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE);

    if ((uint32_t)len + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE != ONION_ANNOUNCE_REQUEST_SIZE) {
        return -1;
    }

    memcpy(packet + 1 + CRYPTO_NONCE_SIZE, public_key, CRYPTO_PUBLIC_KEY_SIZE);

    return ONION_ANNOUNCE_REQUEST_SIZE;
}

/* Create an onion data request packet in packet of max_packet_length (recommended size ONION_MAX_PACKET_SIZE).
 *
 * public_key is the real public key of the node which we want to send the data of length length to.
 * encrypt_public_key is the public key used to encrypt the data packet.
 *
 * nonce is the nonce to encrypt this packet with
 *
 * return -1 on failure.
 * return 0 on success.
 */
int create_data_request(uint8_t *packet, uint16_t max_packet_length, const uint8_t *public_key,
                        const uint8_t *encrypt_public_key, const uint8_t *nonce, const uint8_t *data, uint16_t length)
{
    if (DATA_REQUEST_MIN_SIZE + length > max_packet_length) {
        return -1;
    }

    if (DATA_REQUEST_MIN_SIZE + length > ONION_MAX_DATA_SIZE) {
        return -1;
    }

    packet[0] = NET_PACKET_ONION_DATA_REQUEST;
    memcpy(packet + 1, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);

    uint8_t random_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t random_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(random_public_key, random_secret_key);

    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, random_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    int len = encrypt_data(encrypt_public_key, random_secret_key, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, data, length,
                           packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE);

    if (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + len != DATA_REQUEST_MIN_SIZE +
            length) {
        return -1;
    }

    return DATA_REQUEST_MIN_SIZE + length;
}

/* Create and send an onion announce request packet.
 *
 * path is the path the request will take before it is sent to dest.
 *
 * public_key and secret_key is the kepair which will be used to encrypt the request.
 * ping_id is the ping id that will be sent in the request.
 * client_id is the client id of the node we are searching for.
 * data_public_key is the public key we want others to encrypt their data packets with.
 * sendback_data is the data of ONION_ANNOUNCE_SENDBACK_DATA_LENGTH length that we expect to
 * receive back in the response.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_announce_request(Networking_Core *net, const Onion_Path *path, Node_format dest, const uint8_t *public_key,
                          const uint8_t *secret_key, const uint8_t *ping_id, const uint8_t *client_id, const uint8_t *data_public_key,
                          uint64_t sendback_data)
{
    uint8_t request[ONION_ANNOUNCE_REQUEST_SIZE];
    int len = create_announce_request(request, sizeof(request), dest.public_key, public_key, secret_key, ping_id, client_id,
                                      data_public_key, sendback_data);

    if (len != sizeof(request)) {
        return -1;
    }

    uint8_t packet[ONION_MAX_PACKET_SIZE];
    len = create_onion_packet(packet, sizeof(packet), path, dest.ip_port, request, sizeof(request));

    if (len == -1) {
        return -1;
    }

    if (sendpacket(net, path->ip_port1, packet, len) != len) {
        return -1;
    }

    return 0;
}

/* Create and send an onion data request packet.
 *
 * path is the path the request will take before it is sent to dest.
 * (if dest knows the person with the public_key they should
 * send the packet to that person in the form of a response)
 *
 * public_key is the real public key of the node which we want to send the data of length length to.
 * encrypt_public_key is the public key used to encrypt the data packet.
 *
 * nonce is the nonce to encrypt this packet with
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_data_request(Networking_Core *net, const Onion_Path *path, IP_Port dest, const uint8_t *public_key,
                      const uint8_t *encrypt_public_key, const uint8_t *nonce, const uint8_t *data, uint16_t length)
{
    uint8_t request[ONION_MAX_DATA_SIZE];
    int len = create_data_request(request, sizeof(request), public_key, encrypt_public_key, nonce, data, length);

    if (len == -1) {
        return -1;
    }

    uint8_t packet[ONION_MAX_PACKET_SIZE];
    len = create_onion_packet(packet, sizeof(packet), path, dest, request, len);

    if (len == -1) {
        return -1;
    }

    if (sendpacket(net, path->ip_port1, packet, len) != len) {
        return -1;
    }

    return 0;
}

/* Generate a ping_id and put it in ping_id */
static void generate_ping_id(const Onion_Announce *onion_a, uint64_t time, const uint8_t *public_key,
                             IP_Port ret_ip_port, uint8_t *ping_id)
{
    time /= PING_ID_TIMEOUT;
    uint8_t data[CRYPTO_SYMMETRIC_KEY_SIZE + sizeof(time) + CRYPTO_PUBLIC_KEY_SIZE + sizeof(ret_ip_port)];
    memcpy(data, onion_a->secret_bytes, CRYPTO_SYMMETRIC_KEY_SIZE);
    memcpy(data + CRYPTO_SYMMETRIC_KEY_SIZE, &time, sizeof(time));
    memcpy(data + CRYPTO_SYMMETRIC_KEY_SIZE + sizeof(time), public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(data + CRYPTO_SYMMETRIC_KEY_SIZE + sizeof(time) + CRYPTO_PUBLIC_KEY_SIZE, &ret_ip_port, sizeof(ret_ip_port));
    crypto_sha256(ping_id, data, sizeof(data));
}

/* check if public key is in entries list
 *
 * return -1 if no
 * return position in list if yes
 */
static int in_entries(const Onion_Announce *onion_a, const uint8_t *public_key)
{
    unsigned int i;

    for (i = 0; i < ONION_ANNOUNCE_MAX_ENTRIES; ++i) {
        if (!mono_time_is_timeout(onion_a->mono_time, onion_a->entries[i].time, ONION_ANNOUNCE_TIMEOUT)
                && public_key_cmp(onion_a->entries[i].public_key, public_key) == 0) {
            return i;
        }
    }

    return -1;
}

typedef struct Cmp_data {
    const Mono_Time *mono_time;
    const uint8_t *base_public_key;
    Onion_Announce_Entry entry;
} Cmp_data;

static int cmp_entry(const void *a, const void *b)
{
    Cmp_data cmp1;
    Cmp_data cmp2;
    memcpy(&cmp1, a, sizeof(Cmp_data));
    memcpy(&cmp2, b, sizeof(Cmp_data));
    Onion_Announce_Entry entry1 = cmp1.entry;
    Onion_Announce_Entry entry2 = cmp2.entry;
    const uint8_t *cmp_public_key = cmp1.base_public_key;

    int t1 = mono_time_is_timeout(cmp1.mono_time, entry1.time, ONION_ANNOUNCE_TIMEOUT);
    int t2 = mono_time_is_timeout(cmp1.mono_time, entry2.time, ONION_ANNOUNCE_TIMEOUT);

    if (t1 && t2) {
        return 0;
    }

    if (t1) {
        return -1;
    }

    if (t2) {
        return 1;
    }

    int close = id_closest(cmp_public_key, entry1.public_key, entry2.public_key);

    if (close == 1) {
        return 1;
    }

    if (close == 2) {
        return -1;
    }

    return 0;
}

static void sort_onion_announce_list(Onion_Announce_Entry *list, unsigned int length, const Mono_Time *mono_time,
                                     const uint8_t *comp_public_key)
{
    // Pass comp_public_key to qsort with each Client_data entry, so the
    // comparison function can use it as the base of comparison.
    VLA(Cmp_data, cmp_list, length);

    for (uint32_t i = 0; i < length; ++i) {
        cmp_list[i].mono_time = mono_time;
        cmp_list[i].base_public_key = comp_public_key;
        cmp_list[i].entry = list[i];
    }

    qsort(cmp_list, length, sizeof(Cmp_data), cmp_entry);

    for (uint32_t i = 0; i < length; ++i) {
        list[i] = cmp_list[i].entry;
    }
}

/* add entry to entries list
 *
 * return -1 if failure
 * return position if added
 */
static int add_to_entries(Onion_Announce *onion_a, IP_Port ret_ip_port, const uint8_t *public_key,
                          const uint8_t *data_public_key, const uint8_t *ret)
{

    int pos = in_entries(onion_a, public_key);

    if (pos == -1) {
        for (unsigned i = 0; i < ONION_ANNOUNCE_MAX_ENTRIES; ++i) {
            if (mono_time_is_timeout(onion_a->mono_time, onion_a->entries[i].time, ONION_ANNOUNCE_TIMEOUT)) {
                pos = i;
            }
        }
    }

    if (pos == -1) {
        if (id_closest(dht_get_self_public_key(onion_a->dht), public_key, onion_a->entries[0].public_key) == 1) {
            pos = 0;
        }
    }

    if (pos == -1) {
        return -1;
    }

    memcpy(onion_a->entries[pos].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    onion_a->entries[pos].ret_ip_port = ret_ip_port;
    memcpy(onion_a->entries[pos].ret, ret, ONION_RETURN_3);
    memcpy(onion_a->entries[pos].data_public_key, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    onion_a->entries[pos].time = mono_time_get(onion_a->mono_time);

    sort_onion_announce_list(onion_a->entries, ONION_ANNOUNCE_MAX_ENTRIES, onion_a->mono_time,
                             dht_get_self_public_key(onion_a->dht));
    return in_entries(onion_a, public_key);
}

static int handle_announce_request(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion_Announce *onion_a = (Onion_Announce *)object;

    if (length != ANNOUNCE_REQUEST_SIZE_RECV) {
        return 1;
    }

    const uint8_t *packet_public_key = packet + 1 + CRYPTO_NONCE_SIZE;
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    get_shared_key(onion_a->mono_time, &onion_a->shared_keys_recv, shared_key, dht_get_self_secret_key(onion_a->dht),
                   packet_public_key);

    uint8_t plain[ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE +
                                     ONION_ANNOUNCE_SENDBACK_DATA_LENGTH];
    int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
                                     ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH +
                                     CRYPTO_MAC_SIZE, plain);

    if ((uint32_t)len != sizeof(plain)) {
        return 1;
    }

    uint8_t ping_id1[ONION_PING_ID_SIZE];
    generate_ping_id(onion_a, mono_time_get(onion_a->mono_time), packet_public_key, source, ping_id1);

    uint8_t ping_id2[ONION_PING_ID_SIZE];
    generate_ping_id(onion_a, mono_time_get(onion_a->mono_time) + PING_ID_TIMEOUT, packet_public_key, source, ping_id2);

    int index;

    uint8_t *data_public_key = plain + ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE;

    if (crypto_memcmp(ping_id1, plain, ONION_PING_ID_SIZE) == 0
            || crypto_memcmp(ping_id2, plain, ONION_PING_ID_SIZE) == 0) {
        index = add_to_entries(onion_a, source, packet_public_key, data_public_key,
                               packet + (ANNOUNCE_REQUEST_SIZE_RECV - ONION_RETURN_3));
    } else {
        index = in_entries(onion_a, plain + ONION_PING_ID_SIZE);
    }

    /*Respond with a announce response packet*/
    Node_format nodes_list[MAX_SENT_NODES];
    unsigned int num_nodes =
        get_close_nodes(onion_a->dht, plain + ONION_PING_ID_SIZE, nodes_list, net_family_unspec, ip_is_lan(source.ip), 1);
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    uint8_t pl[1 + ONION_PING_ID_SIZE + sizeof(nodes_list)];

    if (index == -1) {
        pl[0] = 0;
        memcpy(pl + 1, ping_id2, ONION_PING_ID_SIZE);
    } else {
        if (public_key_cmp(onion_a->entries[index].public_key, packet_public_key) == 0) {
            if (public_key_cmp(onion_a->entries[index].data_public_key, data_public_key) != 0) {
                pl[0] = 0;
                memcpy(pl + 1, ping_id2, ONION_PING_ID_SIZE);
            } else {
                pl[0] = 2;
                memcpy(pl + 1, ping_id2, ONION_PING_ID_SIZE);
            }
        } else {
            pl[0] = 1;
            memcpy(pl + 1, onion_a->entries[index].data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
        }
    }

    int nodes_length = 0;

    if (num_nodes != 0) {
        nodes_length = pack_nodes(pl + 1 + ONION_PING_ID_SIZE, sizeof(nodes_list), nodes_list, num_nodes);

        if (nodes_length <= 0) {
            return 1;
        }
    }

    uint8_t data[ONION_ANNOUNCE_RESPONSE_MAX_SIZE];
    len = encrypt_data_symmetric(shared_key, nonce, pl, 1 + ONION_PING_ID_SIZE + nodes_length,
                                 data + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE);

    if (len != 1 + ONION_PING_ID_SIZE + nodes_length + CRYPTO_MAC_SIZE) {
        return 1;
    }

    data[0] = NET_PACKET_ANNOUNCE_RESPONSE;
    memcpy(data + 1, plain + ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
           ONION_ANNOUNCE_SENDBACK_DATA_LENGTH);
    memcpy(data + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH, nonce, CRYPTO_NONCE_SIZE);

    if (send_onion_response(onion_a->net, source, data,
                            1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE + len,
                            packet + (ANNOUNCE_REQUEST_SIZE_RECV - ONION_RETURN_3)) == -1) {
        return 1;
    }

    return 0;
}

static int handle_data_request(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion_Announce *onion_a = (Onion_Announce *)object;

    if (length <= DATA_REQUEST_MIN_SIZE_RECV) {
        return 1;
    }

    if (length > ONION_MAX_PACKET_SIZE) {
        return 1;
    }

    int index = in_entries(onion_a, packet + 1);

    if (index == -1) {
        return 1;
    }

    VLA(uint8_t, data, length - (CRYPTO_PUBLIC_KEY_SIZE + ONION_RETURN_3));
    data[0] = NET_PACKET_ONION_DATA_RESPONSE;
    memcpy(data + 1, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, length - (1 + CRYPTO_PUBLIC_KEY_SIZE + ONION_RETURN_3));

    if (send_onion_response(onion_a->net, onion_a->entries[index].ret_ip_port, data, SIZEOF_VLA(data),
                            onion_a->entries[index].ret) == -1) {
        return 1;
    }

    return 0;
}

Onion_Announce *new_onion_announce(Mono_Time *mono_time, DHT *dht)
{
    if (dht == nullptr) {
        return nullptr;
    }

    Onion_Announce *onion_a = (Onion_Announce *)calloc(1, sizeof(Onion_Announce));

    if (onion_a == nullptr) {
        return nullptr;
    }

    onion_a->mono_time = mono_time;
    onion_a->dht = dht;
    onion_a->net = dht_get_net(dht);
    new_symmetric_key(onion_a->secret_bytes);

    networking_registerhandler(onion_a->net, NET_PACKET_ANNOUNCE_REQUEST, &handle_announce_request, onion_a);
    networking_registerhandler(onion_a->net, NET_PACKET_ONION_DATA_REQUEST, &handle_data_request, onion_a);

    return onion_a;
}

void kill_onion_announce(Onion_Announce *onion_a)
{
    if (onion_a == nullptr) {
        return;
    }

    networking_registerhandler(onion_a->net, NET_PACKET_ANNOUNCE_REQUEST, nullptr, nullptr);
    networking_registerhandler(onion_a->net, NET_PACKET_ONION_DATA_REQUEST, nullptr, nullptr);
    free(onion_a);
}
