/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Implementation of the announce part of docs/Prevent_Tracking.txt
 */
#include "onion_announce.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "DHT.h"
#include "LAN_discovery.h"
#include "ccompat.h"
#include "mono_time.h"
#include "util.h"

#define PING_ID_TIMEOUT ONION_ANNOUNCE_TIMEOUT

#define ANNOUNCE_REQUEST_MIN_SIZE_RECV (ONION_ANNOUNCE_REQUEST_MIN_SIZE + ONION_RETURN_3)
#define ANNOUNCE_REQUEST_MAX_SIZE_RECV (ONION_ANNOUNCE_REQUEST_MAX_SIZE + ONION_RETURN_3)

/* TODO(Jfreegman): DEPRECATE */
#define ANNOUNCE_REQUEST_SIZE_RECV (ONION_ANNOUNCE_REQUEST_SIZE + ONION_RETURN_3)

#define DATA_REQUEST_MIN_SIZE ONION_DATA_REQUEST_MIN_SIZE
#define DATA_REQUEST_MIN_SIZE_RECV (DATA_REQUEST_MIN_SIZE + ONION_RETURN_3)

#define ONION_MINIMAL_SIZE (ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE * 2 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH)

static_assert(ONION_PING_ID_SIZE == CRYPTO_PUBLIC_KEY_SIZE,
              "announce response packets assume that ONION_PING_ID_SIZE is equal to CRYPTO_PUBLIC_KEY_SIZE");

typedef struct Onion_Announce_Entry {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    IP_Port ret_ip_port;
    uint8_t ret[ONION_RETURN_3];
    uint8_t data_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint64_t announce_time;
} Onion_Announce_Entry;

struct Onion_Announce {
    const Logger *log;
    const Mono_Time *mono_time;
    const Random *rng;
    DHT     *dht;
    Networking_Core *net;
    Onion_Announce_Entry entries[ONION_ANNOUNCE_MAX_ENTRIES];
    uint8_t hmac_key[CRYPTO_HMAC_KEY_SIZE];

    Shared_Keys shared_keys_recv;

    uint16_t extra_data_max_size;
    pack_extra_data_cb *extra_data_callback;
    void *extra_data_object;
};

void onion_announce_extra_data_callback(Onion_Announce *onion_a, uint16_t extra_data_max_size,
                                        pack_extra_data_cb *extra_data_callback, void *extra_data_object)
{
    onion_a->extra_data_max_size = extra_data_max_size;
    onion_a->extra_data_callback = extra_data_callback;
    onion_a->extra_data_object = extra_data_object;
}

uint8_t *onion_announce_entry_public_key(Onion_Announce *onion_a, uint32_t entry)
{
    return onion_a->entries[entry].public_key;
}

void onion_announce_entry_set_time(Onion_Announce *onion_a, uint32_t entry, uint64_t announce_time)
{
    onion_a->entries[entry].announce_time = announce_time;
}

/** @brief Create an onion announce request packet in packet of max_packet_length.
 *
 * Recommended value for max_packet_length is ONION_ANNOUNCE_REQUEST_MIN_SIZE.
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
int create_announce_request(const Random *rng, uint8_t *packet, uint16_t max_packet_length, const uint8_t *dest_client_id,
                            const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *ping_id, const uint8_t *client_id,
                            const uint8_t *data_public_key, uint64_t sendback_data)
{
    if (max_packet_length < ONION_ANNOUNCE_REQUEST_MIN_SIZE) {
        return -1;
    }

    uint8_t plain[ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE +
                                     ONION_ANNOUNCE_SENDBACK_DATA_LENGTH];
    memcpy(plain, ping_id, ONION_PING_ID_SIZE);
    memcpy(plain + ONION_PING_ID_SIZE, client_id, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE, &sendback_data,
           sizeof(sendback_data));

    packet[0] = NET_PACKET_ANNOUNCE_REQUEST_OLD;
    random_nonce(rng, packet + 1);

    const int len = encrypt_data(dest_client_id, secret_key, packet + 1, plain, sizeof(plain),
                                 packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE);

    if ((uint32_t)len + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE != ONION_ANNOUNCE_REQUEST_MIN_SIZE) {
        return -1;
    }

    memcpy(packet + 1 + CRYPTO_NONCE_SIZE, public_key, CRYPTO_PUBLIC_KEY_SIZE);

    return ONION_ANNOUNCE_REQUEST_MIN_SIZE;
}

/** @brief Create an onion data request packet in packet of max_packet_length.
 *
 * Recommended value for max_packet_length is ONION_ANNOUNCE_REQUEST_SIZE.
 *
 * public_key is the real public key of the node which we want to send the data of length length to.
 * encrypt_public_key is the public key used to encrypt the data packet.
 *
 * nonce is the nonce to encrypt this packet with
 *
 * return -1 on failure.
 * return 0 on success.
 */
int create_data_request(const Random *rng, uint8_t *packet, uint16_t max_packet_length, const uint8_t *public_key,
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
    crypto_new_keypair(rng, random_public_key, random_secret_key);

    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, random_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    const int len = encrypt_data(encrypt_public_key, random_secret_key, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, data, length,
                                 packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE);

    if (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + len != DATA_REQUEST_MIN_SIZE +
            length) {
        return -1;
    }

    return DATA_REQUEST_MIN_SIZE + length;
}

/** @brief Create and send an onion announce request packet.
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
int send_announce_request(const Networking_Core *net, const Random *rng,
                          const Onion_Path *path, const Node_format *dest,
                          const uint8_t *public_key, const uint8_t *secret_key,
                          const uint8_t *ping_id, const uint8_t *client_id,
                          const uint8_t *data_public_key, uint64_t sendback_data)
{
    uint8_t request[ONION_ANNOUNCE_REQUEST_MIN_SIZE];
    int len = create_announce_request(rng, request, sizeof(request), dest->public_key, public_key, secret_key, ping_id,
                                      client_id, data_public_key, sendback_data);

    if (len != sizeof(request)) {
        return -1;
    }

    uint8_t packet[ONION_MAX_PACKET_SIZE];
    len = create_onion_packet(rng, packet, sizeof(packet), path, &dest->ip_port, request, sizeof(request));

    if (len == -1) {
        return -1;
    }

    if (sendpacket(net, &path->ip_port1, packet, len) != len) {
        return -1;
    }

    return 0;
}

/** @brief Create and send an onion data request packet.
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
 * The maximum length of data is MAX_DATA_REQUEST_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_data_request(const Networking_Core *net, const Random *rng, const Onion_Path *path, const IP_Port *dest,
                      const uint8_t *public_key, const uint8_t *encrypt_public_key, const uint8_t *nonce,
                      const uint8_t *data, uint16_t length)
{
    uint8_t request[ONION_MAX_DATA_SIZE];
    int len = create_data_request(rng, request, sizeof(request), public_key, encrypt_public_key, nonce, data, length);

    if (len == -1) {
        return -1;
    }

    uint8_t packet[ONION_MAX_PACKET_SIZE];
    len = create_onion_packet(rng, packet, sizeof(packet), path, dest, request, len);

    if (len == -1) {
        return -1;
    }

    if (sendpacket(net, &path->ip_port1, packet, len) != len) {
        return -1;
    }

    return 0;
}

/** @brief check if public key is in entries list
 *
 * return -1 if no
 * return position in list if yes
 */
non_null()
static int in_entries(const Onion_Announce *onion_a, const uint8_t *public_key)
{
    for (unsigned int i = 0; i < ONION_ANNOUNCE_MAX_ENTRIES; ++i) {
        if (!mono_time_is_timeout(onion_a->mono_time, onion_a->entries[i].announce_time, ONION_ANNOUNCE_TIMEOUT)
                && pk_equal(onion_a->entries[i].public_key, public_key)) {
            return i;
        }
    }

    return -1;
}

typedef struct Cmp_Data {
    const Mono_Time *mono_time;
    const uint8_t *base_public_key;
    Onion_Announce_Entry entry;
} Cmp_Data;

non_null()
static int cmp_entry(const void *a, const void *b)
{
    const Cmp_Data *cmp1 = (const Cmp_Data *)a;
    const Cmp_Data *cmp2 = (const Cmp_Data *)b;
    const Onion_Announce_Entry entry1 = cmp1->entry;
    const Onion_Announce_Entry entry2 = cmp2->entry;
    const uint8_t *cmp_public_key = cmp1->base_public_key;

    const bool t1 = mono_time_is_timeout(cmp1->mono_time, entry1.announce_time, ONION_ANNOUNCE_TIMEOUT);
    const bool t2 = mono_time_is_timeout(cmp1->mono_time, entry2.announce_time, ONION_ANNOUNCE_TIMEOUT);

    if (t1 && t2) {
        return 0;
    }

    if (t1) {
        return -1;
    }

    if (t2) {
        return 1;
    }

    const int closest = id_closest(cmp_public_key, entry1.public_key, entry2.public_key);

    if (closest == 1) {
        return 1;
    }

    if (closest == 2) {
        return -1;
    }

    return 0;
}

non_null()
static void sort_onion_announce_list(Onion_Announce_Entry *list, unsigned int length, const Mono_Time *mono_time,
                                     const uint8_t *comp_public_key)
{
    // Pass comp_public_key to qsort with each Client_data entry, so the
    // comparison function can use it as the base of comparison.
    Cmp_Data *cmp_list = (Cmp_Data *)calloc(length, sizeof(Cmp_Data));

    if (cmp_list == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < length; ++i) {
        cmp_list[i].mono_time = mono_time;
        cmp_list[i].base_public_key = comp_public_key;
        cmp_list[i].entry = list[i];
    }

    qsort(cmp_list, length, sizeof(Cmp_Data), cmp_entry);

    for (uint32_t i = 0; i < length; ++i) {
        list[i] = cmp_list[i].entry;
    }

    free(cmp_list);
}

/** @brief add entry to entries list
 *
 * return -1 if failure
 * return position if added
 */
non_null()
static int add_to_entries(Onion_Announce *onion_a, const IP_Port *ret_ip_port, const uint8_t *public_key,
                          const uint8_t *data_public_key, const uint8_t *ret)
{

    int pos = in_entries(onion_a, public_key);

    if (pos == -1) {
        for (unsigned i = 0; i < ONION_ANNOUNCE_MAX_ENTRIES; ++i) {
            if (mono_time_is_timeout(onion_a->mono_time, onion_a->entries[i].announce_time, ONION_ANNOUNCE_TIMEOUT)) {
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
    onion_a->entries[pos].ret_ip_port = *ret_ip_port;
    memcpy(onion_a->entries[pos].ret, ret, ONION_RETURN_3);
    memcpy(onion_a->entries[pos].data_public_key, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    onion_a->entries[pos].announce_time = mono_time_get(onion_a->mono_time);

    sort_onion_announce_list(onion_a->entries, ONION_ANNOUNCE_MAX_ENTRIES, onion_a->mono_time,
                             dht_get_self_public_key(onion_a->dht));
    return in_entries(onion_a, public_key);
}

non_null()
static void make_announce_payload_helper(const Onion_Announce *onion_a, const uint8_t *ping_id,
        uint8_t *response, int index, const uint8_t *packet_public_key, const uint8_t *data_public_key)
{
    if (index < 0) {
        response[0] = 0;
        memcpy(response + 1, ping_id, ONION_PING_ID_SIZE);
        return;
    }

    if (pk_equal(onion_a->entries[index].public_key, packet_public_key)) {
        if (!pk_equal(onion_a->entries[index].data_public_key, data_public_key)) {
            response[0] = 0;
            memcpy(response + 1, ping_id, ONION_PING_ID_SIZE);
        } else {
            response[0] = 2;
            memcpy(response + 1, ping_id, ONION_PING_ID_SIZE);
        }
    } else {
        response[0] = 1;
        memcpy(response + 1, onion_a->entries[index].data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    }
}

/** @brief Handle an onion announce request, possibly with extra data for group chats.
 *
 * @param onion_a The announce object.
 * @param source Requester IP/Port.
 * @param packet Encrypted incoming packet.
 * @param length Length of incoming packet.
 * @param response_packet_id Packet ID to use for the onion announce response.
 * @param plain_size Expected size of the decrypted packet. This function returns an error if the
 *   actual decrypted size is not exactly equal to this number.
 * @param want_node_count If true, the packed nodes in the response are preceded by the number of
 *   nodes sent in the packet. This is necessary if you want to send extra data after the nodes.
 * @param max_extra_size Amount of memory to allocate in the outgoing packet to be filled by the
 *   extra data callback.
 * @param pack_extra_data_callback Callback that may write extra data into the packet.
 *
 * @retval 1 on failure.
 * @retval 0 on success.
 */
non_null(1, 2, 3) nullable(9)
static int handle_announce_request_common(
    Onion_Announce *onion_a, const IP_Port *source, const uint8_t *packet, uint16_t length,
    uint8_t response_packet_id, uint16_t plain_size, bool want_node_count, uint16_t max_extra_size,
    pack_extra_data_cb *pack_extra_data_callback)
{
    const uint8_t *packet_public_key = packet + 1 + CRYPTO_NONCE_SIZE;
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    get_shared_key(onion_a->mono_time, &onion_a->shared_keys_recv, shared_key, dht_get_self_secret_key(onion_a->dht),
                   packet_public_key);

    uint8_t *plain = (uint8_t *)malloc(plain_size);

    if (plain == nullptr) {
        return 1;
    }

    const int decrypted_len = decrypt_data_symmetric(shared_key, packet + 1,
                              packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE, plain_size + CRYPTO_MAC_SIZE, plain);

    if ((uint32_t)decrypted_len != plain_size) {
        free(plain);
        return 1;
    }

    const uint16_t ping_id_data_len = CRYPTO_PUBLIC_KEY_SIZE + sizeof(*source);
    uint8_t ping_id_data[CRYPTO_PUBLIC_KEY_SIZE + sizeof(*source)];
    memcpy(ping_id_data, packet_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(ping_id_data + CRYPTO_PUBLIC_KEY_SIZE, source, sizeof(*source));

    const uint8_t *data_public_key = plain + ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE;

    int index;

    if (check_timed_auth(onion_a->mono_time, PING_ID_TIMEOUT, onion_a->hmac_key,
                         ping_id_data, ping_id_data_len, plain)) {
        index = add_to_entries(onion_a, source, packet_public_key, data_public_key,
                               packet + (length - ONION_RETURN_3));
    } else {
        index = in_entries(onion_a, plain + ONION_PING_ID_SIZE);
    }

    /* Respond with a announce response packet */
    Node_format nodes_list[MAX_SENT_NODES];
    const unsigned int num_nodes =
        get_close_nodes(onion_a->dht, plain + ONION_PING_ID_SIZE, nodes_list, net_family_unspec(), ip_is_lan(&source->ip), false);

    assert(num_nodes <= UINT8_MAX);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(onion_a->rng, nonce);

    const uint16_t nodes_offset = 1 + ONION_PING_ID_SIZE + (want_node_count ? 1 : 0);
    const uint16_t response_size = nodes_offset
                                   + MAX_SENT_NODES * PACKED_NODE_SIZE_IP6
                                   + max_extra_size;
    uint8_t *response = (uint8_t *)malloc(response_size);

    if (response == nullptr) {
        free(plain);
        return 1;
    }

    uint8_t ping_id[TIMED_AUTH_SIZE];
    generate_timed_auth(onion_a->mono_time, PING_ID_TIMEOUT, onion_a->hmac_key,
                        ping_id_data, ping_id_data_len, ping_id);

    make_announce_payload_helper(onion_a, ping_id, response, index, packet_public_key, data_public_key);

    int nodes_length = 0;

    if (num_nodes != 0) {
        nodes_length = pack_nodes(onion_a->log, response + nodes_offset, sizeof(nodes_list), nodes_list,
                                  (uint16_t)num_nodes);

        if (nodes_length <= 0) {
            LOGGER_WARNING(onion_a->log, "Failed to pack nodes");
            free(response);
            free(plain);
            return 1;
        }
    }

    uint16_t offset = nodes_offset + nodes_length;

    if (want_node_count) {
        response[1 + ONION_PING_ID_SIZE] = (uint8_t)num_nodes;
    }

    const int extra_size = pack_extra_data_callback == nullptr ? 0
                           : pack_extra_data_callback(onion_a->extra_data_object,
                                   onion_a->log, onion_a->mono_time, num_nodes,
                                   plain + ONION_MINIMAL_SIZE, length - ANNOUNCE_REQUEST_MIN_SIZE_RECV,
                                   response, response_size, offset);

    if (extra_size == -1) {
        free(response);
        free(plain);
        return 1;
    }

    offset += extra_size;

    uint8_t data[ONION_ANNOUNCE_RESPONSE_MAX_SIZE];
    const int len = encrypt_data_symmetric(shared_key, nonce, response, offset,
                                           data + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE);

    if (len != offset + CRYPTO_MAC_SIZE) {
        LOGGER_ERROR(onion_a->log, "Failed to encrypt announce response");
        free(response);
        free(plain);
        return 1;
    }

    data[0] = response_packet_id;
    memcpy(data + 1, plain + ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
           ONION_ANNOUNCE_SENDBACK_DATA_LENGTH);
    memcpy(data + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH, nonce, CRYPTO_NONCE_SIZE);

    if (send_onion_response(onion_a->net, source, data,
                            1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE + len,
                            packet + (length - ONION_RETURN_3)) == -1) {
        free(response);
        free(plain);
        return 1;
    }

    free(response);
    free(plain);
    return 0;
}

non_null()
static int handle_gca_announce_request(Onion_Announce *onion_a, const IP_Port *source, const uint8_t *packet,
                                       uint16_t length)
{
    if (length > ANNOUNCE_REQUEST_MAX_SIZE_RECV || length <= ANNOUNCE_REQUEST_MIN_SIZE_RECV) {
        return 1;
    }

    if (onion_a->extra_data_callback == nullptr) {
        return 1;
    }

    return handle_announce_request_common(onion_a, source, packet, length, NET_PACKET_ANNOUNCE_RESPONSE,
                                          ONION_MINIMAL_SIZE + length - ANNOUNCE_REQUEST_MIN_SIZE_RECV,
                                          true, onion_a->extra_data_max_size, onion_a->extra_data_callback);
}

non_null(1, 2, 3) nullable(5)
static int handle_announce_request(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                                   void *userdata)
{
    Onion_Announce *onion_a = (Onion_Announce *)object;

    if (length != ANNOUNCE_REQUEST_MIN_SIZE_RECV) {
        return handle_gca_announce_request(onion_a, source, packet, length);
    }

    return handle_announce_request_common(onion_a, source, packet, length, NET_PACKET_ANNOUNCE_RESPONSE,
                                          ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE * 2 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                                          true, 0, nullptr);
}

/* TODO(Jfreegman): DEPRECATE */
non_null(1, 2, 3) nullable(5)
static int handle_announce_request_old(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                                       void *userdata)
{
    Onion_Announce *onion_a = (Onion_Announce *)object;

    if (length != ANNOUNCE_REQUEST_SIZE_RECV) {
        return 1;
    }

    return handle_announce_request_common(onion_a, source, packet, length, NET_PACKET_ANNOUNCE_RESPONSE_OLD,
                                          ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE * 2 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                                          false, 0, nullptr);
}

non_null()
static int handle_data_request(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                               void *userdata)
{
    const Onion_Announce *onion_a = (const Onion_Announce *)object;

    if (length <= DATA_REQUEST_MIN_SIZE_RECV) {
        return 1;
    }

    if (length > ONION_MAX_PACKET_SIZE) {
        return 1;
    }

    const int index = in_entries(onion_a, packet + 1);

    if (index == -1) {
        return 1;
    }

    VLA(uint8_t, data, length - (CRYPTO_PUBLIC_KEY_SIZE + ONION_RETURN_3));
    data[0] = NET_PACKET_ONION_DATA_RESPONSE;
    memcpy(data + 1, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, length - (1 + CRYPTO_PUBLIC_KEY_SIZE + ONION_RETURN_3));

    if (send_onion_response(onion_a->net, &onion_a->entries[index].ret_ip_port, data, SIZEOF_VLA(data),
                            onion_a->entries[index].ret) == -1) {
        return 1;
    }

    return 0;
}

Onion_Announce *new_onion_announce(const Logger *log, const Random *rng, const Mono_Time *mono_time, DHT *dht)
{
    if (dht == nullptr) {
        return nullptr;
    }

    Onion_Announce *onion_a = (Onion_Announce *)calloc(1, sizeof(Onion_Announce));

    if (onion_a == nullptr) {
        return nullptr;
    }

    onion_a->log = log;
    onion_a->rng = rng;
    onion_a->mono_time = mono_time;
    onion_a->dht = dht;
    onion_a->net = dht_get_net(dht);
    onion_a->extra_data_max_size = 0;
    onion_a->extra_data_callback = nullptr;
    onion_a->extra_data_object = nullptr;
    new_hmac_key(rng, onion_a->hmac_key);

    networking_registerhandler(onion_a->net, NET_PACKET_ANNOUNCE_REQUEST, &handle_announce_request, onion_a);
    networking_registerhandler(onion_a->net, NET_PACKET_ANNOUNCE_REQUEST_OLD, &handle_announce_request_old, onion_a);
    networking_registerhandler(onion_a->net, NET_PACKET_ONION_DATA_REQUEST, &handle_data_request, onion_a);

    // TODO(Jfreegman): Remove this when we merge the rest of new groupchats
    onion_announce_extra_data_callback(onion_a, 0, nullptr, nullptr);

    return onion_a;
}

void kill_onion_announce(Onion_Announce *onion_a)
{
    if (onion_a == nullptr) {
        return;
    }

    networking_registerhandler(onion_a->net, NET_PACKET_ANNOUNCE_REQUEST, nullptr, nullptr);
    networking_registerhandler(onion_a->net, NET_PACKET_ANNOUNCE_REQUEST_OLD, nullptr, nullptr);
    networking_registerhandler(onion_a->net, NET_PACKET_ONION_DATA_REQUEST, nullptr, nullptr);

    crypto_memzero(onion_a->hmac_key, CRYPTO_HMAC_KEY_SIZE);

    free(onion_a);
}
