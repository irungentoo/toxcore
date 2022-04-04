/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

/**
 * "Server side" of the DHT announcements protocol.
 */

#include "announce.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "LAN_discovery.h"
#include "ccompat.h"
#include "timed_auth.h"
#include "util.h"

uint8_t announce_response_of_request_type(uint8_t request_type)
{
    switch (request_type) {
        case NET_PACKET_DATA_SEARCH_REQUEST:
            return NET_PACKET_DATA_SEARCH_RESPONSE;

        case NET_PACKET_DATA_RETRIEVE_REQUEST:
            return NET_PACKET_DATA_RETRIEVE_RESPONSE;

        case NET_PACKET_STORE_ANNOUNCE_REQUEST:
            return NET_PACKET_STORE_ANNOUNCE_RESPONSE;

        default: {
            assert(false);
            return NET_PACKET_MAX;
        }
    }
}

typedef struct Announce_Entry {
    uint64_t store_until;
    uint8_t data_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t *data;
    uint32_t length;
} Announce_Entry;

struct Announcements {
    const Logger *log;
    const Random *rng;
    Forwarding *forwarding;
    const Mono_Time *mono_time;
    DHT *dht;
    Networking_Core *net;
    const uint8_t *public_key;
    const uint8_t *secret_key;

    Shared_Keys shared_keys;
    uint8_t hmac_key[CRYPTO_HMAC_KEY_SIZE];

    int32_t synch_offset;

    uint64_t start_time;

    Announce_Entry entries[ANNOUNCE_BUCKETS * ANNOUNCE_BUCKET_SIZE];
};

void announce_set_synch_offset(Announcements *announce, int32_t synch_offset)
{
    announce->synch_offset = synch_offset;
}

/**
 * An entry is considered to be "deleted" for the purposes of the protocol
 * once it has timed out.
 */
non_null()
static bool entry_is_empty(const Announcements *announce, const Announce_Entry *entry)
{
    return mono_time_get(announce->mono_time) >= entry->store_until;
}

non_null()
static void delete_entry(Announce_Entry *entry)
{
    entry->store_until = 0;
}

/** Return bits (at most 8) from pk starting at index as uint8_t */
non_null()
static uint8_t truncate_pk_at_index(const uint8_t *pk, uint16_t index, uint16_t bits)
{
    assert(bits < 8);
    const uint8_t i = index / 8;
    const uint8_t j = index % 8;
    return ((uint8_t)((i < CRYPTO_PUBLIC_KEY_SIZE ? pk[i] : 0) << j) >> (8 - bits)) |
           ((i + 1 < CRYPTO_PUBLIC_KEY_SIZE ? pk[i + 1] : 0) >> (16 - bits - j));
}

uint16_t announce_get_bucketnum(const uint8_t *base, const uint8_t *pk)
{
    const uint16_t index = bit_by_bit_cmp(base, pk);

    return truncate_pk_at_index(base, index + 1, ANNOUNCE_BUCKET_PREFIX_LENGTH) ^
           truncate_pk_at_index(pk, index + 1, ANNOUNCE_BUCKET_PREFIX_LENGTH);
}

non_null()
static Announce_Entry *bucket_of_key(Announcements *announce, const uint8_t *pk)
{
    return &announce->entries[announce_get_bucketnum(announce->public_key, pk) * ANNOUNCE_BUCKET_SIZE];
}

non_null()
static Announce_Entry *get_stored(Announcements *announce, const uint8_t *data_public_key)
{
    Announce_Entry *const bucket = bucket_of_key(announce, data_public_key);

    for (uint32_t i = 0; i < ANNOUNCE_BUCKET_SIZE; ++i) {
        if (pk_equal(bucket[i].data_public_key, data_public_key)) {
            if (entry_is_empty(announce, &bucket[i])) {
                break;
            }

            return &bucket[i];
        }
    }

    return nullptr;
}

non_null()
static const Announce_Entry *bucket_of_key_const(const Announcements *announce, const uint8_t *pk)
{
    return &announce->entries[announce_get_bucketnum(announce->public_key, pk) * ANNOUNCE_BUCKET_SIZE];
}

non_null()
static const Announce_Entry *get_stored_const(const Announcements *announce, const uint8_t *data_public_key)
{
    const Announce_Entry *const bucket = bucket_of_key_const(announce, data_public_key);

    for (uint32_t i = 0; i < ANNOUNCE_BUCKET_SIZE; ++i) {
        if (pk_equal(bucket[i].data_public_key, data_public_key)) {
            if (entry_is_empty(announce, &bucket[i])) {
                break;
            }

            return &bucket[i];
        }
    }

    return nullptr;
}


bool announce_on_stored(const Announcements *announce, const uint8_t *data_public_key,
                        announce_on_retrieve_cb *on_retrieve_callback, void *object)
{
    const Announce_Entry *const entry = get_stored_const(announce, data_public_key);

    if (entry == nullptr || entry->data == nullptr) {
        return false;
    }

    if (on_retrieve_callback != nullptr) {
        on_retrieve_callback(object, entry->data, entry->length);
    }

    return true;
}

/**
 * Return existing entry for this key if it exists, else an empty
 * slot in the key's bucket if one exists, else an entry in the key's bucket
 * of greatest 2-adic distance greater than that of the key bucket if one
 * exists, else nullptr.
 */
non_null()
static Announce_Entry *find_entry_slot(Announcements *announce, const uint8_t *data_public_key)
{
    Announce_Entry *const bucket = bucket_of_key(announce, data_public_key);

    Announce_Entry *slot = nullptr;
    uint16_t min_index = bit_by_bit_cmp(announce->public_key, data_public_key);

    for (uint32_t i = 0; i < ANNOUNCE_BUCKET_SIZE; ++i) {
        if (pk_equal(bucket[i].data_public_key, data_public_key)) {
            return &bucket[i];
        }

        if (entry_is_empty(announce, &bucket[i])) {
            slot = &bucket[i];
            min_index = 0;
            continue;
        }

        const uint16_t index = bit_by_bit_cmp(announce->public_key, bucket[i].data_public_key);

        if (index < min_index) {
            slot = &bucket[i];
            min_index = index;
        }
    }

    return slot;
}

non_null()
static bool would_accept_store_request(Announcements *announce, const uint8_t *data_public_key)
{
    return find_entry_slot(announce, data_public_key) != nullptr;
}

bool announce_store_data(Announcements *announce, const uint8_t *data_public_key,
                         const uint8_t *data, uint32_t length, uint32_t timeout)
{
    if (length > MAX_ANNOUNCEMENT_SIZE) {
        return false;
    }

    Announce_Entry *entry = find_entry_slot(announce, data_public_key);

    if (entry == nullptr) {
        return false;
    }

    if (length > 0) {
        assert(data != nullptr);

        if (entry->data != nullptr) {
            free(entry->data);
        }

        entry->data = (uint8_t *)malloc(length);

        if (entry->data == nullptr) {
            return false;
        }

        memcpy(entry->data, data, length);
    }

    entry->length = length;
    memcpy(entry->data_public_key, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    entry->store_until = mono_time_get(announce->mono_time) + timeout;

    return true;
}

non_null()
static uint32_t calculate_timeout(const Announcements *announce, uint32_t requested_timeout)
{
    const uint64_t uptime = mono_time_get(announce->mono_time) - announce->start_time;
    const uint32_t max_announcement_timeout = max_u32(
                (uint32_t)min_u64(
                    MAX_MAX_ANNOUNCEMENT_TIMEOUT,
                    uptime / MAX_ANNOUNCEMENT_TIMEOUT_UPTIME_RATIO),
                MIN_MAX_ANNOUNCEMENT_TIMEOUT);

    return min_u32(max_announcement_timeout, requested_timeout);
}

#define DATA_SEARCH_TO_AUTH_MAX_SIZE (CRYPTO_PUBLIC_KEY_SIZE * 2 + MAX_PACKED_IPPORT_SIZE + MAX_SENDBACK_SIZE)

non_null(1, 2, 3, 4, 7) nullable(5)
static int create_data_search_to_auth(const Logger *logger, const uint8_t *data_public_key,
                                      const uint8_t *requester_key,
                                      const IP_Port *source, const uint8_t *sendback, uint16_t sendback_length,
                                      uint8_t *dest, uint16_t max_length)
{
    if (max_length < DATA_SEARCH_TO_AUTH_MAX_SIZE
            || sendback_length > MAX_SENDBACK_SIZE) {
        return -1;
    }

    memcpy(dest, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(dest + CRYPTO_PUBLIC_KEY_SIZE, requester_key, CRYPTO_PUBLIC_KEY_SIZE);

    const int ipport_length = pack_ip_port(logger, dest + CRYPTO_PUBLIC_KEY_SIZE * 2, MAX_PACKED_IPPORT_SIZE, source);

    if (ipport_length == -1) {
        return -1;
    }

    if (sendback_length > 0) {
        assert(sendback != nullptr);
        memcpy(dest + CRYPTO_PUBLIC_KEY_SIZE * 2 + ipport_length, sendback, sendback_length);
    }

    return CRYPTO_PUBLIC_KEY_SIZE * 2 + ipport_length + sendback_length;
}

#define DATA_SEARCH_TIMEOUT 60

non_null()
static int create_reply_plain_data_search_request(Announcements *announce,
        const IP_Port *source,
        const uint8_t *data, uint16_t length,
        uint8_t *reply, uint16_t reply_max_length,
        uint8_t *to_auth, uint16_t to_auth_length)
{
    if (length != CRYPTO_PUBLIC_KEY_SIZE &&
            length != CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA256_SIZE) {
        return -1;
    }

    const uint8_t *const data_public_key = data;

    const uint8_t *previous_hash = nullptr;

    if (length == CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA256_SIZE) {
        previous_hash = data + CRYPTO_PUBLIC_KEY_SIZE;
    }

    const int nodes_max_length = (int)reply_max_length -
                                 (CRYPTO_PUBLIC_KEY_SIZE + 1 + CRYPTO_SHA256_SIZE + TIMED_AUTH_SIZE + 1 + 1);

    if (nodes_max_length < 0) {
        return -1;
    }

    uint8_t *p = reply;

    memcpy(p, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    p += CRYPTO_PUBLIC_KEY_SIZE;

    const Announce_Entry *const stored = get_stored_const(announce, data_public_key);

    if (stored == nullptr) {
        *p = 0;
        ++p;
    } else {
        *p = 1;
        ++p;
        crypto_sha256(p, stored->data, stored->length);
        p += CRYPTO_SHA256_SIZE;
    }

    generate_timed_auth(announce->mono_time, DATA_SEARCH_TIMEOUT, announce->hmac_key,
                        to_auth, to_auth_length, p);
    p += TIMED_AUTH_SIZE;

    *p = would_accept_store_request(announce, data_public_key);
    ++p;

    Node_format nodes_list[MAX_SENT_NODES];
    const int num_nodes = get_close_nodes(announce->dht, data_public_key, nodes_list,
                                          net_family_unspec(), ip_is_lan(&source->ip), true);

    if (num_nodes < 0 || num_nodes > MAX_SENT_NODES) {
        return -1;
    }

    *p = num_nodes;
    ++p;

    p += pack_nodes(announce->log, p, nodes_max_length, nodes_list, num_nodes);

    const uint32_t reply_len = p - reply;

    if (previous_hash != nullptr) {
        uint8_t hash[CRYPTO_SHA256_SIZE];

        crypto_sha256(hash, reply, reply_len);

        if (crypto_sha256_eq(hash, previous_hash)) {
            return CRYPTO_PUBLIC_KEY_SIZE;
        }
    }

    return reply_len;
}

non_null()
static int create_reply_plain_data_retrieve_request(Announcements *announce,
        const IP_Port *source,
        const uint8_t *data, uint16_t length,
        uint8_t *reply, uint16_t reply_max_length,
        uint8_t *to_auth, uint16_t to_auth_length)
{
    if (length != CRYPTO_PUBLIC_KEY_SIZE + 1 + TIMED_AUTH_SIZE) {
        return -1;
    }

    if (data[CRYPTO_PUBLIC_KEY_SIZE] != 0) {
        return -1;
    }

    const uint8_t *const data_public_key = data;
    const uint8_t *const auth = data + CRYPTO_PUBLIC_KEY_SIZE + 1;

    if (!check_timed_auth(announce->mono_time, DATA_SEARCH_TIMEOUT, announce->hmac_key,
                          to_auth, to_auth_length, auth)) {
        return -1;
    }

    const Announce_Entry *const entry = get_stored_const(announce, data_public_key);

    if (entry == nullptr) {
        return -1;
    }

    const uint16_t reply_len = CRYPTO_PUBLIC_KEY_SIZE + 1 + entry->length;

    if (reply_max_length < reply_len) {
        return -1;
    }

    memcpy(reply, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    reply[CRYPTO_PUBLIC_KEY_SIZE] = 1;
    memcpy(reply + CRYPTO_PUBLIC_KEY_SIZE + 1, entry->data, entry->length);

    return reply_len;
}

non_null()
static int create_reply_plain_store_announce_request(Announcements *announce,
        const IP_Port *source,
        const uint8_t *data, uint16_t length,
        uint8_t *reply, uint16_t reply_max_length,
        uint8_t *to_auth, uint16_t to_auth_length)
{
    const int plain_len = (int)length - (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE);
    const int announcement_len = (int)plain_len - (TIMED_AUTH_SIZE + sizeof(uint32_t) + 1);

    const uint8_t *const data_public_key = data;

    if (announcement_len < 0) {
        return -1;
    }

    VLA(uint8_t, plain, plain_len);
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    get_shared_key(announce->mono_time, &announce->shared_keys, shared_key,
                   announce->secret_key, data_public_key);

    if (decrypt_data_symmetric(shared_key,
                               data + CRYPTO_PUBLIC_KEY_SIZE,
                               data + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                               plain_len + CRYPTO_MAC_SIZE,
                               plain) != plain_len) {
        return -1;
    }

    const uint8_t *const auth = plain;
    uint32_t requested_timeout;
    net_unpack_u32(plain + TIMED_AUTH_SIZE, &requested_timeout);
    const uint32_t timeout = calculate_timeout(announce, requested_timeout);
    const uint8_t announcement_type = plain[TIMED_AUTH_SIZE + sizeof(uint32_t)];
    const uint8_t *announcement = plain + TIMED_AUTH_SIZE + sizeof(uint32_t) + 1;

    if (!check_timed_auth(announce->mono_time, DATA_SEARCH_TIMEOUT, announce->hmac_key,
                          to_auth, to_auth_length, auth)) {
        return -1;
    }

    if (announcement_type > 1) {
        return -1;
    }

    if (announcement_type == 1) {
        if (announcement_len != CRYPTO_SHA256_SIZE) {
            return -1;
        }

        Announce_Entry *stored = get_stored(announce, data_public_key);

        if (stored == nullptr) {
            return -1;
        }

        uint8_t stored_hash[CRYPTO_SHA256_SIZE];
        crypto_sha256(stored_hash, stored->data, stored->length);

        if (!crypto_sha256_eq(announcement, stored_hash)) {
            delete_entry(stored);
            return -1;
        } else {
            stored->store_until = mono_time_get(announce->mono_time) + timeout;
        }
    } else {
        if (!announce_store_data(announce, data_public_key, announcement, announcement_len, timeout)) {
            return -1;
        }
    }

    const uint16_t reply_len = CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint32_t) + sizeof(uint64_t);

    if (reply_max_length < reply_len) {
        return -1;
    }

    memcpy(reply, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    net_pack_u32(reply + CRYPTO_PUBLIC_KEY_SIZE, timeout);
    net_pack_u64(reply + CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint32_t),
                 mono_time_get(announce->mono_time) + announce->synch_offset);
    return reply_len;
}

non_null(1, 2, 3, 7, 9) nullable(5)
static int create_reply_plain(Announcements *announce,
                              const uint8_t *requester_key, const IP_Port *source, uint8_t type,
                              const uint8_t *sendback, uint16_t sendback_length,
                              const uint8_t *data, uint16_t length,
                              uint8_t *reply, uint16_t reply_max_length)
{
    if (length < CRYPTO_PUBLIC_KEY_SIZE) {
        return -1;
    }

    const uint8_t *const data_public_key = data;

    uint8_t to_auth[DATA_SEARCH_TO_AUTH_MAX_SIZE];
    const int to_auth_length = create_data_search_to_auth(announce->log, data_public_key, requester_key, source,
                               sendback, sendback_length, to_auth, DATA_SEARCH_TO_AUTH_MAX_SIZE);

    if (to_auth_length == -1) {
        return -1;
    }

    switch (type) {
        case NET_PACKET_DATA_SEARCH_REQUEST:
            return create_reply_plain_data_search_request(announce, source, data, length, reply, reply_max_length, to_auth,
                    (uint16_t)to_auth_length);

        case NET_PACKET_DATA_RETRIEVE_REQUEST:
            return create_reply_plain_data_retrieve_request(announce, source, data, length, reply, reply_max_length, to_auth,
                    (uint16_t)to_auth_length);

        case NET_PACKET_STORE_ANNOUNCE_REQUEST:
            return create_reply_plain_store_announce_request(announce, source, data, length, reply, reply_max_length, to_auth,
                    (uint16_t)to_auth_length);

        default:
            return -1;
    }
}

non_null(1, 2, 5, 7) nullable(3)
static int create_reply(Announcements *announce, const IP_Port *source,
                        const uint8_t *sendback, uint16_t sendback_length,
                        const uint8_t *data, uint16_t length,
                        uint8_t *reply, uint16_t reply_max_length)
{
    const int plain_len = (int)length - (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE);

    if (plain_len < (int)sizeof(uint64_t)) {
        return -1;
    }

    VLA(uint8_t, plain, plain_len);
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    dht_get_shared_key_recv(announce->dht, shared_key, data + 1);

    if (decrypt_data_symmetric(shared_key,
                               data + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                               data + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                               plain_len + CRYPTO_MAC_SIZE,
                               plain) != plain_len) {
        return -1;
    }

    const int plain_reply_max_len = (int)reply_max_length -
                                    (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE);

    if (plain_reply_max_len < sizeof(uint64_t)) {
        return -1;
    }

    VLA(uint8_t, plain_reply, plain_reply_max_len);

    const int plain_reply_noping_len = create_reply_plain(announce,
                                       data + 1, source, data[0],
                                       sendback, sendback_length,
                                       plain, plain_len - sizeof(uint64_t),
                                       plain_reply, plain_reply_max_len - sizeof(uint64_t));

    if (plain_reply_noping_len == -1) {
        return -1;
    }

    memcpy(plain_reply + plain_reply_noping_len,
           plain + (plain_len - sizeof(uint64_t)), sizeof(uint64_t));

    const uint16_t plain_reply_len = plain_reply_noping_len + sizeof(uint64_t);

    const uint8_t response_type = announce_response_of_request_type(data[0]);

    return dht_create_packet(announce->rng, announce->public_key, shared_key, response_type,
                             plain_reply, plain_reply_len, reply, reply_max_length);
}

non_null(1, 2, 3, 5) nullable(7)
static void forwarded_request_callback(void *object, const IP_Port *forwarder,
                                       const uint8_t *sendback, uint16_t sendback_length,
                                       const uint8_t *data, uint16_t length, void *userdata)
{
    Announcements *announce = (Announcements *) object;

    uint8_t reply[MAX_FORWARD_DATA_SIZE];

    const int len = create_reply(announce, forwarder,
                                 sendback, sendback_length,
                                 data, length, reply, sizeof(reply));

    if (len == -1) {
        return;
    }

    forward_reply(announce->net, forwarder, sendback, sendback_length, reply, len);
}

non_null(1, 2, 3) nullable(5)
static int handle_dht_announce_request(void *object, const IP_Port *source,
                                       const uint8_t *data, uint16_t length, void *userdata)
{
    Announcements *announce = (Announcements *) object;

    uint8_t reply[MAX_FORWARD_DATA_SIZE];

    const int len = create_reply(announce, source,
                                 nullptr, 0,
                                 data, length, reply, sizeof(reply));

    if (len == -1) {
        return -1;
    }

    return sendpacket(announce->net, source, reply, len) == len ? 0 : -1;
}

Announcements *new_announcements(const Logger *log, const Random *rng, const Mono_Time *mono_time,
                                 Forwarding *forwarding)
{
    if (log == nullptr || mono_time == nullptr || forwarding == nullptr) {
        return nullptr;
    }

    Announcements *announce = (Announcements *)calloc(1, sizeof(Announcements));

    if (announce == nullptr) {
        return nullptr;
    }

    announce->log = log;
    announce->rng = rng;
    announce->forwarding = forwarding;
    announce->mono_time = mono_time;
    announce->dht = forwarding_get_dht(forwarding);
    announce->net = dht_get_net(announce->dht);
    announce->public_key = dht_get_self_public_key(announce->dht);
    announce->secret_key = dht_get_self_secret_key(announce->dht);
    new_hmac_key(announce->rng, announce->hmac_key);

    announce->start_time = mono_time_get(announce->mono_time);

    set_callback_forwarded_request(forwarding, forwarded_request_callback, announce);

    networking_registerhandler(announce->net, NET_PACKET_DATA_SEARCH_REQUEST, handle_dht_announce_request, announce);
    networking_registerhandler(announce->net, NET_PACKET_DATA_RETRIEVE_REQUEST, handle_dht_announce_request, announce);
    networking_registerhandler(announce->net, NET_PACKET_STORE_ANNOUNCE_REQUEST, handle_dht_announce_request, announce);

    return announce;
}

void kill_announcements(Announcements *announce)
{
    if (announce == nullptr) {
        return;
    }

    set_callback_forwarded_request(announce->forwarding, nullptr, nullptr);

    networking_registerhandler(announce->net, NET_PACKET_DATA_SEARCH_REQUEST, nullptr, nullptr);
    networking_registerhandler(announce->net, NET_PACKET_DATA_RETRIEVE_REQUEST, nullptr, nullptr);
    networking_registerhandler(announce->net, NET_PACKET_STORE_ANNOUNCE_REQUEST, nullptr, nullptr);

    crypto_memzero(announce->hmac_key, CRYPTO_HMAC_KEY_SIZE);
    crypto_memzero(&announce->shared_keys, sizeof(Shared_Keys));

    for (uint32_t i = 0; i < ANNOUNCE_BUCKETS * ANNOUNCE_BUCKET_SIZE; ++i) {
        if (announce->entries[i].data != nullptr) {
            free(announce->entries[i].data);
        }
    }

    free(announce);
}
