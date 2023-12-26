/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * An implementation of massive text only group chats.
 */

#include "group_connection.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "DHT.h"
#include "TCP_connection.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "group_chats.h"
#include "group_common.h"
#include "logger.h"
#include "mono_time.h"
#include "network.h"
#include "util.h"

/** Seconds since last direct UDP packet was received before the connection is considered dead */
#define GCC_UDP_DIRECT_TIMEOUT (GC_PING_TIMEOUT + 4)

/** Returns true if array entry does not contain an active packet. */
non_null()
static bool array_entry_is_empty(const GC_Message_Array_Entry *array_entry)
{
    assert(array_entry != nullptr);
    return array_entry->time_added == 0;
}

/** @brief Clears an array entry. */
non_null()
static void clear_array_entry(GC_Message_Array_Entry *const array_entry)
{
    if (array_entry->data != nullptr) {
        free(array_entry->data);
    }

    *array_entry = (GC_Message_Array_Entry) {
        nullptr
    };
}

/**
 * Clears every send array message from queue starting at the index designated by
 * `start_id` and ending at `end_id`, and sets the send_message_id for `gconn`
 * to `start_id`.
 */
non_null()
static void clear_send_queue_id_range(GC_Connection *gconn, uint64_t start_id, uint64_t end_id)
{
    const uint16_t start_idx = gcc_get_array_index(start_id);
    const uint16_t end_idx = gcc_get_array_index(end_id);

    for (uint16_t i = start_idx; i != end_idx; i = (i + 1) % GCC_BUFFER_SIZE) {
        GC_Message_Array_Entry *entry = &gconn->send_array[i];
        clear_array_entry(entry);
    }

    gconn->send_message_id = start_id;
}

uint16_t gcc_get_array_index(uint64_t message_id)
{
    return message_id % GCC_BUFFER_SIZE;
}

void gcc_set_send_message_id(GC_Connection *gconn, uint64_t id)
{
    gconn->send_message_id = id;
    gconn->send_array_start = id % GCC_BUFFER_SIZE;
}

void gcc_set_recv_message_id(GC_Connection *gconn, uint64_t id)
{
    gconn->received_message_id = id;
}

/** @brief Puts packet data in array_entry.
 *
 * Return true on success.
 */
non_null(1, 2) nullable(3)
static bool create_array_entry(const Mono_Time *mono_time, GC_Message_Array_Entry *array_entry, const uint8_t *data,
                               uint16_t length, uint8_t packet_type, uint64_t message_id)
{
    if (length > 0) {
        if (data == nullptr) {
            return false;
        }

        array_entry->data = (uint8_t *)malloc(sizeof(uint8_t) * length);

        if (array_entry->data == nullptr) {
            return false;
        }

        memcpy(array_entry->data, data, length);
    }

    const uint64_t tm = mono_time_get(mono_time);

    array_entry->data_length = length;
    array_entry->packet_type = packet_type;
    array_entry->message_id = message_id;
    array_entry->time_added = tm;
    array_entry->last_send_try = tm;

    return true;
}

/** @brief Adds data of length to gconn's send_array.
 *
 * Returns true on success and increments gconn's send_message_id.
 */
non_null(1, 2, 3) nullable(4)
static bool add_to_send_array(const Logger *log, const Mono_Time *mono_time, GC_Connection *gconn, const uint8_t *data,
                              uint16_t length, uint8_t packet_type)
{
    /* check if send_array is full */
    if ((gconn->send_message_id % GCC_BUFFER_SIZE) == (uint16_t)(gconn->send_array_start - 1)) {
        LOGGER_DEBUG(log, "Send array overflow");
        return false;
    }

    const uint16_t idx = gcc_get_array_index(gconn->send_message_id);
    GC_Message_Array_Entry *array_entry = &gconn->send_array[idx];

    if (!array_entry_is_empty(array_entry)) {
        LOGGER_DEBUG(log, "Send array entry isn't empty");
        return false;
    }

    if (!create_array_entry(mono_time, array_entry, data, length, packet_type, gconn->send_message_id)) {
        LOGGER_WARNING(log, "Failed to create array entry");
        return false;
    }

    ++gconn->send_message_id;

    return true;
}

int gcc_send_lossless_packet(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint16_t length,
                             uint8_t packet_type)
{
    const uint64_t message_id = gconn->send_message_id;

    if (!add_to_send_array(chat->log, chat->mono_time, gconn, data, length, packet_type)) {
        LOGGER_WARNING(chat->log, "Failed to add payload to send array: (type: 0x%02x, length: %d)", packet_type, length);
        return -1;
    }

    if (!gcc_encrypt_and_send_lossless_packet(chat, gconn, data, length, message_id, packet_type)) {
        LOGGER_DEBUG(chat->log, "Failed to send payload: (type: 0x%02x, length: %d)", packet_type, length);
        return -2;
    }

    return 0;
}


bool gcc_send_lossless_packet_fragments(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data,
                                        uint16_t length, uint8_t packet_type)
{
    if (length <= MAX_GC_PACKET_CHUNK_SIZE || data == nullptr) {
        LOGGER_FATAL(chat->log, "invalid length or null data pointer");
        return false;
    }

    const uint16_t start_id = gconn->send_message_id;

    // First packet segment is comprised of packet type + first chunk of payload
    uint8_t chunk[MAX_GC_PACKET_CHUNK_SIZE];
    chunk[0] = packet_type;
    memcpy(chunk + 1, data, MAX_GC_PACKET_CHUNK_SIZE - 1);

    if (!add_to_send_array(chat->log, chat->mono_time, gconn, chunk, MAX_GC_PACKET_CHUNK_SIZE, GP_FRAGMENT)) {
        return false;
    }

    uint16_t processed = MAX_GC_PACKET_CHUNK_SIZE - 1;

    // The rest of the segments are added in chunks
    while (length > processed) {
        const uint16_t chunk_len = min_u16(MAX_GC_PACKET_CHUNK_SIZE, length - processed);

        memcpy(chunk, data + processed, chunk_len);
        processed += chunk_len;

        if (!add_to_send_array(chat->log, chat->mono_time, gconn, chunk, chunk_len, GP_FRAGMENT)) {
            clear_send_queue_id_range(gconn, start_id, gconn->send_message_id);
            return false;
        }
    }

    // empty packet signals the end of the sequence
    if (!add_to_send_array(chat->log, chat->mono_time, gconn, nullptr, 0, GP_FRAGMENT)) {
        clear_send_queue_id_range(gconn, start_id, gconn->send_message_id);
        return false;
    }

    const uint16_t start_idx = gcc_get_array_index(start_id);
    const uint16_t end_idx = gcc_get_array_index(gconn->send_message_id);

    for (uint16_t i = start_idx; i != end_idx; i = (i + 1) % GCC_BUFFER_SIZE) {
        const GC_Message_Array_Entry *entry = &gconn->send_array[i];

        if (array_entry_is_empty(entry)) {
            LOGGER_FATAL(chat->log, "array entry for packet chunk is empty");
            return false;
        }

        assert(entry->packet_type == GP_FRAGMENT);

        gcc_encrypt_and_send_lossless_packet(chat, gconn, entry->data, entry->data_length,
                                             entry->message_id, entry->packet_type);
    }

    return true;
}

bool gcc_handle_ack(const Logger *log, GC_Connection *gconn, uint64_t message_id)
{
    uint16_t idx = gcc_get_array_index(message_id);
    GC_Message_Array_Entry *array_entry = &gconn->send_array[idx];

    if (array_entry_is_empty(array_entry)) {
        return true;
    }

    if (array_entry->message_id != message_id) {  // wrap-around indicates a connection problem
        LOGGER_DEBUG(log, "Wrap-around on message %llu", (unsigned long long)message_id);
        return false;
    }

    clear_array_entry(array_entry);

    /* Put send_array_start in proper position */
    if (idx == gconn->send_array_start) {
        const uint16_t end = gconn->send_message_id % GCC_BUFFER_SIZE;

        while (array_entry_is_empty(&gconn->send_array[idx]) && gconn->send_array_start != end) {
            gconn->send_array_start = (gconn->send_array_start + 1) % GCC_BUFFER_SIZE;
            idx = (idx + 1) % GCC_BUFFER_SIZE;
        }
    }

    return true;
}

bool gcc_ip_port_is_set(const GC_Connection *gconn)
{
    return ipport_isset(&gconn->addr.ip_port);
}

void gcc_set_ip_port(GC_Connection *gconn, const IP_Port *ipp)
{
    if (ipp != nullptr && ipport_isset(ipp)) {
        gconn->addr.ip_port = *ipp;
    }
}

bool gcc_copy_tcp_relay(const Random *rng, Node_format *tcp_node, const GC_Connection *gconn)
{
    if (gconn == nullptr || tcp_node == nullptr) {
        return false;
    }

    if (gconn->tcp_relays_count == 0) {
        return false;
    }

    const uint32_t rand_idx = random_range_u32(rng, gconn->tcp_relays_count);

    if (!ipport_isset(&gconn->connected_tcp_relays[rand_idx].ip_port)) {
        return false;
    }

    *tcp_node = gconn->connected_tcp_relays[rand_idx];

    return true;
}

int gcc_save_tcp_relay(const Random *rng, GC_Connection *gconn, const Node_format *tcp_node)
{
    if (gconn == nullptr || tcp_node == nullptr) {
        return -1;
    }

    if (!ipport_isset(&tcp_node->ip_port)) {
        return -1;
    }

    for (uint16_t i = 0; i < gconn->tcp_relays_count; ++i) {
        if (pk_equal(gconn->connected_tcp_relays[i].public_key, tcp_node->public_key)) {
            return -2;
        }
    }

    uint32_t idx = gconn->tcp_relays_count;

    if (gconn->tcp_relays_count >= MAX_FRIEND_TCP_CONNECTIONS) {
        idx = random_range_u32(rng, gconn->tcp_relays_count);
    } else {
        ++gconn->tcp_relays_count;
    }

    gconn->connected_tcp_relays[idx] = *tcp_node;

    return 0;
}

/** @brief Stores `data` of length `length` in the receive array for `gconn`.
 *
 * Return true on success.
 */
non_null(1, 2, 3) nullable(4)
static bool store_in_recv_array(const Logger *log, const Mono_Time *mono_time, GC_Connection *gconn,
                                const uint8_t *data,
                                uint16_t length, uint8_t packet_type, uint64_t message_id)
{
    const uint16_t idx = gcc_get_array_index(message_id);
    GC_Message_Array_Entry *ary_entry = &gconn->recv_array[idx];

    if (!array_entry_is_empty(ary_entry)) {
        LOGGER_DEBUG(log, "Recv array is not empty");
        return false;
    }

    if (!create_array_entry(mono_time, ary_entry, data, length, packet_type, message_id)) {
        LOGGER_WARNING(log, "Failed to create array entry");
        return false;
    }

    return true;
}

/**
 * Reassembles a fragmented packet sequence ending with the data in the receive
 * array at slot `message_id - 1` and starting with the last found slot containing
 * a GP_FRAGMENT packet when searching backwards in the array.
 *
 * The fully reassembled packet is stored in `payload`, which must be passed as a
 * null pointer, and must be free'd by the caller.
 *
 * Return the length of the fully reassembled packet on success.
 * Return 0 on failure.
 */
non_null(1, 3) nullable(2)
static uint16_t reassemble_packet(const Logger *log, GC_Connection *gconn, uint8_t **payload, uint64_t message_id)
{
    uint16_t end_idx = gcc_get_array_index(message_id - 1);
    uint16_t start_idx = end_idx;
    uint16_t packet_length = 0;

    GC_Message_Array_Entry *entry = &gconn->recv_array[end_idx];

    // search backwards in recv array until we find an empty slot or a non-fragment packet type
    while (!array_entry_is_empty(entry) && entry->packet_type == GP_FRAGMENT) {
        assert(entry->data != nullptr);
        assert(entry->data_length <= MAX_GC_PACKET_INCOMING_CHUNK_SIZE);

        const uint16_t diff = packet_length + entry->data_length;

        assert(diff > packet_length);  // overflow check
        packet_length = diff;

        if (packet_length > MAX_GC_PACKET_SIZE) {
            LOGGER_ERROR(log, "Payload of size %u exceeded max packet size", packet_length);  // should never happen
            return 0;
        }

        start_idx = start_idx > 0 ? start_idx - 1 : GCC_BUFFER_SIZE - 1;
        entry = &gconn->recv_array[start_idx];

        if (start_idx == end_idx) {
            LOGGER_ERROR(log, "Packet reassemble wrap-around");
            return 0;
        }
    }

    if (packet_length == 0) {
        return 0;
    }

    assert(*payload == nullptr);
    *payload = (uint8_t *)malloc(packet_length);

    if (*payload == nullptr) {
        LOGGER_ERROR(log, "Failed to allocate %u bytes for payload buffer", packet_length);
        return 0;
    }

    start_idx = (start_idx + 1) % GCC_BUFFER_SIZE;
    end_idx = (end_idx + 1) % GCC_BUFFER_SIZE;

    uint16_t processed = 0;

    for (uint16_t i = start_idx; i != end_idx; i = (i + 1) % GCC_BUFFER_SIZE) {
        entry = &gconn->recv_array[i];

        assert(processed + entry->data_length <= packet_length);
        memcpy(*payload + processed, entry->data, entry->data_length);
        processed += entry->data_length;

        clear_array_entry(entry);
    }

    return processed;
}

int gcc_handle_packet_fragment(const GC_Session *c, GC_Chat *chat, uint32_t peer_number,
                               GC_Connection *gconn, const uint8_t *chunk, uint16_t length, uint8_t packet_type,
                               uint64_t message_id, void *userdata)
{
    if (length > 0) {
        if (!store_in_recv_array(chat->log, chat->mono_time, gconn, chunk, length, packet_type, message_id)) {
            return -1;
        }

        gcc_set_recv_message_id(gconn, gconn->received_message_id + 1);
        gconn->last_chunk_id = message_id;

        return 1;
    }

    uint8_t sender_pk[ENC_PUBLIC_KEY_SIZE];
    memcpy(sender_pk, get_enc_key(gconn->addr.public_key), ENC_PUBLIC_KEY_SIZE);

    uint8_t *payload = nullptr;
    const uint16_t processed_len = reassemble_packet(chat->log, gconn, &payload, message_id);

    if (processed_len == 0) {
        free(payload);
        return -1;
    }

    if (!handle_gc_lossless_helper(c, chat, peer_number, payload + 1, processed_len - 1, payload[0], userdata)) {
        free(payload);
        return -1;
    }

    /* peer number can change from peer add operations in packet handlers */
    peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);
    gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        free(payload);
        return 0;
    }

    gcc_set_recv_message_id(gconn, gconn->received_message_id + 1);
    gconn->last_chunk_id = 0;

    free(payload);

    return 0;
}

int gcc_handle_received_message(const Logger *log, const Mono_Time *mono_time, GC_Connection *gconn,
                                const uint8_t *data, uint16_t length, uint8_t packet_type, uint64_t message_id,
                                bool direct_conn)
{
    if (direct_conn) {
        gconn->last_received_direct_time = mono_time_get(mono_time);
    }

    /* Appears to be a duplicate packet so we discard it */
    if (message_id < gconn->received_message_id + 1) {
        return 0;
    }

    if (packet_type == GP_FRAGMENT) { // we handle packet fragments as a special case
        return 3;
    }

    /* we're missing an older message from this peer so we store it in recv_array */
    if (message_id > gconn->received_message_id + 1) {
        if (!store_in_recv_array(log, mono_time, gconn, data, length, packet_type, message_id)) {
            return -1;
        }

        return 1;
    }

    gcc_set_recv_message_id(gconn, gconn->received_message_id + 1);

    return 2;
}

/** @brief Handles peer_number's array entry with appropriate handler and clears it from array.
 *
 * This function increments the received message ID for `gconn`.
 *
 * Return true on success.
 */
non_null(1, 2, 3, 5) nullable(6)
static bool process_recv_array_entry(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number,
                                     GC_Message_Array_Entry *const array_entry, void *userdata)
{
    uint8_t sender_pk[ENC_PUBLIC_KEY_SIZE];
    memcpy(sender_pk, get_enc_key(gconn->addr.public_key), ENC_PUBLIC_KEY_SIZE);

    const bool ret = handle_gc_lossless_helper(c, chat, peer_number, array_entry->data, array_entry->data_length,
                     array_entry->packet_type, userdata);

    /* peer number can change from peer add operations in packet handlers */
    peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);
    gconn = get_gc_connection(chat, peer_number);

    clear_array_entry(array_entry);

    if (gconn == nullptr) {
        return true;
    }

    if (!ret) {
        gc_send_message_ack(chat, gconn, array_entry->message_id, GR_ACK_REQ);
        return false;
    }

    gc_send_message_ack(chat, gconn, array_entry->message_id, GR_ACK_RECV);

    gcc_set_recv_message_id(gconn, gconn->received_message_id + 1);

    return true;
}

void gcc_check_recv_array(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number,
                          void *userdata)
{
    if (gconn->last_chunk_id != 0) {  // dont check array if we have an unfinished fragment sequence
        return;
    }

    const uint16_t idx = (gconn->received_message_id + 1) % GCC_BUFFER_SIZE;
    GC_Message_Array_Entry *const array_entry = &gconn->recv_array[idx];

    if (!array_entry_is_empty(array_entry)) {
        process_recv_array_entry(c, chat, gconn, peer_number, array_entry, userdata);
    }
}

void gcc_resend_packets(const GC_Chat *chat, GC_Connection *gconn)
{
    const uint64_t tm = mono_time_get(chat->mono_time);
    const uint16_t start = gconn->send_array_start;
    const uint16_t end = gconn->send_message_id % GCC_BUFFER_SIZE;

    GC_Message_Array_Entry *array_entry = &gconn->send_array[start];

    if (array_entry_is_empty(array_entry)) {
        return;
    }

    if (mono_time_is_timeout(chat->mono_time, array_entry->time_added, GC_CONFIRMED_PEER_TIMEOUT)) {
        gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_TIMEOUT, nullptr, 0);
        LOGGER_DEBUG(chat->log, "Send array stuck; timing out peer");
        return;
    }

    for (uint16_t i = start; i != end; i = (i + 1) % GCC_BUFFER_SIZE) {
        array_entry = &gconn->send_array[i];

        if (array_entry_is_empty(array_entry)) {
            continue;
        }

        if (tm == array_entry->last_send_try) {
            continue;
        }

        const uint64_t delta = array_entry->last_send_try - array_entry->time_added;
        array_entry->last_send_try = tm;

        /* if this occurrs less than once per second this won't be reliable */
        if (delta > 1 && is_power_of_2(delta)) {
            gcc_encrypt_and_send_lossless_packet(chat, gconn, array_entry->data, array_entry->data_length,
                                                 array_entry->message_id, array_entry->packet_type);
        }
    }
}

bool gcc_send_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *packet, uint16_t length)
{
    if (packet == nullptr || length == 0) {
        return false;
    }

    bool direct_send_attempt = false;

    if (gcc_direct_conn_is_possible(chat, gconn)) {
        if (gcc_conn_is_direct(chat->mono_time, gconn)) {
            return (uint16_t) sendpacket(chat->net, &gconn->addr.ip_port, packet, length) == length;
        }

        if ((uint16_t) sendpacket(chat->net, &gconn->addr.ip_port, packet, length) == length) {
            direct_send_attempt = true;
        }
    }

    const int ret = send_packet_tcp_connection(chat->tcp_conn, gconn->tcp_connection_num, packet, length);
    return ret == 0 || direct_send_attempt;
}

bool gcc_encrypt_and_send_lossless_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *data,
        uint16_t length, uint64_t message_id, uint8_t packet_type)
{
    const uint16_t packet_size = gc_get_wrapped_packet_size(length, NET_PACKET_GC_LOSSLESS);
    uint8_t *packet = (uint8_t *)malloc(packet_size);

    if (packet == nullptr) {
        LOGGER_ERROR(chat->log, "Failed to allocate memory for packet buffer");
        return false;
    }

    const int enc_len = group_packet_wrap(
                            chat->log, chat->rng, chat->self_public_key, gconn->session_shared_key, packet,
                            packet_size, data, length, message_id, packet_type, NET_PACKET_GC_LOSSLESS);

    if (enc_len < 0) {
        LOGGER_ERROR(chat->log, "Failed to wrap packet (type: 0x%02x, error: %d)", packet_type, enc_len);
        free(packet);
        return false;
    }

    if (!gcc_send_packet(chat, gconn, packet, (uint16_t)enc_len)) {
        LOGGER_DEBUG(chat->log, "Failed to send packet (type: 0x%02x, enc_len: %d)", packet_type, enc_len);
        free(packet);
        return false;
    }

    free(packet);

    return true;
}

void gcc_make_session_shared_key(GC_Connection *gconn, const uint8_t *sender_pk)
{
    encrypt_precompute(sender_pk, gconn->session_secret_key, gconn->session_shared_key);
}

bool gcc_conn_is_direct(const Mono_Time *mono_time, const GC_Connection *gconn)
{
    return GCC_UDP_DIRECT_TIMEOUT + gconn->last_received_direct_time > mono_time_get(mono_time);
}

bool gcc_direct_conn_is_possible(const GC_Chat *chat, const GC_Connection *gconn)
{
    return !net_family_is_unspec(gconn->addr.ip_port.ip.family) && !net_family_is_unspec(net_family(chat->net));
}

void gcc_mark_for_deletion(GC_Connection *gconn, TCP_Connections *tcp_conn, Group_Exit_Type type,
                           const uint8_t *part_message, uint16_t length)
{
    if (gconn == nullptr) {
        return;
    }

    if (gconn->pending_delete) {
        return;
    }

    gconn->pending_delete = true;
    gconn->exit_info.exit_type = type;

    kill_tcp_connection_to(tcp_conn, gconn->tcp_connection_num);

    if (length > 0 && length <= MAX_GC_PART_MESSAGE_SIZE  && part_message != nullptr) {
        memcpy(gconn->exit_info.part_message, part_message, length);
        gconn->exit_info.length = length;
    }
}

void gcc_peer_cleanup(GC_Connection *gconn)
{
    for (size_t i = 0; i < GCC_BUFFER_SIZE; ++i) {
        free(gconn->send_array[i].data);
        free(gconn->recv_array[i].data);
    }

    free(gconn->recv_array);
    free(gconn->send_array);

    crypto_memunlock(gconn->session_secret_key, sizeof(gconn->session_secret_key));
    crypto_memunlock(gconn->session_shared_key, sizeof(gconn->session_shared_key));
    crypto_memzero(gconn, sizeof(GC_Connection));
}

void gcc_cleanup(const GC_Chat *chat)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        GC_Connection *gconn = get_gc_connection(chat, i);
        assert(gconn != nullptr);

        gcc_peer_cleanup(gconn);
    }
}
