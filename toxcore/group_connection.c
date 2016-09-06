/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "DHT.h"
#include "mono_time.h"
#include "network.h"
#include "group_connection.h"
#include "group_chats.h"
#include "Messenger.h"
#include "util.h"

#ifndef VANILLA_NACL

/* Returns group connection object for peernumber.
 * Returns NULL if peernumber is invalid.
 */
GC_Connection *gcc_get_connection(const GC_Chat *chat, int peernumber)
{
    if (!peernumber_valid(chat, peernumber)) {
        return nullptr;
    }

    return &chat->gcc[peernumber];
}

/* Returns true if ary entry does not contain an active packet. */
static bool ary_entry_is_empty(struct GC_Message_Ary_Entry *ary_entry)
{
    return ary_entry->time_added == 0;
}

/* Clears an ary entry.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static void clear_ary_entry(struct GC_Message_Ary_Entry *ary_entry)
{
    if (ary_entry->data) {
        free(ary_entry->data);
    }

    memset(ary_entry, 0, sizeof(struct GC_Message_Ary_Entry));
}

/* Returns ary index for message_id */
uint16_t get_ary_index(uint64_t message_id)
{
    return message_id % GCC_BUFFER_SIZE;
}

/* Puts packet data in ary_entry.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int create_ary_entry(const Mono_Time *mono_time, struct GC_Message_Ary_Entry *ary_entry, const uint8_t *data,
                            uint32_t length, uint8_t packet_type, uint64_t message_id)
{
    if (length) {
        ary_entry->data = (uint8_t *)malloc(sizeof(uint8_t) * length);

        if (ary_entry->data == nullptr) {
            return -1;
        }

        memcpy(ary_entry->data, data, length);
    }

    ary_entry->data_length = length;
    ary_entry->packet_type = packet_type;
    ary_entry->message_id = message_id;
    ary_entry->time_added = mono_time_get(mono_time);
    ary_entry->last_send_try = mono_time_get(mono_time);

    return 0;
}

/* Adds data of length to gconn's send_ary.
 *
 * Returns 0 on success and increments gconn's send_message_id.
 * Returns -1 on failure.
 */
int gcc_add_send_ary(const Mono_Time *mono_time, GC_Connection *gconn, const uint8_t *data, uint32_t length,
                     uint8_t packet_type)
{
    /* check if send_ary is full */
    if ((gconn->send_message_id % GCC_BUFFER_SIZE) == (uint16_t)(gconn->send_ary_start - 1)) {
        return -1;
    }

    uint16_t idx = get_ary_index(gconn->send_message_id);
    struct GC_Message_Ary_Entry *ary_entry = &gconn->send_ary[idx];

    if (!ary_entry_is_empty(ary_entry)) {
        return -1;
    }

    if (create_ary_entry(mono_time, ary_entry, data, length, packet_type, gconn->send_message_id) == -1) {
        return -1;
    }

    ++gconn->send_message_id;

    return 0;
}

/* Removes send_ary item with message_id.
 *
 * Returns 0 if success.
 * Returns -1 on failure.
 */
int gcc_handle_ack(GC_Connection *gconn, uint64_t message_id)
{
    uint16_t idx = get_ary_index(message_id);
    struct GC_Message_Ary_Entry *ary_entry = &gconn->send_ary[idx];

    if (ary_entry_is_empty(ary_entry)) {
        return -1;
    }

    if (ary_entry->message_id != message_id) {  // wrap-around indicates a connection problem
        return -1;
    }

    clear_ary_entry(ary_entry);

    /* Put send_ary_start in proper position */
    if (idx == gconn->send_ary_start) {
        uint16_t end = gconn->send_message_id % GCC_BUFFER_SIZE;

        while (ary_entry_is_empty(ary_entry) && gconn->send_ary_start != end) {
            gconn->send_ary_start = (gconn->send_ary_start + 1) % GCC_BUFFER_SIZE;
            idx = (idx + 1) % GCC_BUFFER_SIZE;
        }
    }

    return 0;
}

/* Decides if message need to be put in recv_ary or immediately handled.
 *
 * Return 2 if message is in correct sequence and may be handled immediately.
 * Return 1 if packet is out of sequence and added to recv_ary.
 * Return 0 if message is a duplicate.
 * Return -1 on failure
 */
int gcc_handle_recv_message(GC_Chat *chat, uint32_t peernumber, const uint8_t *data, uint32_t length,
                            uint8_t packet_type, uint64_t message_id)
{
    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    /* Appears to be a duplicate packet so we discard it */
    if (message_id < gconn->recv_message_id + 1) {
        return 0;
    }

    /* we're missing an older message from this peer so we store it in recv_ary */
    if (message_id > gconn->recv_message_id + 1) {
        uint16_t idx = get_ary_index(message_id);
        struct GC_Message_Ary_Entry *ary_entry = &gconn->recv_ary[idx];

        if (!ary_entry_is_empty(ary_entry)) {
            return -1;
        }

        if (create_ary_entry(chat->mono_time, ary_entry, data, length, packet_type, message_id) == -1) {
            return -1;
        }

        return 1;
    }

    ++gconn->recv_message_id;

    return 2;
}

/* Handles peernumber's array entry with appropriate handler and clears it from array.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int process_recv_ary_entry(GC_Chat *chat, Messenger *m, int groupnum, uint32_t peernumber,
                                  struct GC_Message_Ary_Entry *ary_entry)
{
    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    int ret = handle_gc_lossless_helper(m, groupnum, peernumber, ary_entry->data, ary_entry->data_length,
                                        ary_entry->message_id, ary_entry->packet_type);
    clear_ary_entry(ary_entry);

    if (ret == -1) {
        gc_send_message_ack(chat, gconn, 0, ary_entry->message_id);
        return -1;
    }

    gc_send_message_ack(chat, gconn, ary_entry->message_id, 0);
    ++gconn->recv_message_id;

    return 0;
}

/* Checks for and handles messages that are in proper sequence in gconn's recv_ary.
 * This should always be called after a new packet is handled in correct sequence.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gcc_check_recv_ary(Messenger *m, int groupnum, uint32_t peernumber)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnum);

    if (!chat) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    uint16_t idx = (gconn->recv_message_id + 1) % GCC_BUFFER_SIZE;
    struct GC_Message_Ary_Entry *ary_entry = &gconn->recv_ary[idx];

    while (!ary_entry_is_empty(ary_entry)) {
        if (process_recv_ary_entry(chat, m, groupnum, peernumber, ary_entry) == -1) {
            return -1;
        }

        idx = (gconn->recv_message_id + 1) % GCC_BUFFER_SIZE;
        ary_entry = &gconn->recv_ary[idx];
    }

    return 0;
}

void gcc_resend_packets(Messenger *m, GC_Chat *chat, uint32_t peernumber)
{
    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return;
    }

    uint64_t tm = mono_time_get(m->mono_time);
    uint16_t i, start = gconn->send_ary_start, end = gconn->send_message_id % GCC_BUFFER_SIZE;

    for (i = start; i != end; i = (i + 1) % GCC_BUFFER_SIZE) {
        struct GC_Message_Ary_Entry *ary_entry = &gconn->send_ary[i];

        if (ary_entry_is_empty(ary_entry)) {
            continue;
        }

        if (tm == ary_entry->last_send_try) {
            continue;
        }

        uint64_t delta = ary_entry->last_send_try - ary_entry->time_added;
        ary_entry->last_send_try = tm;

        /* if this occurrs less than once per second this won't be reliable */
        if (delta > 1 && is_power_of_2(delta)) {
            gcc_send_group_packet(chat, gconn, ary_entry->data, ary_entry->data_length, ary_entry->packet_type);
            continue;
        }

        if (mono_time_is_timeout(m->mono_time, ary_entry->time_added, GC_CONFIRMED_PEER_TIMEOUT)) {
            gc_peer_delete(m, chat->groupnumber, peernumber, (const uint8_t *)"Peer timed out", 14);
            return;
        }
    }
}

/* Sends a packet to the peer associated with gconn.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int gcc_send_group_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *packet,
                          uint16_t length, uint8_t packet_type)
{
    if (!packet || length == 0) {
        return -1;
    }

    bool direct_send_attempt = false;

    if (!net_family_is_unspec(gconn->addr.ip_port.ip.family)) {
        if (gcc_connection_is_direct(chat->mono_time, gconn)) {
            if ((uint16_t) sendpacket(chat->net, gconn->addr.ip_port, packet, length) == length) {
                return 0;
            }

            return -1;
        }

        if (packet_type != GP_BROADCAST && packet_type != GP_MESSAGE_ACK) {
            if ((uint16_t) sendpacket(chat->net, gconn->addr.ip_port, packet, length) == length) {
                direct_send_attempt = true;
            }
        }
    }

    int ret = send_packet_tcp_connection(chat->tcp_conn, gconn->tcp_connection_num, packet, length);

    if (ret == 0 || direct_send_attempt) {
        return 0;
    }

    return -1;
}

/* Returns true if we have a direct connection with this group connection */
bool gcc_connection_is_direct(const Mono_Time *mono_time, const GC_Connection *gconn)
{
    return ((GCC_UDP_DIRECT_TIMEOUT + gconn->last_recv_direct_time) > mono_time_get(mono_time));
}

/* called when a peer leaves the group */
void gcc_peer_cleanup(GC_Connection *gconn)
{
    size_t i;

    for (i = 0; i < GCC_BUFFER_SIZE; ++i) {
        if (gconn->send_ary[i].data) {
            free(gconn->send_ary[i].data);
        }

        if (gconn->recv_ary[i].data) {
            free(gconn->recv_ary[i].data);
        }
    }

    memset(gconn, 0, sizeof(GC_Connection));
}

/* called on group exit */
void gcc_cleanup(GC_Chat *chat)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (&chat->gcc[i]) {
            gcc_peer_cleanup(&chat->gcc[i]);
        }
    }

    free(chat->gcc);
    chat->gcc = nullptr;
}

#endif /* VANILLA_NACL */
