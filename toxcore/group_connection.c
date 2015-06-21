/* group_connection.c
 *
 * An implementation of massive text only group chats.
 *
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
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

#include "DHT.h"
#include "network.h"
#include "group_connection.h"
#include "group_chats.h"
#include "Messenger.h"
#include "util.h"

/* Removes idx ary item.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static void rm_from_ary(struct GC_Message_Ary *ary, uint16_t idx)
{
    free(ary[idx].data);
    memset(&ary[idx], 0, sizeof(struct GC_Message_Ary));
}

/* Returns ary index for message_id */
uint16_t get_ary_index(uint64_t message_id)
{
    return message_id % GCC_BUFFER_SIZE;
}

/* Adds a group message to ary.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int add_to_ary(struct GC_Message_Ary *ary, const uint8_t *data, uint32_t length,
                      uint8_t packet_type, uint64_t message_id, uint16_t idx)
{
    if (!data || !length)
        return -1;

    if (!ary)
        return -1;

    ary[idx].data = malloc(sizeof(uint8_t) * length);

    if (ary[idx].data == NULL)
        return -1;

    memcpy(ary[idx].data, data, length);
    ary[idx].data_length = length;
    ary[idx].packet_type = packet_type;
    ary[idx].message_id = message_id;
    ary[idx].time_added = unix_time();
    ary[idx].last_send_try = unix_time();

    return 0;
}

/* Adds data of length to peernum's send_ary.
 *
 * Returns 0 on success and increments peernum's send_message_id.
 * Returns -1 on failure.
 */
int gcc_add_send_ary(GC_Chat *chat, const uint8_t *data, uint32_t length, uint32_t peernum,
                     uint8_t packet_type)
{
    GC_Connection *gconn = &chat->gcc[peernum];

    if (!gconn)
        return -1;

    /* check if send_ary is full */
    if ((gconn->send_message_id % GCC_BUFFER_SIZE) == (uint16_t) (gconn->send_ary_start - 1))
        return -1;

    uint16_t idx = get_ary_index(gconn->send_message_id);

    if (gconn->send_ary[idx].data != NULL)
        return -1;

    if (add_to_ary(gconn->send_ary, data, length, packet_type, gconn->send_message_id, idx) == -1)
        return -1;

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
    if (!gconn)
        return -1;

    uint16_t idx = get_ary_index(message_id);

    if (gconn->send_ary[idx].data == NULL)
        return -1;

    if (gconn->send_ary[idx].message_id != message_id)  // wrap-around indicates a connection problem
        return -1;

    rm_from_ary(gconn->send_ary, idx);

    /* Put send_ary_start in proper position */
    if (idx == gconn->send_ary_start) {
        uint16_t end = gconn->send_message_id % GCC_BUFFER_SIZE;

        while (gconn->send_ary[idx].data == NULL && gconn->send_ary_start != end) {
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
int gcc_handle_recv_message(GC_Chat *chat, uint32_t peernum, const uint8_t *data, uint32_t length,
                            uint8_t packet_type, uint64_t message_id)
{
    GC_Connection *gconn = &chat->gcc[peernum];

    if (!gconn)
        return -1;

    /* Appears to be a duplicate packet so we discard it */
    if (message_id < gconn->recv_message_id + 1)
        return 0;

    /* we're missing an older message from this peer so we store it in recv_ary */
    if (message_id > gconn->recv_message_id + 1) {
        uint16_t idx = get_ary_index(message_id);

        if (gconn->recv_ary[idx].data != NULL)
            return -1;

        if (add_to_ary(gconn->recv_ary, data, length, packet_type, message_id, idx) == -1)
            return -1;

        return 1;
    }

    ++gconn->recv_message_id;

    return 2;
}

/* Handles peernum's recv_ary message at idx with appropriate handler and removes from it. */
static int process_recv_ary_item(GC_Chat *chat, Messenger *m, int groupnum, uint32_t peernum, uint16_t idx)
{
    GC_Connection *gconn = &chat->gcc[peernum];

    if (!gconn)
        return -1;

    const uint8_t *public_key = gconn->addr.public_key;
    const uint8_t *data = gconn->recv_ary[idx].data;
    uint32_t length = gconn->recv_ary[idx].data_length;

    int ret = handle_gc_lossless_helper(m, groupnum, peernum, data, length, gconn->recv_ary[idx].message_id,
                                        gconn->recv_ary[idx].packet_type);
    rm_from_ary(gconn->recv_ary, idx);

    if (ret == -1) {
        gc_send_message_ack(chat, peernum, 0, gconn->recv_ary[idx].message_id);
        return -1;
    }

    gc_send_message_ack(chat, peernum, gconn->recv_ary[idx].message_id, 0);
    ++gconn->recv_message_id;

    return ret;
}

/* Checks for and handles messages that are in proper sequence in peernum's recv_ary.
 * This should always be called after a new packet is handled in correct sequence.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gcc_check_recv_ary(Messenger *m, int groupnum, uint32_t peernum)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnum);

    if (!chat)
        return -1;

    GC_Connection *gconn = &chat->gcc[peernum];

    if (!gconn)
        return -1;

    uint16_t idx = (gconn->recv_message_id + 1) % GCC_BUFFER_SIZE;

    while (gconn->recv_ary[idx].data != NULL) {
        if (process_recv_ary_item(chat, m, groupnum, peernum, idx) == -1)
            return -1;

        idx = (gconn->recv_message_id + 1) % GCC_BUFFER_SIZE;
    }

    return 0;
}

void gcc_resend_packets(Messenger *m, GC_Chat *chat, uint32_t peernum)
{
    GC_Connection *gconn = &chat->gcc[peernum];

    if (!gconn)
        return;

    uint64_t tm = unix_time();
    uint16_t i, start = gconn->send_ary_start, end = gconn->send_message_id % GCC_BUFFER_SIZE;

    for (i = start; i != end; i = (i + 1) % GCC_BUFFER_SIZE) {
        if (gconn->send_ary[i].data == NULL)
            continue;

        if (tm == gconn->send_ary[i].last_send_try)
            continue;

        uint64_t delta = gconn->send_ary[i].last_send_try - gconn->send_ary[i].time_added;
        gconn->send_ary[i].last_send_try = tm;

        /* if this occurrs less than once per second this won't be reliable */
        if (delta > 1 && POWER_OF_2(delta)) {
            gcc_send_group_packet(chat, gconn, gconn->send_ary[i].data, gconn->send_ary[i].data_length,
                                  gconn->send_ary[i].packet_type);
            continue;
        }

        if (is_timeout(gconn->send_ary[i].time_added, GC_CONFIRMED_PEER_TIMEOUT)) {
            gc_peer_delete(m, chat->groupnumber, peernum, (uint8_t *) "Peer timed out", 14);
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
    if (!packet || length == 0)
        return -1;

    if (!gconn)
        return -1;

    bool direct_send_attempt = false;

    if (gconn->addr.ip_port.ip.family != 0) {
        if (gcc_connection_is_direct(gconn)) {
            if ((uint16_t) sendpacket(chat->net, gconn->addr.ip_port, packet, length) == length)
                return 0;

            return -1;
        }

        if (packet_type != GP_BROADCAST && packet_type != GP_MESSAGE_ACK) {
            if ((uint16_t) sendpacket(chat->net, gconn->addr.ip_port, packet, length) == length)
                direct_send_attempt = true;
        }
    }

    int ret = send_packet_tcp_connection(chat->tcp_conn, gconn->tcp_connection_num, packet, length);

    if (ret == -1)
        fprintf(stderr, "send_packet_tcp_connection failed in gcc_send_group_packet\n");

    if (ret == 0 || direct_send_attempt)
        return 0;

    return -1;
}

/* Returns true if we have a direct connection with this group connection */
bool gcc_connection_is_direct(const GC_Connection *gconn)
{
    if (!gconn)
        return false;

    return ((GCC_UDP_DIRECT_TIMEOUT + gconn->last_recv_direct_time) > unix_time());
}

/* Adds tcp relays for group peer connection.
 *
 * Returns the number of relays added on success.
 * Returns -1 on failure.
 */
int gcc_add_peer_tcp_relays(GC_Chat *chat, GC_Connection *gconn, const uint8_t *nodes_data, uint16_t length)
{
    if (!gconn)
        return -1;

    if (length == 0)
        return 0;

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    int num_nodes = unpack_nodes(tcp_relays, GCC_MAX_TCP_SHARED_RELAYS, NULL, nodes_data, length, 1);

    if (num_nodes == -1)
        return -1;

    int i;

    for (i = 0; i < num_nodes; ++i)
        add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, tcp_relays[i].ip_port,
                                 tcp_relays[i].public_key);

    return num_nodes;
}

/* called when a peer leaves the group */
void gcc_peer_cleanup(GC_Connection *gconn)
{
    if (!gconn)
        return;

    size_t i;

    for (i = 0; i < GCC_BUFFER_SIZE; ++i) {
        if (gconn->send_ary[i].data) {
            free(gconn->send_ary[i].data);
            gconn->send_ary[i].data = NULL;
        }

        if (gconn->recv_ary[i].data) {
            free(gconn->recv_ary[i].data);
            gconn->recv_ary[i].data = NULL;
        }
    }
}

/* called on group exit */
void gcc_cleanup(GC_Chat *chat)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (&chat->gcc[i])
            gcc_peer_cleanup(&chat->gcc[i]);
    }

    free(chat->gcc);
    chat->gcc = NULL;
}
