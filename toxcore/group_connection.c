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
static void rm_from_ary(struct GC_Message_Ary *ary, uint32_t idx)
{
    free(ary[idx].data);
    memset(&ary[idx], 0, sizeof(struct GC_Message_Ary));
}

/* Returns the index of the first empty slot in send_ary.
 * Returns -1 if ary is full
 */
static int get_new_send_ary_index(struct GC_Message_Ary *ary)
{
    if (!ary)
        return -1;

    size_t i;

    for (i = 0; i < GCC_BUFFER_SIZE; ++i) {
        if (ary[i].data == NULL) {
            return i;
        }
    }

    return -1;
}

/* Returns an empty index for recv_ary.
 * Returns -1 if slot is already in use (this indicates a connection problem).
 */
static int get_new_recv_ary_index(GC_Connection *gconn, uint64_t message_id)
{
    if (!gconn)
        return -1;

    uint16_t idx = message_id % GCC_BUFFER_SIZE;

    if (gconn->recv_ary[idx].data != NULL)
        return -1;

    return idx;
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

    ary[idx].data = malloc(sizeof(uint8_t) * length);

    if (ary[idx].data == NULL)
        return -1;

    memcpy(ary[idx].data, data, length);
    ary[idx].data_length = length;
    ary[idx].packet_type = packet_type;
    ary[idx].message_id = message_id;
    ary[idx].time_queued = unix_time();
    ary[idx].last_send_try = unix_time();

    return 0;
}

/* Adds data of length to peernum's send_ary.
 *
 * Returns 0 on success and increments peernum's send_message_id.
 * Returns -1 on failure.
 */
int gcc_add_send_ary(GC_Chat *chat, const uint8_t *data, uint32_t length, uint32_t peernum,
                     uint8_t packet_type, uint64_t message_id)
{
    GC_Connection *gconn = &chat->gcc[peernum];

    if (!gconn)
        return -1;

    if (!LOSSLESS_PACKET(packet_type))
        return -1;

    int idx = get_new_send_ary_index(gconn->send_ary);

    if (idx == -1)
        return -1;

    if (add_to_ary(gconn->send_ary, data, length, packet_type, message_id, idx) == -1)
        return -1;

    fprintf(stderr, "added send_message_id %llu to array\n", message_id);
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
    size_t i;

    for (i = 0; i < GCC_BUFFER_SIZE; ++i) {
        if (gconn->send_ary[i].message_id == message_id) {
            fprintf(stderr, "handled ack for %llu\n", message_id);
            rm_from_ary(gconn->send_ary, i);
            return 0;
        }
    }

    return -1;
}

/* Decides if message need to be put in recv_ary or immediately handled.
 *
 * Return 1 if message is in correct sequence and may be handled immediately.
 * Return 0 if message is a duplicate or put in ary.
 * Return -1 on failure
 */
int gcc_handle_recv_message(GC_Chat *chat, uint32_t peernum, const uint8_t *data, uint32_t length,
                            uint8_t packet_type, uint64_t message_id)
{
    GC_Connection *gconn = &chat->gcc[peernum];

    if (!gconn)
        return -1;

    /* Appears to be a duplicate packet so we ack and discard it */
    if (message_id < gconn->recv_message_id + 1)
        return 0;

    /* we're missing an older message from this peer so we store it in recv_ary */
    if (message_id > gconn->recv_message_id + 1) {
        int idx = get_new_recv_ary_index(gconn, message_id);

        if (idx == -1)
            return -2;

        if (add_to_ary(gconn->recv_ary, data, length, packet_type, message_id, idx) == -1)
            return -3;

        return 0;
    }

    ++gconn->recv_message_id;

    return 1;
}

/* Handles peernum's recv_ary message at idx with appropriate handler and removes from it. */
static void process_recv_ary_item(GC_Chat *chat, Messenger *m, int groupnum, uint32_t peernum, size_t idx)
{
    GC_Connection *gconn = &chat->gcc[peernum];

    const uint8_t *client_id = chat->group[peernum].client_id;
    const uint8_t *data = gconn->recv_ary[idx].data;
    uint32_t length = gconn->recv_ary[idx].data_length;

    switch (gconn->recv_ary[idx].packet_type) {
        case GP_BROADCAST:
            handle_gc_broadcast(m, groupnum, chat->group[peernum].ip_port, client_id, peernum, data, length);
            break;
        case GP_SYNC_REQUEST:
            handle_gc_sync_request(m, groupnum, client_id, peernum, data, length);
            break;
        case GP_SYNC_RESPONSE:
            handle_gc_sync_response(m, groupnum, client_id, data, length);
            break;
    }

    ++gconn->recv_message_id;
    rm_from_ary(gconn->recv_ary, idx);
}

/* Checks for and handles messages that are in proper sequence in peernum's recv_ary.
 * This should always be called after a new packet is successfully handled.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gcc_check_recv_ary(Messenger *m, int groupnum, int peernum)
{
    if (peernum < 0)
        return -1;

    GC_Chat *chat = gc_get_group(m->group_handler, groupnum);

    if (!chat)
        return -1;

    GC_Connection *gconn = &chat->gcc[peernum];

    if (!gconn)
        return -1;

    uint64_t idx = (gconn->recv_message_id + 1) % GCC_BUFFER_SIZE;

    while (gconn->recv_ary[idx].data != NULL) {
        process_recv_ary_item(chat, m, groupnum, peernum, idx);
        idx = (gconn->recv_message_id + 1) % GCC_BUFFER_SIZE;
    }

    return 0;
}

void gcc_do_connection(GC_Chat *chat, uint32_t peernum)
{
    GC_Connection *gconn = &chat->gcc[peernum];

    if (!gconn)
        return;

    size_t i;

    for (i = 0; i < GCC_BUFFER_SIZE; ++i) {
        if (!gconn->send_ary[i].data)
            continue;

        uint64_t t = unix_time();

        if (t == gconn->send_ary[i].last_send_try)
            continue;

        uint64_t j, delta = gconn->send_ary[i].last_send_try - gconn->send_ary[i].time_queued;

        // TODO: this is temporary
        for (j = 1; j <= 256 && delta <= j; j *= 2) {
            if (delta == j) {
                sendpacket(chat->net, chat->group[peernum].ip_port, gconn->send_ary[i].data, gconn->send_ary[i].data_length);
                fprintf(stderr, "resending %llu to peer %llu\n", gconn->send_ary[i].message_id, peernum);
                break;
            }
        }

        gconn->send_ary[i].last_send_try = t;
    }
}

/* called when a peer leaves the group */
void gcc_peer_cleanup(GC_Connection *gconn)
{
    size_t i;

    for (i = 0; i < GCC_BUFFER_SIZE; ++i) {
        if (gconn->send_ary[i].data)
            free(gconn->send_ary[i].data);

        if (gconn->recv_ary[i].data)
            free(gconn->recv_ary[i].data);
    }
}

/* called on group exit */
void gcc_cleanup(GC_Chat *chat)
{
    size_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (&chat->gcc[i])
            gcc_peer_cleanup(&chat->gcc[i]);
    }

    free(chat->gcc);
}
