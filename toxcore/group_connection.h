/* group_connection.h
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

#ifndef GROUP_CONNECTION_H
#define GROUP_CONNECTION_H

#include "group_chats.h"

#define GCC_BUFFER_SIZE 8192    /* must fit inside an uint16 */

/* The time before the direct UDP connection is considered dead */
#define GCC_UDP_DIRECT_TIMEOUT (GC_PING_INTERVAL * 2 + 2)

struct GC_Message_Ary {
    uint8_t *data;
    uint32_t data_length;
    uint8_t  packet_type;
    uint64_t message_id;
    uint64_t time_added;
    uint64_t last_send_try;
};

typedef struct GC_Connection {
    uint64_t send_message_id;   /* message_id of the next message we send to peer */

    uint16_t send_ary_start;   /* send_ary index of oldest item */
    struct GC_Message_Ary send_ary[GCC_BUFFER_SIZE];

    uint64_t recv_message_id;   /* message_id of peer's last message to us */
    struct GC_Message_Ary recv_ary[GCC_BUFFER_SIZE];

    GC_PeerAddress   addr;   /* holds peer's extended real public key and ip_port */
    uint32_t    public_key_hash;   /* hash of peer's real encryption public key */
    uint8_t     session_public_key[ENC_PUBLIC_KEY];   /* self session public key for this peer */
    uint8_t     session_secret_key[ENC_SECRET_KEY];   /* self session secret key for this peer */
    uint8_t     shared_key[crypto_box_BEFORENMBYTES];  /* made with our session sk and peer's session pk */

    int         tcp_id;
    int         tcp_connection_num;
    uint64_t    last_recv_direct_time;   /* the last time we received a direct packet from this peer */

    uint64_t    last_rcvd_ping;
    uint64_t    peer_sync_timer;
    uint64_t    time_added;
    bool        pending_sync_request;
    bool        ignore;
    bool        handshaked; /* true if we've successfully handshaked with this peer */
    bool        confirmed;  /* true if this peer has given us their info */
} GC_Connection;


/* Adds data of length to peernum's send_ary.
 *
 * Returns 0 on success and increments peernum's send_message_id.
 * Returns -1 on failure.
 */
int gcc_add_send_ary(GC_Chat *chat, const uint8_t *data, uint32_t length, uint32_t peernum,
                     uint8_t packet_type);

/* Decides if message need to be put in recv_ary or immediately handled.
 *
 * Return 2 if message is in correct sequence and may be handled immediately.
 * Return 1 if packet is out of sequence and added to recv_ary.
 * Return 0 if message is a duplicate.
 * Return -1 on failure
 */
int gcc_handle_recv_message(GC_Chat *chat, uint32_t peernum, const uint8_t *data, uint32_t length,
                            uint8_t packet_type, uint64_t message_id);

/* Returns ary index for message_id */
uint16_t get_ary_index(uint64_t message_id);

/* Removes send_ary item with message_id.
 *
 * Returns 0 if success.
 * Returns -1 on failure.
 */
int gcc_handle_ack(GC_Connection *gconn, uint64_t message_id);

/* Checks for and handles messages that are in proper sequence in peernum's recv_ary.
 * This should always be called after a new packet is successfully handled.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gcc_check_recv_ary(Messenger *m, int groupnum, uint32_t peernum);

void gcc_resend_packets(Messenger *m, GC_Chat *chat, uint32_t peernumber);

/* Returns a new unique TCP connection id for peers. */
int gcc_new_connection_id(const GC_Chat *chat);

/* Returns true if we have a direct connection with this group connection */
bool gcc_connection_is_direct(const GC_Connection *gconn);

/* Sends a packet to the peer associated with gconn.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int gcc_send_group_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *packet,
                          uint16_t length, uint8_t packet_type);

/* called when a peer leaves the group */
void gcc_peer_cleanup(GC_Connection *gconn);

/* called on group exit */
void gcc_cleanup(GC_Chat *chat);

#endif  /* GROUP_CONNECTION_H */
