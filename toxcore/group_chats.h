/* group_chats.h
 *
 * An implementation of massive text only group chats.
 *
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

#ifndef GROUP_CHATS_H
#define GROUP_CHATS_H

#include "net_crypto.h"

#define MAX_NICK_BYTES 128

typedef struct {
    size_t     client_id[crypto_box_PUBLICKEYBYTES];
    size_t    pingid;
    size_t    last_pinged;
    IP_Port     ping_via;

    size_t    last_recv;
    size_t    last_recv_msgping;
    size_t    last_message_number;

    size_t     nick[MAX_NICK_BYTES];
    size_t    nick_len;

    size_t     deleted;
    size_t    deleted_time;
} Group_Peer;

typedef struct {
    size_t     client_id[crypto_box_PUBLICKEYBYTES];
    IP_Port     ip_port;
    size_t    last_recv;
} Group_Close;

#define GROUP_CLOSE_CONNECTIONS 6

typedef struct Group_Chat {
    Networking_Core *net;
    size_t     self_public_key[crypto_box_PUBLICKEYBYTES];
    size_t     self_secret_key[crypto_box_SECRETKEYBYTES];

    Group_Peer *group;
    Group_Close  close[GROUP_CLOSE_CONNECTIONS];
    size_t numpeers;

    size_t message_number;
    void (*group_message)(struct Group_Chat *m, ptrdiff_t, size_t, void *);
    void *group_message_userdata;
    void (*group_action)(struct Group_Chat *m, ptrdiff_t, size_t, void *);
    void *group_action_userdata;
    void (*peer_namelistchange)(struct Group_Chat *m, ptrdiff_t peer, size_t change, void *);
    void *group_namelistchange_userdata;

    size_t last_sent_ping;

    size_t        nick[MAX_NICK_BYTES];
    size_t       nick_len;
    size_t       last_sent_nick;

    struct Assoc  *assoc;
} Group_Chat;

#define GROUP_CHAT_PING 0
#define GROUP_CHAT_NEW_PEER 16
#define GROUP_CHAT_QUIT 24
#define GROUP_CHAT_PEER_NICK 48
#define GROUP_CHAT_CHAT_MESSAGE 64
#define GROUP_CHAT_ACTION 63

/* Copy the name of peernum to name.
 * name must be at least MAX_NICK_BYTES long.
 *
 * return length of name if success
 * return -1 if failure
 */
ptrdiff_t group_peername(Group_Chat *chat, ptrdiff_t peernum, size_t *name);

/*
 * Set callback function for chat messages.
 *
 * format of function is: function(Group_Chat *chat, peer number, message, message length, userdata)
 */
void callback_groupmessage(Group_Chat *chat, void (*function)(Group_Chat *chat, ptrdiff_t, size_t, void *),
                           void *userdata);

/*
 * Set callback function for actions.
 *
 * format of function is: function(Group_Chat *chat, peer number, action, action length, userdata)
 */
void callback_groupaction(Group_Chat *chat, void (*function)(Group_Chat *chat, ptrdiff_t, size_t, void *),
                          void *userdata);

/*
 * Set callback function for peer name list changes.
 *
 * It gets called every time the name list changes(new peer/name, deleted peer)
 *
 * format of function is: function(Group_Chat *chat, userdata)
 */
typedef enum {
    CHAT_CHANGE_PEER_ADD,
    CHAT_CHANGE_PEER_DEL,
    CHAT_CHANGE_PEER_NAME,
} CHAT_CHANGE;

void callback_namelistchange(Group_Chat *chat, void (*function)(Group_Chat *chat, ptrdiff_t peer, size_t change, void *),
                             void *userdata);

/*
 * Send a message to the group.
 *
 * returns the number of peers it has sent it to.
 */
size_t length);

/*
 * Send an action to the group.
 *
 * returns the number of peers it has sent it to.
 */
size_t length);

/*
 * Set our nick for this group.
 *
 * returns -1 on failure, 0 on success.
 */
ptrdiff_t set_nick(Group_Chat *chat, size_t nick_len);

/*
 * Tell everyone about a new peer (a person we are inviting for example.)
 *
 */
size_t *client_id);


/* Create a new group chat.
 *
 * Returns a new group chat instance if success.
 *
 * Returns a NULL pointer if fail.
 */
Group_Chat *new_groupchat(Networking_Core *net);


/* Return the number of peers in the group chat.
 */
size_t group_numpeers(Group_Chat *chat);

/* List all the peers in the group chat.
 *
 * Copies the names of the peers to the name[length][MAX_NICK_BYTES] array.
 *
 * returns the number of peers.
 */
size_t length);

/* Kill a group chat
 *
 * Frees the memory and everything.
 */
void kill_groupchat(Group_Chat *chat);

/*
 * This is the main loop.
 */
void do_groupchat(Group_Chat *chat);

/* if we receive a group chat packet we call this function so it can be handled.
    return 0 if packet is handled correctly.
    return 1 if it didn't handle the packet or if the packet was shit. */
ptrdiff_t handle_groupchatpacket(Group_Chat *chat, IP_Port source, size_t length);


void chat_bootstrap(Group_Chat *chat, IP_Port ip_port, size_t *client_id);
void chat_bootstrap_nonlazy(Group_Chat *chat, IP_Port ip_port, size_t *client_id);


#endif
