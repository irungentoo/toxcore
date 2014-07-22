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

#define MAX_NICK_BYTES 128
#define MAX_ROLE_BYTES 128
#define GROUP_CLOSE_CONNECTIONS 6
#define SIGNATURE_SIZE  64

// Invitee_ID + Inviter_ID + timestamp + Invitee_Signature + Inviter_Signature
#define CERTIFICATE_SIZE (CLIENT_ID_EXT_SIZE + CLIENT_ID_EXT_SIZE + sizeof(uint64_t) + SIGNATURE_SIZE + SIGNATURE_SIZE)

// Roles
#define FOUNDER_ROLE 0
#define OP_ROLE 1
#define USER_ROLE 2
#define HUMAN_ROLE 3
#define ELF_ROLE 4
#define DWARF_ROLE 5

typedef struct {
    uint8_t     client_id[CLIENT_ID_EXT_SIZE];
    uint8_t     certificate[CERTIFICATE_SIZE];

    IP_Port     ip_port;

    uint8_t     nick[MAX_NICK_BYTES];
    uint16_t    nick_len;

    uint8_t     banned;
    uint64_t    banned_time;

    uint8_t     role;
} Group_Peer;

typedef struct {
    // Maybe create separate struct
    uint8_t     client_id[CLIENT_ID_EXT_SIZE];
    IP_Port     ip_port;
} Group_Close;

typedef struct Group_Chat {
    Networking_Core *net;

    uint8_t     self_public_key[CLIENT_ID_EXT_SIZE];
    uint8_t     self_secret_key[CLIENT_ID_EXT_SIZE]; //could be longer...
    uint8_t     self_certificate[CERTIFICATE_SIZE];

    Group_Peer  *group;
    Group_Close close[GROUP_CLOSE_CONNECTIONS];
    uint32_t    numpeers;

    uint8_t     self_nick[MAX_NICK_BYTES];
    uint16_t    self_nick_len;
    uint8_t     self_role;

    uint8_t     chat_public_key[CLIENT_ID_EXT_SIZE];
    uint8_t     founder_public_key[CLIENT_ID_EXT_SIZE]; // not sure about it, invitee somehow needs to check it
} Group_Chat;

typedef struct {
    uint8_t     client_id[CLIENT_ID_EXT_SIZE];
    uint8_t     role;    
} Group_OPs;

// For founder needs
typedef struct Group_Credentials {
    uint8_t     chat_public_key[CLIENT_ID_EXT_SIZE];
    uint8_t     chat_secret_key[CLIENT_ID_EXT_SIZE];
    uint64_t    creation_time;

    Group_OPs   *ops;
} Group_Credentials;


/* Send a message to the group.
 * returns the number of peers it has sent it to.
 */
//uint32_t group_sendmessage(Group_Chat *chat, const uint8_t *message, uint32_t length);

/* Send an action to the group.
 * returns the number of peers it has sent it to.
 */
//uint32_t group_sendaction(Group_Chat *chat, const uint8_t *action, uint32_t length);

/* Set our nick for this group.
 * returns -1 on failure, 0 on success.
 */
//int set_nick(Group_Chat *chat, const uint8_t *nick, uint16_t nick_len);

/* Tell everyone about a new peer (a person we are inviting for example.)
 */
//uint32_t group_newpeer(Group_Chat *chat, const uint8_t *client_id);

/* Return the number of peers in the group chat.
 */
//uint32_t group_numpeers(const Group_Chat *chat);

/* List all the peers in the group chat.
 * Copies the names of the peers to the name[length][MAX_NICK_BYTES] array.
 * returns the number of peers.
 */
//uint32_t group_client_names(const Group_Chat *chat, uint8_t names[][MAX_NICK_BYTES], uint16_t lengths[], uint16_t length);

/* If we receive a group chat packet we call this function so it can be handled.
 * return 0 if packet is handled correctly.
 * return -1 if it didn't handle the packet or if the packet was shit.
*/
int handle_groupchatpacket(void * _chat, IP_Port source, const uint8_t *packet, uint32_t length);

/* Create new group credentials with pk ans sk.
 * Returns a new group credentials instance if success.
 * Returns a NULL pointer if fail.
 */
Group_Credentials *new_groupcredentials();

/* Create a new group chat.
 * Returns a new group chat instance if success.
 * Returns a NULL pointer if fail.
 */
Group_Chat *new_groupchat(Networking_Core *net);

/* Kill a group chat
 * Frees the memory and everything.
 */
void kill_groupchat(Group_Chat *chat);

/* This is the main loop.
 */
//void do_groupchat(Group_Chat *chat);


#endif