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
#define GROUP_CLOSE_CONNECTIONS 6
#define TIME_STAMP (sizeof(uint64_t))

// CERT_TYPE + INVITEE + TIME_STAMP + INVITEE_SIGNATURE + INVITER + TIME_STAMP + INVITER_SIGNATURE
#define INVITE_CERTIFICATE_SIGNED_SIZE (1 + EXT_PUBLIC_KEY + TIME_STAMP + SIGNATURE_SIZE + EXT_PUBLIC_KEY + TIME_STAMP + SIGNATURE_SIZE)
#define SEMI_INVITE_CERTIFICATE_SIGNED_SIZE (1 + EXT_PUBLIC_KEY + TIME_STAMP + SIGNATURE_SIZE)
// CERT_TYPE + TARGET + SOURCE + TIME_STAMP + SOURCE_SIGNATURE 
#define COMMON_CERTIFICATE_SIGNED_SIZE (1 + EXT_PUBLIC_KEY + EXT_PUBLIC_KEY + TIME_STAMP + SIGNATURE_SIZE)

#define MAX_CERTIFICATES_NUM 5

// Certificates types
#define CERT_INVITE 0
#define CERT_BAN 1
#define CERT_OP_CREDENTIALS 2

// Roles
#define FOUNDER_ROLE 0
#define OP_ROLE 1
#define USER_ROLE 2
#define HUMAN_ROLE 3
#define ELF_ROLE 4
#define DWARF_ROLE 5

// Statuses
#define ONLINE_STATUS 0
#define ONFFLINE_STATUS 1
#define AWAY_STATUS 2
#define BUSY_STATUS 3

typedef struct {
    uint8_t     client_id[EXT_PUBLIC_KEY];
    uint8_t     invite_certificate[INVITE_CERTIFICATE_SIGNED_SIZE];
    uint8_t     common_certificate[COMMON_CERTIFICATE_SIGNED_SIZE][MAX_CERTIFICATES_NUM];

    IP_Port     ip_port;

    uint8_t     nick[MAX_NICK_BYTES];
    uint16_t    nick_len;

    uint8_t     banned;
    uint64_t    banned_time;

    uint8_t     status; // online, offline, dead etc.

    uint8_t     verified; // is peer verified, e.g. was invited by verified peer. Recursion. Problems?

    uint8_t     role; // actually, user could have several roles, so, it's better to reimplement it as array
} Group_Peer;

typedef struct {
    // Maybe create separate struct
    uint8_t     client_id[EXT_PUBLIC_KEY];
    IP_Port     ip_port;
} Group_Close;

typedef struct Group_Chat {
    Networking_Core *net;

    uint8_t     self_public_key[EXT_PUBLIC_KEY];
    uint8_t     self_secret_key[EXT_SECRET_KEY];
    uint8_t     self_invite_certificate[INVITE_CERTIFICATE_SIGNED_SIZE];
    uint8_t     self_common_certificate[MAX_CERTIFICATES_NUM][COMMON_CERTIFICATE_SIGNED_SIZE];

    Group_Peer  *group;
    Group_Close close[GROUP_CLOSE_CONNECTIONS];
    uint32_t    numpeers;

    uint8_t     self_nick[MAX_NICK_BYTES];
    uint16_t    self_nick_len;
    uint8_t     self_role;

    uint8_t     chat_public_key[EXT_PUBLIC_KEY];
    uint8_t     founder_public_key[EXT_PUBLIC_KEY]; // not sure about it, invitee somehow needs to check it
} Group_Chat;

typedef struct {
    uint8_t     client_id[EXT_PUBLIC_KEY];
    uint8_t     role;    
} Group_OPs;

// For founder needs
typedef struct Group_Credentials {
    uint8_t     chat_public_key[EXT_PUBLIC_KEY];
    uint8_t     chat_secret_key[EXT_SECRET_KEY];
    uint64_t    creation_time;

    Group_OPs   *ops;
} Group_Credentials;


int sign_certificate(const uint8_t *data, uint32_t length, const uint8_t *private_key, const uint8_t *public_key, uint8_t *certificate);
int make_invite_cert(const uint8_t *private_key, const uint8_t *public_key, uint8_t *half_certificate);
int make_common_cert(const uint8_t *private_key, const uint8_t *public_key, const uint8_t *target_pub_key, uint8_t *certificate, const uint8_t cert_type);
int verify_cert_integrity(const uint8_t *certificate);
int process_invite_cert(const Group_Chat *chat, const uint8_t *certificate);
int process_common_cert(const Group_Chat *chat, const uint8_t *certificate);
int send_invite_request(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key);
int send_invite_response(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                         const uint8_t *data, uint32_t length);



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

/* Kill a group chat credentials
 * Frees the memory and everything.
 */
void kill_groupcredentials(Group_Credentials *credentials);

#endif