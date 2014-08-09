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

#include <stdbool.h>

#define MAX_NICK_BYTES 128
#define MAX_TOPIC_BYTES 512
#define GROUP_CLOSE_CONNECTIONS 6
#define GROUP_PING_INTERVAL 5
#define BAD_GROUPNODE_TIMEOUT 60

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
#define FOUNDER_ROLE 1
#define OP_ROLE 2
#define USER_ROLE 4
#define HUMAN_ROLE 8
#define ELF_ROLE 16
#define DWARF_ROLE 32

// Statuses
#define ONLINE_STATUS 0
#define OFFLINE_STATUS 1
#define AWAY_STATUS 2
#define BUSY_STATUS 3

// Messages
#define GROUP_CHAT_PING 0
#define GROUP_CHAT_STATUS 1
#define GROUP_CHAT_NEW_PEER 2
#define GROUP_CHAT_CHANGE_NICK 3
#define GROUP_CHAT_CHANGE_TOPIC 4
#define GROUP_CHAT_MESSAGE 5
#define GROUP_CHAT_ACTION 6

typedef struct {
    uint8_t     client_id[EXT_PUBLIC_KEY];
    IP_Port     ip_port;

    uint8_t     invite_certificate[INVITE_CERTIFICATE_SIGNED_SIZE];
    uint8_t     common_certificate[COMMON_CERTIFICATE_SIGNED_SIZE][MAX_CERTIFICATES_NUM];
    uint32_t    common_cert_num;

    uint8_t     nick[MAX_NICK_BYTES];
    uint16_t    nick_len;

    bool        banned;
    uint64_t    banned_time;

    uint8_t     status; // TODO: enum

    bool        verified; // is peer verified, e.g. was invited by verified peer. Recursion. Problems?

    uint64_t    role;

    uint64_t    last_update_time; // updates when nick, role, verified, ip_port change or banned
    uint64_t    last_rcvd_ping;
} Group_Peer;

typedef struct {
    uint8_t     client_id[EXT_PUBLIC_KEY];
    IP_Port     ip_port;
} Group_Close;

typedef struct Group_Chat {
    Networking_Core *net;

    uint8_t     self_public_key[EXT_PUBLIC_KEY];
    uint8_t     self_secret_key[EXT_SECRET_KEY];
    uint8_t     self_invite_certificate[INVITE_CERTIFICATE_SIGNED_SIZE];
    uint8_t     self_common_certificate[MAX_CERTIFICATES_NUM][COMMON_CERTIFICATE_SIGNED_SIZE];
    uint32_t    self_common_cert_num;

    Group_Peer  *group;
    Group_Close close[GROUP_CLOSE_CONNECTIONS];
    uint32_t    numpeers;

    uint8_t     self_nick[MAX_NICK_BYTES];
    uint16_t    self_nick_len;
    uint64_t    self_role;
    uint8_t     self_status; // TODO: enum

    uint8_t     chat_public_key[EXT_PUBLIC_KEY];
    uint8_t     founder_public_key[EXT_PUBLIC_KEY]; // not sure about it, invitee somehow needs to check it
    uint8_t     topic[MAX_TOPIC_BYTES];
    uint16_t    topic_len;

    uint64_t    last_synced_time;
    uint64_t    last_sent_ping_time;


    uint32_t message_number;
    void (*group_message)(struct Group_Chat *chat, int peernum, const uint8_t *data, uint32_t length, void *userdata);
    void *group_message_userdata;
    void (*group_action)(struct Group_Chat *chat, int peernum, const uint8_t *data, uint32_t length, void *userdata);
    void *group_action_userdata;

} Group_Chat;

typedef struct {
    uint8_t     client_id[EXT_PUBLIC_KEY];
    uint64_t    role;    
} Group_OPs;

// For founder needs
typedef struct Group_Credentials {
    uint8_t     chat_public_key[EXT_PUBLIC_KEY];
    uint8_t     chat_secret_key[EXT_SECRET_KEY];
    uint64_t    creation_time;

    Group_OPs   *ops;
} Group_Credentials;

/* Sign input data
 * Add signer public key, time stamp and signature in the end of the data
 * Return -1 if fail, 0 if success
 */
int sign_certificate(const uint8_t *data, uint32_t length, const uint8_t *private_key, const uint8_t *public_key, uint8_t *certificate);

/* Make invite certificate
 * This cert is only half-done, cause it needs to be signed by inviter also
 * Return -1 if fail, 0 if success
 */
int make_invite_cert(const uint8_t *private_key, const uint8_t *public_key, uint8_t *half_certificate);

/* Make common certificate
 * Return -1 if fail, 0 if success
 */
int make_common_cert(const uint8_t *private_key, const uint8_t *public_key, const uint8_t *target_pub_key, uint8_t *certificate, const uint8_t cert_type);

/* Return -1 if certificate is corrupted
 * Return 0 if certificate is consistent
 * Works for invite and common certificates
 */
int verify_cert_integrity(const uint8_t *certificate);

/* Return -1 if we don't know who signed the certificate
 * Return -2 if cert is signed by chat pk, e.g. in case it is the cert founder created for himself
 * Return peer number in other cases
 * If inviter is verified peer, than invitee becomes verified also
 */ 
int process_invite_cert(const Group_Chat *chat, const uint8_t *certificate);

/* Return -1 if cert isn't issued by ops
 * Return issuer peer number in other cases
 */
int process_common_cert(Group_Chat *chat, const uint8_t *certificate);

// TODO !!!
int process_chain_trust(Group_Chat *chat);

/* Return -1 if fail
 * Return packet length if success
 */
int send_invite_request(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key);

/* Return -1 if fail
 * Return packet length if success
 */
int send_invite_response(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                         const uint8_t *data, uint32_t length);

/* Return -1 if fail
 * Return packet length if success
 */
int send_sync_request(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key);

/* Return -1 if fail
 * Return packet length if success
 */
int send_sync_response(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                         const uint8_t *data, uint32_t length);

int send_ping(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key);

int send_status(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key, uint8_t status_type);

int send_change_nick(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key);

int send_change_topic(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key);

int send_new_peer(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key);

int send_action(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key, const uint8_t *certificate);

int send_message(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key, const uint8_t *message, uint32_t length);

void callback_groupmessage(Group_Chat *chat, void (*function)(Group_Chat *chat, int peernum, const uint8_t *data, uint32_t length, void *userdata),
                           void *userdata);

void callback_groupaction(Group_Chat *chat, void (*function)(Group_Chat *chat, int peernum, const uint8_t *data, uint32_t length, void *userdata),
                          void *userdata);

/* If we receive a group chat packet we call this function so it can be handled.
 * return 0 if packet is handled correctly.
 * return -1 if it didn't handle the packet or if the packet was shit.
 */
int handle_groupchatpacket(void * _chat, IP_Port source, const uint8_t *packet, uint32_t length);

/* Check if peer with client_id is in peer array.
 * return peer number if peer is in chat.
 * return -1 if peer is not in chat.
 * TODO: make this more efficient.
 */
int peer_in_chat(const Group_Chat *chat, const uint8_t *client_id);

int add_peer(Group_Chat *chat, const Group_Peer *peer);
int update_peer(Group_Chat *chat, const Group_Peer *peer, uint32_t peernum);
int gc_to_peer(const Group_Chat *chat, Group_Peer *peer);

/* This is the main loop.
 */
void do_groupchat(Group_Chat *chat);

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