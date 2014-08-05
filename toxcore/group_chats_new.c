/* group_chats.c
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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "DHT.h"
#include "group_chats_new.h"
#include "LAN_discovery.h"
#include "util.h"

#define GC_INVITE_REQUEST_PLAIN_SIZE SEMI_INVITE_CERTIFICATE_SIGNED_SIZE
#define GC_INVITE_REQUEST_DHT_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_INVITE_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

#define GC_INVITE_RESPONSE_PLAIN_SIZE INVITE_CERTIFICATE_SIGNED_SIZE
#define GC_INVITE_RESPONSE_DHT_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_INVITE_RESPONSE_PLAIN_SIZE + crypto_box_MACBYTES)

#define MIN_PACKET_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES)

int unwrap_group_packet(const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key, uint8_t *data,
                   uint8_t *packet_type, const uint8_t *packet, uint16_t length)
{
    if (length < MIN_PACKET_SIZE && length > MAX_CRYPTO_REQUEST_SIZE) 
        return -1;
    
    if (id_long_equal(packet + 1, self_public_key))
        return -1;

    memcpy(public_key, packet + 1, EXT_PUBLIC_KEY);

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, packet + 1 + EXT_PUBLIC_KEY, crypto_box_NONCEBYTES);

    uint8_t plain[MAX_CRYPTO_REQUEST_SIZE];
    int len = decrypt_data(ENC_KEY(public_key), ENC_KEY(self_secret_key), nonce,
                            packet + 1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES,
                            length - (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES), plain);

    if (len == -1 || len == 0)
        return -1;

    packet_type[0] = plain[0];
    --len;
    memcpy(data, plain + 1, len);
    return len;
}

int wrap_group_packet(const uint8_t *send_public_key, const uint8_t *send_secret_key, const uint8_t *recv_public_key,
                        uint8_t *packet, const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    if (MAX_CRYPTO_REQUEST_SIZE < length + MIN_PACKET_SIZE)
        return -1;
    
    uint8_t plain[MAX_CRYPTO_REQUEST_SIZE];
    plain[0] = packet_type;
    memcpy(plain + 1, data, length);
    
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t encrypt[1 + length + crypto_box_MACBYTES];
    int len = encrypt_data(ENC_KEY(recv_public_key), ENC_KEY(send_secret_key), nonce, plain, length + 1, encrypt);
    if (len != sizeof(encrypt))
        return -1;

    packet[0] = NET_PACKET_GROUP_CHATS;
    memcpy(packet + 1, send_public_key, EXT_PUBLIC_KEY);
    memcpy(packet + 1 + EXT_PUBLIC_KEY, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + 1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES, encrypt, len);

    return 1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES + len;
}

int send_groupchatpacket(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                         const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    if (id_long_equal(chat->self_public_key, public_key))
        return -1;

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    int len = wrap_group_packet(chat->self_public_key, chat->self_secret_key, public_key, packet, data, length, packet_type);
    if (len == -1)
        return -1;

    if (sendpacket(chat->net, ip_port, packet, len) == len)
        return 0;

    return -1;
}

int handle_groupchatpacket(void * _chat, IP_Port ipp, const uint8_t *packet, uint32_t length)
{
    Group_Chat *chat = _chat;

    uint8_t public_key[EXT_PUBLIC_KEY];
    uint8_t data[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t packet_type;

    int len = unwrap_group_packet(chat->self_public_key, chat->self_secret_key, public_key, data, &packet_type, packet, length);

    if (len == -1)
        return -1;

    // TODO need to check if we know the person. However in case of invite we don't need this...

    switch (packet_type) {
        case CRYPTO_PACKET_GROUP_CHAT_INVITE_REQUEST:
            return handle_gc_invite_request(chat, ipp, public_key, data, len);

        case CRYPTO_PACKET_GROUP_CHAT_INVITE_RESPONSE:
            return handle_gc_invite_response(chat, ipp, public_key, data, len);

        default:
            return -1;
    }

    return -1;
}

int send_invite_request(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key)
{
    uint8_t  invite_certificate[SEMI_INVITE_CERTIFICATE_SIGNED_SIZE];

    if (make_invite_cert(chat->self_secret_key, chat->self_public_key, invite_certificate)==-1)
        return -1;

    return send_groupchatpacket(chat, ip_port, public_key, invite_certificate,
         SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, CRYPTO_PACKET_GROUP_CHAT_INVITE_REQUEST);
}


int handle_gc_invite_request(Group_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length)
{
    uint8_t  invite_certificate[INVITE_CERTIFICATE_SIGNED_SIZE];

    if (!id_long_equal(public_key, data+1))
        return -1;

    if (data[0]!=CERT_INVITE)
        return -1;

    if (crypto_sign_verify_detached(data+SEMI_INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE,
                data, SEMI_INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE, SIG_KEY(public_key)) != 0)
        return -1;

    if (sign_certificate(data, SEMI_INVITE_CERTIFICATE_SIGNED_SIZE,
            chat->self_secret_key, chat->self_public_key, invite_certificate) == -1)
        return -1;

    // Adding peer we just invited into the peer group list
    Group_Peer *peer = calloc(1, sizeof(Group_Peer));
    memcpy(peer->client_id, public_key, EXT_PUBLIC_KEY);
    memcpy(peer->invite_certificate, invite_certificate, INVITE_CERTIFICATE_SIGNED_SIZE);
    peer->role |= USER_ROLE;
    peer->verified = 1;
    add_peer(chat, peer);

    return send_invite_response(chat, ipp, public_key, invite_certificate, INVITE_CERTIFICATE_SIGNED_SIZE);
}

int send_invite_response(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                         const uint8_t *data, uint32_t length)
{
    return send_groupchatpacket(chat, ip_port, public_key, data,
        length, CRYPTO_PACKET_GROUP_CHAT_INVITE_RESPONSE);
}

int handle_gc_invite_response(Group_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length)
{
    if (!id_long_equal(public_key, data+SEMI_INVITE_CERTIFICATE_SIGNED_SIZE))
        return -1;

    if (data[0]!=CERT_INVITE)
        return -1;

    if (crypto_sign_verify_detached(data+INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE,
                 data, INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE, SIG_KEY(public_key)) != 0)
        return -1;

    memcpy(chat->self_invite_certificate, data, INVITE_CERTIFICATE_SIGNED_SIZE);

    // send_sync_request();
    return 0;
}

int sign_certificate(const uint8_t *data, uint32_t length, const uint8_t *private_key, const uint8_t *public_key, uint8_t *certificate)
{
    memcpy(certificate, data, length);
    memcpy(certificate + length, public_key, EXT_PUBLIC_KEY);

    unix_time_update(); 
    U64_to_bytes(certificate + length + EXT_PUBLIC_KEY, unix_time());
    uint32_t mlen = length + EXT_PUBLIC_KEY + TIME_STAMP;

    if (crypto_sign_detached(certificate+mlen, NULL, certificate, mlen, SIG_KEY(private_key)) != 0)
        return -1;
    
    return 0;
}

int make_invite_cert(const uint8_t *private_key, const uint8_t *public_key, uint8_t *half_certificate)
{
    uint8_t buf[COMMON_CERTIFICATE_SIGNED_SIZE];
    buf[0] = CERT_INVITE;
    return sign_certificate(buf, 1, private_key, public_key, half_certificate);
}

int make_common_cert(const uint8_t *private_key, const uint8_t *public_key, const uint8_t *target_pub_key, uint8_t *certificate, const uint8_t cert_type)
{
    uint8_t buf[COMMON_CERTIFICATE_SIGNED_SIZE];
    buf[0] = cert_type;
    memcpy(buf + 1, target_pub_key, EXT_PUBLIC_KEY);

    return sign_certificate(buf, 1 + EXT_PUBLIC_KEY, private_key, public_key, certificate);
}

// Return -1 if certificate is corrupted
// Return 0 if certificate is consistent
int verify_cert_integrity(const uint8_t *certificate)
{
    if (certificate[0] == CERT_INVITE) {
        uint8_t invitee_pk[SIG_PUBLIC_KEY];
        uint8_t inviter_pk[SIG_PUBLIC_KEY];
        memcpy(invitee_pk, SIG_KEY(certificate + 1), SIG_PUBLIC_KEY);
        memcpy(inviter_pk, SIG_KEY(certificate + SEMI_INVITE_CERTIFICATE_SIGNED_SIZE), SIG_PUBLIC_KEY);

        if (crypto_sign_verify_detached(certificate+INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE,
                     certificate, INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE, inviter_pk) != 0)
            return -1;

         if (crypto_sign_verify_detached(certificate+SEMI_INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE,
                     certificate, SEMI_INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE, invitee_pk) != 0)
            return -1;

        return 0;
    }

    if (certificate[0] > CERT_INVITE && certificate[0] < 255) {
        uint8_t source_pk[CLIENT_ID_SIGN_SIZE];
        memcpy(source_pk, SIG_KEY(certificate + 1 + EXT_PUBLIC_KEY), SIG_PUBLIC_KEY);
        if (crypto_sign_verify_detached(certificate+COMMON_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE,
                     certificate, COMMON_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE, source_pk) != 0)
            return -1;

        return 0;
    }

    return -1;
}

// Return -1 if we don't know who signed the certificate
// Return -2 if cert is signed by chat pk, e.g. in case it is the cert founder created for himself
// Return peer number in other cases
int process_invite_cert(const Group_Chat *chat, const uint8_t *certificate)
{
    if (certificate[0] != CERT_INVITE)
        return -1;

    uint8_t inviter_pk[EXT_PUBLIC_KEY];
    uint8_t invitee_pk[EXT_PUBLIC_KEY];
    memcpy(inviter_pk, certificate + SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, EXT_PUBLIC_KEY);
    memcpy(invitee_pk, certificate + 1, EXT_PUBLIC_KEY);
    uint32_t j = peer_in_chat(chat, invitee_pk);

    if (id_long_equal(chat->chat_public_key, inviter_pk)) {
        chat->group[j].verified = 1;
        return -2;
    }

    uint32_t i = peer_in_chat(chat, inviter_pk);
    if (i != -1) 
        if (chat->group[i].verified == 1 ) {
            chat->group[j].verified = 1;
            return i;
        }

    chat->group[j].verified = 0;
    return i;
}

// Return -1 if cert isn't issued by ops
// Return issuer peer number in other cases
int process_common_cert(const Group_Chat *chat, const uint8_t *certificate)
{
    if (certificate[0] > CERT_INVITE && certificate[0] < 255) {
        uint8_t source_pk[EXT_PUBLIC_KEY];
        uint8_t target_pk[EXT_PUBLIC_KEY];
        memcpy(source_pk, certificate + 1 + EXT_PUBLIC_KEY, EXT_PUBLIC_KEY);
        memcpy(target_pk, certificate + 1, EXT_PUBLIC_KEY);

        uint32_t i = peer_in_chat(chat, source_pk);
        if (i==-1)
            return i;
        if (chat->group[i].role&OP_ROLE || chat->group[i].role&FOUNDER_ROLE) {
            if (certificate[0] == CERT_BAN) {
                uint32_t j = peer_in_chat(chat, target_pk);
                chat->group[j].banned = 1;
                bytes_to_U64(&chat->group[i].banned_time, certificate + 1 + EXT_PUBLIC_KEY * 2);
            }
            if (certificate[0] == CERT_OP_CREDENTIALS) {
                uint32_t j = peer_in_chat(chat, target_pk);
                chat->group[j].role |= OP_ROLE;
            }

            return i;
        }

        // TODO: process the situation when op is trying to ban op or founder

    }

    return -1;
}

/* Check if peer with client_id is in peer array.
 * return peer number if peer is in chat.
 * return -1 if peer is not in chat.
 * TODO: make this more efficient.
 */
int peer_in_chat(const Group_Chat *chat, const uint8_t *client_id)
{
    uint32_t i;
    for (i = 0; i < chat->numpeers; ++i)
        if (id_long_equal(chat->group[i].client_id, client_id))
            return i;

    return -1;
}

// Return peernum if success or peer already in chat.
// Return -1 if fail
int add_peer(Group_Chat *chat, const Group_Peer *peer)
{
    int peernum = peer_in_chat(chat, peer->client_id);

    if (peernum != -1)
        return peernum;

    Group_Peer *temp;
    temp = realloc(chat->group, sizeof(Group_Peer) * (chat->numpeers + 1));

    if (temp == NULL)
        return -1;

    memcpy(&(temp[chat->numpeers]), peer, sizeof(Group_Peer));
    chat->group = temp;

    ++chat->numpeers;

    return (chat->numpeers - 1);
}

Group_Credentials *new_groupcredentials()
{
    Group_Credentials *credentials = calloc(1, sizeof(Group_Credentials));
    create_long_keypair(credentials->chat_public_key, credentials->chat_secret_key);
    unix_time_update();
    credentials->creation_time = unix_time();

    return credentials;
}


Group_Chat *new_groupchat(Networking_Core *net)
{
   	if (net == 0)
        return NULL;

    Group_Chat *chat = calloc(1, sizeof(Group_Chat));
    if (chat == NULL)
        return NULL;

    if (net == NULL)
        return NULL;

    chat->net = net;
    chat->numpeers = 0;
    chat->self_role = 0;
    networking_registerhandler(chat->net, NET_PACKET_GROUP_CHATS, &handle_groupchatpacket, chat);

    // TODO: Need to handle the situation when we load this from locally stored data
    create_long_keypair(chat->self_public_key, chat->self_secret_key);

    return chat;
}

void kill_groupchat(Group_Chat *chat)
{
    free(chat->group);
    free(chat);
}

void kill_groupcredentials(Group_Credentials *credentials)
{
    free(credentials->ops);
    free(credentials);
}