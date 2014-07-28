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

#define TIME_STAMP (sizeof(uint64_t))
#define GC_INVITE_REQUEST_PLAIN_SIZE (1 + (CLIENT_ID_EXT_SIZE + SIGNATURE_SIZE) )
#define GC_INVITE_REQUEST_DHT_SIZE (1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES + GC_INVITE_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

#define GC_INVITE_RESPONSE_PLAIN_SIZE (1 + ((CLIENT_ID_EXT_SIZE + SIGNATURE_SIZE) + TIME_STAMP + CLIENT_ID_EXT_SIZE + SIGNATURE_SIZE) )
#define GC_INVITE_RESPONSE_DHT_SIZE (1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES + GC_INVITE_RESPONSE_PLAIN_SIZE + crypto_box_MACBYTES)

#define MIN_PACKET_SIZE (1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES)

int unwrap_group_packet(const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key, uint8_t *data,
                   uint8_t *packet_type, const uint8_t *packet, uint16_t length)
{
    if (length < MIN_PACKET_SIZE && length > MAX_CRYPTO_REQUEST_SIZE) 
        return -1;
    
    if id_equal2(packet + 1, self_public_key, ID_ALL_KEYS)
        return -1;

    id_copy2(public_key, packet + 1, ID_ALL_KEYS);

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, packet + 1 + CLIENT_ID_EXT_SIZE, crypto_box_NONCEBYTES);

    uint8_t pk[CLIENT_ID_SIZE];
    uint8_t ssk[CLIENT_ID_SIZE];
    id_copy2(pk, public_key, ID_ENCRYPTION_KEY);
    id_copy2(ssk, send_secret_key, ID_ENCRYPTION_KEY);

    uint8_t plain[MAX_CRYPTO_REQUEST_SIZE];
    int len = decrypt_data(pk, ssk, nonce,
                            packet + 1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES,
                            length - (1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES), plain);

    if (len == -1 || len == 0)
        return -1;

    packet_type = plain[0];
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

    uint8_t rpk[CLIENT_ID_SIZE];
    uint8_t ssk[CLIENT_ID_SIZE];
    id_copy2(rpk, recv_public_key, ID_ENCRYPTION_KEY);
    id_copy2(ssk, send_secret_key, ID_ENCRYPTION_KEY);

    uint8_t encrypt[1 + length + crypto_box_MACBYTES];
    int len = encrypt_data(rpk, ssk, nonce, plain, length + 1, encrypt);
    if (len != sizeof(encrypt))
        return -1;

    packet[0] = NET_PACKET_GROUP_CHATS;
    memcpy(packet + 1, send_public_key, CLIENT_ID_EXT_SIZE);
    memcpy(packet + 1 + CLIENT_ID_EXT_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + 1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES, encrypt, len);

    return 1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES + len;
}

int handle_groupchatpacket(void * _chat, IP_Port ipp, const uint8_t *packet, uint32_t length)
{

    Group_Chat *chat = _chat;

    uint8_t public_key[CLIENT_ID_EXT_SIZE];
    uint8_t data[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t packet_type;

    int len = handle_request(chat->self_public_key, chat->self_secret_key, public_key, data, &packet_type, packet, length);

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

int sign_certificate(const uint8_t *data, uint32_t length, const uint8_t *private_key, const uint8_t *public_key, uint8_t *certificate)
{
    unsigned long long clen;
    uint8_t buf[MAX_CRYPTO_REQUEST_SIZE];
    memcpy(buf, data, length);
    id_copy2(buf + length, public_key, ID_ALL_KEYS);   
    unix_time_update(); 
    U64_to_bytes(buf + length + CLIENT_ID_EXT_SIZE, unix_time());
    uint32_t len = length + CLIENT_ID_EXT_SIZE + sizeof(uint64_t) + SIGNATURE_SIZE;

    if (crypto_sign(certificate, &clen, buf, len - SIGNATURE_SIZE, private_key) != 0 || slen != len)
        return -1;
    
    return 0;
}

int verify_certificate(const uint8_t *certificate)
{
    uint8_t buf[INVITE_CERTIFICATE_SIGNED_SIZE];
    unsigned long long mlen;

    switch (certificate[0]) {
        case INVITE_CERTIFICATE_SIGNED_SIZE: {
            uint8_t invitee_pk[CLIENT_ID_SIGN_SIZE];
            uint8_t inviter_pk[CLIENT_ID_SIGN_SIZE];
            id_copy2(invitee_pk, certificate + 1, ID_SIGNATURE_KEY);
            id_copy2(inviter_pk, certificate + 1 + CLIENT_ID_EXT_SIZE + TIME_STAMP + SIGNATURE_SIZE, ID_SIGNATURE_KEY);

            if (crypto_sign_open(buf, &mlen, certificate, INVITE_CERTIFICATE_SIGNED_SIZE, inviter_pk) < 0 ||
                    mlen != (INVITE_CERTIFICATE_SIGNED_SIZE - SIGNATURE_SIZE))
                return -1;

            if (crypto_sign_open(buf, &mlen, certificate, 1 + CLIENT_ID_EXT_SIZE + TIME_STAMP + SIGNATURE_SIZE, invitee_pk) < 0 ||
                    mlen != (1 + CLIENT_ID_EXT_SIZE + TIME_STAMP))
                return -1;

            // TODO verify if we know inviter pk

        }

        case COMMON_CERTIFICATE_SIGNED_SIZE: {
            uint8_t target_pk[CLIENT_ID_SIGN_SIZE];
            id_copy2(target_pk, certificate + 1 + CLIENT_ID_EXT_SIZE, ID_SIGNATURE_KEY);
            if (crypto_sign_open(buf, &mlen, certificate, COMMON_CERTIFICATE_SIGNED_SIZE, target_pk) < 0 ||
                mlen != (COMMON_CERTIFICATE_SIGNED_SIZE - SIGNATURE_SIZE))
            return -1;

            // TODO verify if we know target pk and if tarfet is op or founder
        }

        default:
            return -1;
    }
    
    return 0;    
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
        return -1;

    // Why do we even need this?
    //unix_time_update();

    Group_Chat *chat = calloc(1, sizeof(Group_Chat));
    if (chat == NULL)
        return NULL;

    if (net == NULL)
        return NULL;

    chat->net = net;
    networking_registerhandler(chat->net, NET_PACKET_GROUP_CHATS, &handle_groupchatpacket, chat);

    // TODO: Need to handle the situation when we load this from locally stored data
    create_long_keypair(chat->self_public_key, chat->self_secret_key);

    return chat;
}

void kill_groupchat(Group_Chat *chat)
{
	// Send quit action
    // send_data(chat, 0, 0, GROUP_CHAT_QUIT);
    
    free(chat->group);
    free(chat);
}