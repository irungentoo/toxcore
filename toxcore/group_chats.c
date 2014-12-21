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
#include "group_chats.h"
#include "LAN_discovery.h"
#include "util.h"
#include "Messenger.h"

#define GC_INVITE_REQUEST_PLAIN_SIZE SEMI_INVITE_CERTIFICATE_SIGNED_SIZE
#define GC_INVITE_REQUEST_DHT_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_INVITE_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

#define GC_INVITE_RESPONSE_PLAIN_SIZE INVITE_CERTIFICATE_SIGNED_SIZE
#define GC_INVITE_RESPONSE_DHT_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_INVITE_RESPONSE_PLAIN_SIZE + crypto_box_MACBYTES)

#define MIN_PACKET_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES)

#define NET_PACKET_GROUP_CHATS 9 /* WARNING. Temporary measure. */

static int peernumber_valid(const GC_Chat *chat, uint32_t peernum);
static int groupnumber_valid(const GC_Session* c, int groupnumber);
static int gc_peer_add(GC_Chat *chat, const GC_GroupPeer *peer);
static int gc_peer_update(GC_Chat *chat, const GC_GroupPeer *peer, uint32_t peernum);
static int gc_peer_delete(GC_Chat *chat, uint32_t peernum, const uint8_t *data, uint32_t length);;

enum {
    GP_GET_NODES,
    GP_SEND_NODES,
    GP_BROADCAST,
    GP_INVITE_REQUEST,
    GP_INVITE_RESPONSE,
    GP_SYNC_REQUEST,
    GP_SYNC_RESPONSE
} GROUP_PACKET;


/* Shamelessly taken from wikipedia's Jenkins hash function page
 */
uint32_t calculate_hash(const uint8_t *key, size_t len)
{
    uint32_t hash, i;

    for (hash = i = 0; i < len; ++i) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

// Handle all decrypt procedures
int unwrap_group_packet(const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key, uint8_t *data,
                   uint8_t *packet_type, const uint8_t *packet, uint16_t length)
{
    if (length < MIN_PACKET_SIZE && length > MAX_GC_PACKET_SIZE) 
        return -1;
    
    if (id_long_equal(packet + 1, self_public_key))
        return -1;

    memcpy(public_key, packet + 1, EXT_PUBLIC_KEY);

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, packet + 1 + EXT_PUBLIC_KEY, crypto_box_NONCEBYTES);

    uint8_t plain[MAX_GC_PACKET_SIZE];
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

// Handle all encrypt procedures
int wrap_group_packet(const uint8_t *send_public_key, const uint8_t *send_secret_key, const uint8_t *recv_public_key,
                      uint8_t *packet, const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    if (MAX_GC_PACKET_SIZE < length + MIN_PACKET_SIZE)
        return -1;
    
    uint8_t plain[MAX_GC_PACKET_SIZE];
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

    return 1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + len;
}

// General function for packet sending
int send_groupchatpacket(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                         const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    if (id_long_equal(chat->self_public_key, public_key))
        return -1;

    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, chat->self_secret_key, public_key, packet, data, length, packet_type);

    if (len == -1)
        return -1;

    return sendpacket(chat->net, ip_port, packet, len);
}

/* Expects extpubkey being the size of EXT_PUBLIC_KEY bytes
 */
static GC_Chat* get_chat_by_public_key(GC_Session* gc, const uint8_t* extpubkey)
{
    uint32_t hh = calculate_hash(extpubkey, EXT_PUBLIC_KEY);
    
    uint32_t i = 0;
    for (; i < gc->num_chats; i ++) {
        if (gc->chats[i].hash_id == hh)
            return &gc->chats[i];
    }
    
    return NULL;
}

/* If we receive a group chat packet we call this function so it can be handled.
 * return 0 if packet is handled correctly.
 * return -1 if it didn't handle the packet or if the packet was shit.
 */
int handle_groupchatpacket(void * object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    /* TODO check packet size */
    GC_Session* gc = object;
    GC_Chat* chat = get_chat_by_public_key(gc, packet + 1);

    if (!chat)
        return -1;

    uint8_t public_key[EXT_PUBLIC_KEY];
    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;

    int len = unwrap_group_packet(chat->self_public_key, chat->self_secret_key, public_key, data, &packet_type, packet, length);

    if (len == -1)
        return -1;

    // Check if we know the user and if it's banned
    uint32_t peernum = gc_peer_in_chat(chat, public_key);
    if (peernum!=-1) {
        if (chat->group[peernum].banned==1)
            return -1;
    }

    switch (packet[2]) {
        case GP_INVITE_REQUEST: {
            return handle_gc_invite_request(chat, source, public_key, data, len);
        }
        case GP_INVITE_RESPONSE:
            return handle_gc_invite_response(chat, source, public_key, data, len);

        case GP_SYNC_REQUEST:
            return handle_gc_sync_request(chat, source, public_key, data, len);

        case GP_SYNC_RESPONSE:
            return handle_gc_sync_response(chat, source, public_key, data, len);

        case GP_BROADCAST:
            return handle_gc_broadcast(chat, source, public_key, data, len);

        default:
            return -1;
    }

    return -1;
}


/* Return -1 if fail
 * Return 0 if success
 */
int gc_send_invite_request(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key)
{
    uint8_t  invite_certificate[SEMI_INVITE_CERTIFICATE_SIGNED_SIZE];

    if (make_invite_cert(chat->self_secret_key, chat->self_public_key, invite_certificate)==-1)
        return -1;

    return send_groupchatpacket(chat, ip_port, public_key, invite_certificate,
         SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, GP_INVITE_REQUEST);
}


/* Return -1 if fail
 * Return 0 if success
 */
int handle_gc_invite_request(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length)
{
    uint8_t  invite_certificate[INVITE_CERTIFICATE_SIGNED_SIZE];

    if (!id_long_equal(public_key, data+1))
        return -1;

    if (data[0] != GC_INVITE)
        return -1;

    if (crypto_sign_verify_detached(data + SEMI_INVITE_CERTIFICATE_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    SEMI_INVITE_CERTIFICATE_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(public_key)) != 0)
        return -1;

    if (sign_certificate(data, SEMI_INVITE_CERTIFICATE_SIGNED_SIZE, chat->self_secret_key, chat->self_public_key,
                         invite_certificate) == -1)
        return -1;

    // Adding peer we just invited into the peer group list
    GC_GroupPeer *peer = calloc(1, sizeof(GC_GroupPeer));

    if (peer == NULL)
        return -1;

    memcpy(peer->client_id, public_key, EXT_PUBLIC_KEY);
    memcpy(peer->invite_certificate, invite_certificate, INVITE_CERTIFICATE_SIGNED_SIZE);
    peer->role |= GR_USER;
    peer->verified = 1;
    peer->last_update_time = unix_time();
    peer->ip_port = ipp;
    gc_peer_add(chat, peer);

    return gc_send_invite_response(chat, ipp, public_key, invite_certificate, INVITE_CERTIFICATE_SIGNED_SIZE);
}

/* Return -1 if fail
 * Return 0 if succes
 */
int gc_send_invite_response(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                            const uint8_t *data, uint32_t length)
{
    return send_groupchatpacket(chat, ip_port, public_key, data, length, GP_INVITE_RESPONSE);
}

/* Return -1 if fail
 * Return 0 if success
 */
int handle_gc_invite_response(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length)
{
    if (!id_long_equal(public_key, data+SEMI_INVITE_CERTIFICATE_SIGNED_SIZE))
        return -1;

    if (data[0] != GC_INVITE)
        return -1;

    // Verify our own signature
    if (crypto_sign_verify_detached(data + SEMI_INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE, data,
                                    SEMI_INVITE_CERTIFICATE_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(chat->self_public_key)) != 0)
        return -1;

    // Verify inviter signature
    if (crypto_sign_verify_detached(data + INVITE_CERTIFICATE_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    INVITE_CERTIFICATE_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(public_key)) != 0)
        return -1;

    memcpy(chat->self_invite_certificate, data, INVITE_CERTIFICATE_SIGNED_SIZE);

    // send_sync_request();
    // add the peer who invited us
    return 0;
}

int gc_send_sync_request(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key)
{
    uint8_t data[MAX_GC_PACKET_SIZE];

    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(data + EXT_PUBLIC_KEY, &chat->last_synced_time, TIME_STAMP);

    return send_groupchatpacket(chat, ip_port, public_key, data, EXT_PUBLIC_KEY+TIME_STAMP, GP_SYNC_REQUEST);

}

int handle_gc_sync_request(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data,
                           uint32_t length)
{
    if (!id_long_equal(public_key, data))
        return -1;

    // TODO: Check if we know the peer and if peer is verified

    uint8_t response[MAX_GC_PACKET_SIZE];
    memcpy(response, chat->self_public_key, EXT_PUBLIC_KEY);

    uint64_t last_synced_time;
    bytes_to_U64(&last_synced_time, data + EXT_PUBLIC_KEY);

    uint32_t len = 0;

    if (last_synced_time > chat->last_synced_time) {
        // TODO: probably we should initiate sync request ourself, cause requester has more fresh info
        len = EXT_PUBLIC_KEY + sizeof(uint32_t);
        uint32_t num = 0;
        U32_to_bytes(response + EXT_PUBLIC_KEY, num);
    } else {
        GC_GroupPeer *peers = calloc(1, sizeof(GC_GroupPeer) * chat->numpeers);

        if (peers == NULL)
            return -1;

        uint32_t i, num = 0;

        for (i = 0; i < chat->numpeers; i++) 
            if ((chat->group[i].last_update_time > last_synced_time)
                        && (!id_long_equal(chat->group[i].client_id, public_key))) {
                memcpy(&peers[num], &chat->group[i], sizeof(GC_GroupPeer));
                ++num;
            }
            
        // Add yourself
        gc_to_peer(chat, &peers[num]);
        ++num;

        len = EXT_PUBLIC_KEY + sizeof(uint32_t) + TIME_STAMP + sizeof(GC_GroupPeer) * num;
        U32_to_bytes(response + EXT_PUBLIC_KEY, num);
        U64_to_bytes(response + EXT_PUBLIC_KEY + sizeof(uint32_t), chat->last_synced_time);
        
        // TODO: big packet size...
        memcpy(response + EXT_PUBLIC_KEY + sizeof(uint32_t) + TIME_STAMP, peers, sizeof(GC_GroupPeer) * num);
    }
    return gc_send_sync_response(chat, ipp, public_key, response, len);
}

int gc_send_sync_response(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                         const uint8_t *data, uint32_t length)
{
    return send_groupchatpacket(chat, ip_port, public_key, data, length, GP_SYNC_RESPONSE);
}

int handle_gc_sync_response(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key,
                             const uint8_t *data, uint32_t length)
{
    if (!id_long_equal(public_key, data))
        return -1;

    uint32_t num = 0;
    bytes_to_U32(&num, data + EXT_PUBLIC_KEY);

    if (num == 0)
        return -1;

    bytes_to_U64(&chat->last_synced_time, data + EXT_PUBLIC_KEY + sizeof(uint32_t));

    GC_GroupPeer *peers = calloc(1, sizeof(GC_GroupPeer) * num);

    if (peers == NULL)
        return -1;

    memcpy(peers, data + EXT_PUBLIC_KEY + sizeof(uint32_t) + TIME_STAMP, sizeof(GC_GroupPeer) * num);

    uint32_t i;

    for (i = 0; i < num; i++){
        uint32_t j = gc_peer_in_chat(chat, peers[i].client_id);

        if (j != -1)
            gc_peer_update(chat, &peers[i], j);
        else
            gc_peer_add(chat, &peers[i]);
    }

    // The last one is always the sender
    chat->group[num-1].ip_port = ipp;

    // NB: probably to be deleted
    chat->group_address_only[num-1].ip_port = ipp;

    return 0;
}

int send_gc_broadcast_packet(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                             const uint8_t *data, uint32_t length)
{
    uint8_t dt[length+EXT_PUBLIC_KEY];
    memcpy(dt, chat->self_public_key, EXT_PUBLIC_KEY);

    if (data && length > 0)
        memcpy(dt + EXT_PUBLIC_KEY, data, length);

    // TODO: send to all peers... Or rather we should make efficient sophisticated routing :)
    // Currently ping_group() and others think that we send only one packet. Change ping_group() in case
    // of this function changing
    return send_groupchatpacket(chat, ip_port, public_key, dt, EXT_PUBLIC_KEY + length, GP_BROADCAST);
}

int handle_gc_broadcast(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length)
{
    if (!id_long_equal(public_key, data))
        return -1;

    uint32_t len = length - 1 - EXT_PUBLIC_KEY;
    uint8_t dt[len];
    memcpy(dt, data + 1 + EXT_PUBLIC_KEY, len);

    // TODO: Check if peer is verified. Actually we should make it optional
    uint32_t peernum = gc_peer_in_chat(chat, public_key);

    if ((peernum == -1) && (data[EXT_PUBLIC_KEY] != GM_NEW_PEER))
        return -1;

    switch (data[EXT_PUBLIC_KEY]) {
        case GM_PING:
            return handle_gc_ping(chat, ipp, public_key, dt, len, peernum);
        case GM_STATUS:
            return handle_gc_status(chat, ipp, public_key, dt, len, peernum);
        case GM_NEW_PEER:
            return handle_gc_new_peer(chat, ipp, public_key, dt, len);
        case GM_CHANGE_NICK:
            return handle_gc_change_nick(chat, ipp, public_key, dt, len, peernum);
        case GM_CHANGE_TOPIC:
            return handle_gc_change_topic(chat, ipp, public_key, dt, len, peernum);
        case GM_PLAIN:
            return handle_gc_message(chat, ipp, public_key, dt, len, peernum);
        case GM_ACTION:
            return handle_gc_op_action(chat, ipp, public_key, dt, len, peernum);
        case GM_PEER_EXIT:
            return handle_gc_peer_exit(chat, ipp, public_key, dt, len, peernum);
        default:
            return -1;
    }
}

int send_gc_ping(const GC_Chat *chat, const GC_PeerAddress *rcv_peer, int numpeers)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    uint32_t length;

    data[0] = GM_PING;
    length = 1;

    int i;

    for (i = 0; i < numpeers; ++i)
        if (send_gc_broadcast_packet(chat, rcv_peer[i].ip_port, rcv_peer[i].client_id, data, length) == -1)
            return -1;
    
    return 0;
}

int handle_gc_ping(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length, uint32_t peernum)
{
    chat->group[peernum].ip_port = ipp;
    chat->group[peernum].last_rcvd_ping = unix_time();
    return 0;
}

int send_gc_status(const GC_Chat *chat, uint8_t status_type)
{
    uint8_t data[MAX_GC_PACKET_SIZE];

    data[0] = GM_STATUS;
    data[1] = chat->self_status;
    uint32_t length = 2;

    const GC_PeerAddress *rcv_peer = chat->group_address_only;

    int i;

    for (i = 0; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, rcv_peer[i].ip_port, rcv_peer[i].client_id, data, length) == -1)
            return -1;
    }

    return 0;
}

int gc_set_self_status(GC_Chat *chat, uint8_t status_type)
{
    if (status_type == GS_NONE || status_type >= GS_INVALID)
        return -1;

    chat->self_status = status_type;
    return send_gc_status(chat, status_type);
}

int handle_gc_status(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length, uint32_t peernum)
{
    chat->group[peernum].status = data[0];
    return 0;
}

/* Return's peernum's status (GS_INVALID on failure) */
uint8_t gc_get_status(const GC_Chat *chat, uint8_t peernum)
{
    if (!peernumber_valid(chat, peernum))
        return GS_INVALID;

    return chat->group[peernum].status;
}

int send_gc_new_peer(const GC_Chat *chat, const GC_PeerAddress *rcv_peer, int numpeers)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    uint32_t length;

    
    GC_GroupPeer *peer = calloc(1, sizeof(GC_GroupPeer));

    if (peer == NULL)
        return -1;

    gc_to_peer(chat, peer);
    data[0] = GM_NEW_PEER;
    memcpy(data+1, peer, sizeof(GC_GroupPeer));
    length = 1 + sizeof(GC_GroupPeer);

    int i;

    for (i = 0; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, rcv_peer[i].ip_port, rcv_peer[i].client_id, data, length) == -1)
            return -1;
    }

    return 0;
}

int handle_gc_new_peer(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length)
{
    GC_GroupPeer *peer = calloc(1, sizeof(GC_GroupPeer));

    if (peer == NULL)
        return -1;

    memcpy(peer, data, sizeof(GC_GroupPeer));

    // TODO: Probably we should make it also optional, but I'm personally against it (c) henotba
    if (verify_cert_integrity(peer->invite_certificate) == -1) {
        free(peer);
        return -1;
    }

    peer->ip_port = ipp;
    gc_peer_add(chat, peer);
    return 0;
}

static int send_gc_self_exit(const GC_Chat *chat, const uint8_t *partmessage, uint32_t length)
{
    /* NOTE: length should be checked by caller function */

    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = GM_PEER_EXIT;
    U64_to_bytes(data + 1, unix_time());
    memcpy(data + 1 + TIME_STAMP, partmessage, length);
    length = 1 + TIME_STAMP + length;

    const GC_PeerAddress *rcv_peer = chat->group_address_only;
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (send_gc_broadcast_packet(chat, rcv_peer[i].ip_port, rcv_peer[i].client_id, data, length) == -1)
            return -1;
    }

    return 0;
}

int handle_gc_peer_exit(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data,
                        uint32_t length, uint32_t peernum)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE)
        return gc_peer_delete(chat, peernum, NULL, 0);

    return gc_peer_delete(chat, peernum, data, length);
}

int send_gc_change_nick(const GC_Chat *chat)
{
    uint8_t data[MAX_GC_PACKET_SIZE];

    data[0] = GM_CHANGE_NICK;
    memcpy(data + 1, chat->self_nick, chat->self_nick_len);
    uint32_t length = 1 + chat->self_nick_len;

    const GC_PeerAddress *rcv_peer = chat->group_address_only;

    int i;

    for (i = 0; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, rcv_peer[i].ip_port, rcv_peer[i].client_id, data, length) == -1)
            return -1;
    }

    return 0;
}

int gc_set_self_nick(GC_Chat *chat, const uint8_t *nick, uint32_t length)
{
    if (length > MAX_GC_NICK_SIZE || length == 0)
        return -1;

    memcpy(chat->self_nick, nick, length);
    chat->self_nick_len = length;
    return send_gc_change_nick(chat);
}

/* Return -1 on error.
 * Return nick length if success
 */
int gc_get_nick(const GC_Chat *chat, uint32_t peernum, uint8_t *namebuffer)
{
    if (!peernumber_valid(chat, peernum))
        return -1;

    memcpy(namebuffer, chat->group[peernum].nick, chat->group[peernum].nick_len);
    return chat->group[peernum].nick_len;
}

int handle_gc_change_nick(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data,
                          uint32_t length, uint32_t peernum)
{
    if (length > MAX_GC_NICK_SIZE)
        return -1;

    if (chat->group_nick_change)
        (*chat->group_nick_change)(chat, peernum, data, length, chat->group_nick_change_userdata);

    memcpy(chat->group[peernum].nick, data, length);
    chat->group[peernum].nick_len = length;

    return 0;
}

int send_gc_change_topic(const GC_Chat *chat)
{
    uint8_t data[MAX_GC_PACKET_SIZE];

    data[0] = GM_CHANGE_TOPIC;
    memcpy(data + 1, chat->topic, chat->topic_len);
    uint32_t length = 1 + chat->topic_len;

    const GC_PeerAddress *rcv_peer = chat->group_address_only;

    int i;

    for (i = 0; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, rcv_peer[i].ip_port, rcv_peer[i].client_id, data, length) == -1)
            return -1;
    }

    return 0;
}

int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint32_t length)
{
    if (length > MAX_GC_TOPIC_SIZE)
        return -1;

    memcpy(chat->topic, topic, length);
    chat->topic_len = length;
    return send_gc_change_topic(chat);
}

 /* Return topic length. */
int gc_get_topic(const GC_Chat *chat, uint8_t *topicbuffer)
{
    memcpy(topicbuffer, chat->topic, chat->topic_len);
    return chat->topic_len;
}

int handle_gc_change_topic(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length, uint32_t peernum)
{
    if (length > MAX_GC_TOPIC_SIZE)
        return -1;

    // NB: peernum could be used to verify who is changing the topic in some cases
    memcpy(chat->topic, data, length);
    chat->topic_len = length;

    if (chat->group_title_change)
        (*chat->group_title_change)(chat, peernum, data, length, chat->group_title_change_userdata);

    return 0;
}

int gc_send_plain_message(const GC_Chat *chat, const uint8_t *message, uint32_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE || length == 0)
        return -1;

    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = GM_PLAIN;
    U64_to_bytes(data + 1, unix_time());
    memcpy(data + 1 + TIME_STAMP, message, length);
    length = 1 + TIME_STAMP + length;

    const GC_PeerAddress *rcv_peer = chat->group_address_only;

    int i;

    for (i = 0; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, rcv_peer[i].ip_port, rcv_peer[i].client_id, data, length) == -1)
            return -1;
    }

    return 0;
}

int handle_gc_message(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length, uint32_t peernum)
{
    if (length > MAX_GC_MESSAGE_SIZE || length == 0)
        return -1;

    if (!chat->group_message)
        return -1;

    (*chat->group_message)(chat, peernum, data, length, chat->group_message_userdata);
    return 0;
}

int gc_send_op_action(const GC_Chat *chat, const uint8_t *certificate)
{
    uint8_t data[MAX_GC_PACKET_SIZE];

    data[0] = GM_ACTION;
    memcpy(data + 1, certificate, COMMON_CERTIFICATE_SIGNED_SIZE);

    const GC_PeerAddress *rcv_peer = chat->group_address_only;

    int i;

    for (i = 0; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, rcv_peer[i].ip_port, rcv_peer[i].client_id, data, COMMON_CERTIFICATE_SIGNED_SIZE+1) == -1)
            return -1;
    }

    return 0;
}

int handle_gc_op_action(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data, uint32_t length, uint32_t peernum)
{
    if (process_common_cert(chat, data) == -1)
        return -1;

    if (!chat->group_op_action)
        return -1;

    (*chat->group_op_action)(chat, peernum, data, length, chat->group_op_action_userdata);
    return 0;
}

void gc_callback_groupmessage(GC_Chat *chat, void (*function)(GC_Chat *chat, uint32_t, const uint8_t *,
                              uint32_t, void *), void *userdata)
{
    chat->group_message = function;
    chat->group_message_userdata = userdata;
}

void gc_callback_group_op_action(GC_Chat *chat, void (*function)(GC_Chat *chat, uint32_t, const uint8_t *,
                                 uint32_t, void *), void *userdata)
{
    chat->group_op_action = function;
    chat->group_op_action_userdata = userdata;
}

void gc_callback_group_nick_change(GC_Chat *chat, void (*function)(GC_Chat *chat, uint32_t, const uint8_t *,
                                   uint32_t, void *), void *userdata)
{
    chat->group_nick_change = function;
    chat->group_nick_change_userdata = userdata;
}

void gc_callback_group_title_change(GC_Chat *chat, void (*function)(GC_Chat *chat, uint32_t, const uint8_t *,
                                    uint32_t, void *), void *userdata)
{
    chat->group_title_change = function;
    chat->group_title_change_userdata = userdata;
}


void gc_callback_group_peer_exit(GC_Chat *chat, void (*function)(GC_Chat *chat, uint32_t, const uint8_t *,
                                 uint32_t, void *), void *userdata)
{
    chat->group_peer_exit = function;
    chat->group_peer_exit_userdata = userdata;
}

void gc_callback_group_peer_join(GC_Chat *chat, void (*function)(GC_Chat *chat, uint32_t, void *), void *userdata)
{
    chat->group_peer_join = function;
    chat->group_peer_join_userdata = userdata;
}

/* Sign input data
 * Add signer public key, time stamp and signature in the end of the data
 * Return -1 if fail, 0 if success
 */
int sign_certificate(const uint8_t *data, uint32_t length, const uint8_t *private_key, const uint8_t *public_key, uint8_t *certificate)
{
    memcpy(certificate, data, length);
    memcpy(certificate + length, public_key, EXT_PUBLIC_KEY);

    U64_to_bytes(certificate + length + EXT_PUBLIC_KEY, unix_time());
    uint32_t mlen = length + EXT_PUBLIC_KEY + TIME_STAMP;

    if (crypto_sign_detached(certificate+mlen, NULL, certificate, mlen, SIG_KEY(private_key)) != 0)
        return -1;
    
    return 0;
}

/* Make invite certificate
 * This cert is only half-done, cause it needs to be signed by inviter also
 * Return -1 if fail, 0 if success
 */
int make_invite_cert(const uint8_t *private_key, const uint8_t *public_key, uint8_t *half_certificate)
{
    uint8_t buf[COMMON_CERTIFICATE_SIGNED_SIZE];
    buf[0] = GC_INVITE;
    return sign_certificate(buf, 1, private_key, public_key, half_certificate);
}

/* Make common certificate
 * Return -1 if fail, 0 if success
 */
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
    if (certificate[0] == GC_INVITE) {
        uint8_t invitee_pk[SIG_PUBLIC_KEY];
        uint8_t inviter_pk[SIG_PUBLIC_KEY];
        memcpy(invitee_pk, SIG_KEY(CERT_INVITEE_KEY(certificate)), SIG_PUBLIC_KEY);
        memcpy(inviter_pk, SIG_KEY(CERT_INVITER_KEY(certificate)), SIG_PUBLIC_KEY);

        if (crypto_sign_verify_detached(certificate+INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE,
                     certificate, INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE, inviter_pk) != 0)
            return -1;

         if (crypto_sign_verify_detached(certificate+SEMI_INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE,
                     certificate, SEMI_INVITE_CERTIFICATE_SIGNED_SIZE-SIGNATURE_SIZE, invitee_pk) != 0)
            return -1;

        return 0;
    }

    if (certificate[0] > GC_INVITE && certificate[0] < 255) {
        uint8_t source_pk[SIG_PUBLIC_KEY];
        memcpy(source_pk, SIG_KEY(CERT_SOURCE_KEY(certificate)), SIG_PUBLIC_KEY);
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
int process_invite_cert(const GC_Chat *chat, const uint8_t *certificate)
{
    if (certificate[0] != GC_INVITE)
        return -1;

    uint8_t inviter_pk[EXT_PUBLIC_KEY];
    uint8_t invitee_pk[EXT_PUBLIC_KEY];
    memcpy(inviter_pk, CERT_INVITER_KEY(certificate), EXT_PUBLIC_KEY);
    memcpy(invitee_pk, CERT_INVITEE_KEY(certificate), EXT_PUBLIC_KEY);
    uint32_t j = gc_peer_in_chat(chat, invitee_pk); // TODO: processing after adding?

    if (id_long_equal(chat->chat_public_key, inviter_pk)) {
        chat->group[j].verified = 1;
        return -2;
    }

    uint32_t i = gc_peer_in_chat(chat, inviter_pk);
    if (i != -1) 
        if (chat->group[i].verified == 1 ) {
            chat->group[j].verified = 1;
            return i;
        }

    chat->group[j].verified = 0;
    return i;
}

// Return -1 if cert isn't issued by ops or we don't know the source or op tries to ban op
// Return issuer peer number in other cases
// Add roles or ban depending on the cert and save the cert in common_cert arrays (works for ourself and peers)
int process_common_cert(GC_Chat *chat, const uint8_t *certificate)
{
    if (certificate[0] > GC_INVITE && certificate[0] < 255) {
        uint8_t source_pk[EXT_PUBLIC_KEY];
        uint8_t target_pk[EXT_PUBLIC_KEY];
        memcpy(source_pk, CERT_SOURCE_KEY(certificate), EXT_PUBLIC_KEY);
        memcpy(target_pk, CERT_TARGET_KEY(certificate), EXT_PUBLIC_KEY);

        uint32_t src = gc_peer_in_chat(chat, source_pk); 
        if (src==-1)
            return src;
        if (chat->group[src].role&GR_OP || chat->group[src].role&GR_FOUNDER) {

            if (id_long_equal(target_pk, chat->self_public_key)) {
                memcpy(chat->self_common_certificate[chat->self_common_cert_num], certificate, COMMON_CERTIFICATE_SIGNED_SIZE);
                chat->self_common_cert_num++;
                if (certificate[0] == GC_OP_CREDENTIALS)
                    chat->self_role |= GR_OP;
                // In case of ban cert action callback should handle this
                return src;
            }

            // In case cert is not for us
            uint32_t trg = gc_peer_in_chat(chat, target_pk);
            if (trg==-1)
                return -1;

            if (certificate[0] == GC_BAN) {
                // Process the situation when op is trying to ban op or founder
                if  (((chat->group[trg].role&GR_OP) || (chat->group[trg].role&GR_FOUNDER)) && (chat->group[src].role&GR_OP)) {
                    return -1;
                }
                chat->group[trg].banned = 1;
                bytes_to_U64(&chat->group[trg].banned_time, certificate + 1 + EXT_PUBLIC_KEY * 2);
                memcpy(chat->group[trg].common_certificate[chat->group[trg].common_cert_num], certificate, COMMON_CERTIFICATE_SIGNED_SIZE);
                chat->group[trg].common_cert_num++;
            }

            if (certificate[0] == GC_OP_CREDENTIALS) {
                chat->group[trg].role |= GR_OP;
                memcpy(chat->group[trg].common_certificate[chat->group[trg].common_cert_num], certificate, COMMON_CERTIFICATE_SIGNED_SIZE);
                chat->group[trg].common_cert_num++;
            }

            return src;
        }
    }
    return -1;
}

int process_chain_trust(GC_Chat *chat)
{
    // TODO !!!
    return -1;
}

// That's really a stump
static int peers_to_address_format(GC_Chat *chat, GC_PeerAddress *rcv_peer)
{
    chat->group_address_only = calloc(1, sizeof(GC_PeerAddress) * chat->numpeers);

    if (chat->group_address_only == NULL)
        return -1;

    int i;

    for (i = 0; i < chat->numpeers; i++) {
        memcpy(chat->group_address_only[i].client_id, chat->group[i].client_id, EXT_PUBLIC_KEY);
        chat->group_address_only[i].ip_port = chat->group[i].ip_port;
    }

    //rcv_peer = chat->group_address_only;

    return 0;
}

/* Check if peer with client_id is in peer array.
 * return peer number if peer is in chat.
 * return -1 if peer is not in chat.
 * TODO: make this more efficient.
 */
int gc_peer_in_chat(const GC_Chat *chat, const uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i)
        if (id_long_equal(chat->group[i].client_id, client_id))
            return i;

    return -1;
}

static int peernumber_valid(const GC_Chat *chat, uint32_t peernum)
{
    if (peernum >= chat->numpeers)
        return -1;

    return chat->group[peernum].status > GS_NONE;
}

static int gc_peer_delete(GC_Chat *chat, uint32_t peernum, const uint8_t *data, uint32_t length)
{
    if (chat->group_peer_exit)
        (*chat->group_peer_exit)(chat, peernum, data, length, chat->group_peer_exit_userdata);

    --chat->numpeers;

    if (chat->numpeers == 0) {
        free(chat->group);
        chat->group = NULL;
        return 0;
    }

    if (chat->numpeers != peernum)
        memcpy(&chat->group[peernum], &chat->group[chat->numpeers], sizeof(GC_GroupPeer));

    GC_GroupPeer *temp = realloc(chat->group, sizeof(GC_GroupPeer) * chat->numpeers);

    if (temp == NULL)
        return -1;

    chat->group = temp;

    return 0;
}

/* Return peernum if success or peer already in chat.
 * Return -1 if fail
 */
static int gc_peer_add(GC_Chat *chat, const GC_GroupPeer *peer)
{
    int peernum = gc_peer_in_chat(chat, peer->client_id);

    if (peernum != -1)
        return peernum;

    GC_GroupPeer *temp = realloc(chat->group, sizeof(GC_GroupPeer) * (chat->numpeers + 1));

    if (temp == NULL)
        return -1;

    peernum = chat->numpeers++;
    memcpy(&(temp[peernum]), peer, sizeof(GC_GroupPeer));

    chat->group = temp;
    chat->group[peernum].last_rcvd_ping = unix_time();

    peers_to_address_format(chat, NULL);

    if (chat->group_peer_join)
        (*chat->group_peer_join)(chat, peernum, chat->group_peer_join_userdata);

    return peernum;
}

static int gc_peer_update(GC_Chat *chat, const GC_GroupPeer *peer, uint32_t peernum)
{
    memcpy(&(chat->group[peernum]), peer, sizeof(GC_GroupPeer));
    return 0;
}

int gc_to_peer(const GC_Chat *chat, GC_GroupPeer *peer)
{
    // NB: we cannot add out ip_port
    memcpy(peer->client_id, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(peer->invite_certificate, chat->self_invite_certificate, INVITE_CERTIFICATE_SIGNED_SIZE);
    memcpy(peer->common_certificate, chat->self_common_certificate, COMMON_CERTIFICATE_SIGNED_SIZE*MAX_CERTIFICATES_NUM);
    memcpy(peer->nick, chat->self_nick, chat->self_nick_len);
    peer->nick_len = chat->self_nick_len;
    peer->role = chat->self_role;
    peer->last_update_time = unix_time();

    return 0;
}

static void check_peer_timeouts(GC_Chat *chat)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (is_timeout(chat->group[i].last_rcvd_ping, BAD_GROUPNODE_TIMEOUT))
            gc_peer_delete(chat, i, (const uint8_t *) "Timed out", 9);
    }
}

static void ping_group(GC_Chat *chat)
{
    if (chat->group_address_only == NULL)
        return;

    if (is_timeout(chat->last_sent_ping_time, GROUP_PING_INTERVAL)) {
        // TODO: add validation to send_ping
        send_gc_ping(chat, chat->group_address_only, chat->numpeers);  
        chat->last_sent_ping_time = unix_time();
    }
}

void do_gc(GC_Session *c)
{
    uint32_t i;
    
    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].self_status != GS_NONE) {
            ping_group(&c->chats[i]);
            check_peer_timeouts(&c->chats[i]);
        }
    }
}

GC_ChatCredentials *new_groupcredentials(void)
{
    GC_ChatCredentials *credentials = calloc(1, sizeof(GC_ChatCredentials));

    if (credentials == NULL)
        return NULL;

    create_long_keypair(credentials->chat_public_key, credentials->chat_secret_key);
    credentials->creation_time = unix_time();

    return credentials;
}

/* Set the size of the groupchat list to n.
 *
 *  return -1 on failure.
 *  return 0 success.
 */
static int realloc_groupchats(GC_Session *c, uint32_t n)
{
    if (n == 0) {
        free(c->chats);
        c->chats = NULL;
        return 0;
    }

    GC_Chat *temp = realloc(c->chats, n * sizeof(GC_Chat));

    if (temp == NULL)
        return -1;

    c->chats = temp;
    return 0;
}

static int get_new_group_index(GC_Session *c)
{
    if (c == NULL)
        return -1;

    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].self_status == GS_NONE)
            return i;
    }

    if (realloc_groupchats(c, c->num_chats + 1) != 0)
        return -1;

    ++c->num_chats;
    return c->num_chats - 1;
}

static int create_new_group(GC_Session *c)
{
    // TODO: Need to handle the situation when we load info from locally stored data
    int new_index = get_new_group_index(c);

    if (new_index == -1)
        return -1;


    GC_Chat *chat = &c->chats[new_index];

    chat->self_status = GS_ONLINE;
    chat->numpeers = 0;
    chat->last_synced_time = 0; // TODO: delete this later, it's for testing now

    create_long_keypair(chat->self_public_key, chat->self_secret_key);
    
    chat->hash_id = calculate_hash(chat->self_public_key, EXT_PUBLIC_KEY);
    
    return new_index;
}

/* Adds a new group chat
 *
 * Return groupnumber on success
 * Return -1 on failure
 */
int gc_group_add(GC_Session *c)
{
    return create_new_group(c);
}

/* Creates a group chat and sends an invite request using invite_key
 *
 * Return groupnumber on success.
 * Reutrn -1 on failure.
 */
int gc_group_join(GC_Session *c, const uint8_t *invite_key)
{
    int groupnumber = create_new_group(c);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    IP_Port port;  // TODO: fill me out

    if (gc_send_invite_request(chat, port, invite_key) == -1)
        return -1;

    return groupnumber;
}

void kill_groupcredentials(GC_ChatCredentials *credentials)
{
    free(credentials->ops);
    free(credentials);
}

/* Deletes chat from group chat array and cleans up.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gc_group_delete(GC_Session* c, GC_Chat *chat, const uint8_t *partmessage, uint32_t length)
{
    if (c == NULL)
        return -1;

    if (length > MAX_GC_PART_MESSAGE_SIZE)
        send_gc_self_exit(chat, NULL, 0);
    else
        send_gc_self_exit(chat, partmessage, length);

    if (chat->credentials)
        kill_groupcredentials(chat->credentials);

    if (chat->group)
        free(chat->group);

    if (chat->group_address_only)
        free(chat->group_address_only);

    memset(chat, 0, sizeof(GC_Chat));

    uint32_t i;

    for (i = c->num_chats; i > 0; --i) {
        if (c->chats[i-1].self_status != GS_NONE)
            break;
    }

    if (c->num_chats != i) {
        c->num_chats = i;

        if (realloc_groupchats(c, c->num_chats) != 0)
            return -1;
    }

    return 0;
}

GC_Session* new_groupchats(Messenger* m)
{
    GC_Session* retu = calloc(sizeof(GC_Session), 1);

    if (retu == NULL)
        return NULL;

    retu->messenger = m;

    networking_registerhandler(m->net, NET_PACKET_GROUP_CHATS, &handle_groupchatpacket, m->group_handler);
    return retu;
}

void gc_kill_groupchats(GC_Session* c)
{
    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].self_status != GS_NONE)
            gc_group_delete(c, &c->chats[i], (const uint8_t *) "Quit", 4);
    }
    
    networking_registerhandler(c->messenger->net, NET_PACKET_GROUP_CHATS, NULL, NULL);
    free(c);
}

/* Return 1 if groupnumber is a valid group chat index
 * Return 0 otherwise
 */
static int groupnumber_valid(const GC_Session* c, int groupnumber)
{
    if (groupnumber < 0 || groupnumber >= c->num_chats)
        return 0;

    if (c->chats == NULL)
        return 0;

    return c->chats[groupnumber].self_status != GS_NONE;
}

/* Return groupnumber's GC_Chat pointer on success
 * Return NULL on failure
 */
GC_Chat *gc_get_group(const GC_Session* c, int groupnumber)
{
    if (!groupnumber_valid(c, groupnumber))
        return NULL;

    return &c->chats[groupnumber];
}
