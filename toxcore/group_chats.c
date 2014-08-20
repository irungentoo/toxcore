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
#include "assoc.h"
#include "group_chats.h"
#include "LAN_discovery.h"
#include "util.h"

#define GROUPCHAT_MAXDATA_LENGTH (MAX_CRYPTO_REQUEST_SIZE - (1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES))
#define GROUPCHAT_MAXPLAINDATA_LENGTH (GROUPCHAT_MAXDATA_LENGTH - crypto_box_MACBYTES)

#define GROUP_MAX_SENDNODES (GROUP_CLOSE_CONNECTIONS * 2)

typedef struct {
    uint64_t   pingid;
    //uint8_t    client_id[crypto_box_PUBLICKEYBYTES];

} getnodes_data;

typedef struct {
    uint8_t    client_id[crypto_box_PUBLICKEYBYTES];
    IP_Port    ip_port;

} groupchat_nodes;

typedef struct {
    uint64_t   pingid;
    groupchat_nodes nodes[GROUP_CLOSE_CONNECTIONS];
    //uint8_t    client_id[crypto_box_PUBLICKEYBYTES];

} sendnodes_data;

/*
 * check if peer with client_id is in peer array.
 *
 * return peer number if peer is in chat.
 * return -1 if peer is not in chat.
 *
 * TODO: make this more efficient.
 */

static int peer_in_chat(const Group_Chat *chat, const uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i)
        if (id_equal(chat->group[i].client_id, client_id))
            return i;

    return -1;
}

/* Compares client_id1 and client_id2 with client_id.
 *
 *  return 0 if both are same distance.
 *  return 1 if client_id1 is closer.
 *  return 2 if client_id2 is closer.
 */
static int id_closest_groupchats(const uint8_t *id, const uint8_t *id1, const uint8_t *id2)
{
    size_t   i;
    uint8_t distance1, distance2;

    for (i = 0; i < CLIENT_ID_SIZE; ++i) {

        distance1 = abs(((int8_t *)id)[i] - ((int8_t *)id1)[i]);
        distance2 = abs(((int8_t *)id)[i] - ((int8_t *)id2)[i]);

        if (distance1 < distance2)
            return 1;

        if (distance1 > distance2)
            return 2;
    }

    return 0;
}

#define BAD_GROUPNODE_TIMEOUT 30

/*
 * Check if peer is closer to us that the other peers in the list and if the peer is in the list.
 * Return the number of peers it is closer to if it is not in the closelist.
 * Return -1 if the peer is in the closelist.
 */

static int peer_okping(const Group_Chat *chat, const uint8_t *client_id)
{
    uint32_t i, j = 0;

    if (id_equal(chat->self_public_key, client_id))
        return -1;

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) {
        if (is_timeout(chat->close[i].last_recv, BAD_GROUPNODE_TIMEOUT)) {
            ++j;
            continue;
        }

        /* Equal */
        if (id_equal(chat->close[i].client_id, client_id))
            return -1;

        if (id_closest_groupchats(chat->self_public_key, chat->close[i].client_id, client_id) == 2)
            ++j;
    }

    return j;
}



/* Attempt to add a peer to the close list.
 * Update last_recv if it is in list.
 * Attempt to add it to list if it is not.
 *
 * Return 0 if success.
 * Return -1 if peer was not put in list/updated.
 */
static int add_closepeer(Group_Chat *chat, const uint8_t *client_id, IP_Port ip_port)
{
    uint32_t i;

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) { /* Check if node is already in list, if it is update its last_recv */
        if (id_equal(chat->close[i].client_id, client_id)) {
            chat->close[i].last_recv = unix_time();
            return 0;
        }
    }

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) { /* Try replacing bad nodes first */
        if (is_timeout(chat->close[i].last_recv, BAD_GROUPNODE_TIMEOUT)) {
            id_copy(chat->close[i].client_id, client_id);
            chat->close[i].ip_port = ip_port;
            chat->close[i].last_recv = unix_time();
            return 0;
        }
    }

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) { /* Replace nodes if given one is closer. */
        if (id_closest_groupchats(chat->self_public_key, chat->close[i].client_id, client_id) == 2) {
            id_copy(chat->close[i].client_id, client_id);
            chat->close[i].ip_port = ip_port;
            chat->close[i].last_recv = unix_time();
            return 0;
        }
    }

    return -1;
}

static int send_groupchatpacket(const Group_Chat *chat, IP_Port ip_port, const uint8_t *public_key, const uint8_t *data,
                                uint32_t length, uint8_t request_id)
{
    if (id_equal(chat->self_public_key, public_key))
        return -1;

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    int len = create_request(chat->self_public_key, chat->self_secret_key, packet, public_key, data, length, request_id);
    packet[0] = NET_PACKET_GROUP_CHATS;

    if (len == -1)
        return -1;

    if (sendpacket(chat->net, ip_port, packet, len) == len)
        return 0;

    return -1;

}

/*
 * Send data to all peers in close peer list.
 *
 * return the number of peers the packet was sent to.
 */
static uint8_t sendto_allpeers(const Group_Chat *chat, const uint8_t *data, uint16_t length, uint8_t request_id)
{
    uint16_t sent = 0;
    uint32_t i;

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) {
        if (ip_isset(&chat->close[i].ip_port.ip) &&
                !is_timeout(chat->close[i].last_recv, BAD_GROUPNODE_TIMEOUT)) {
            if (send_groupchatpacket(chat, chat->close[i].ip_port, chat->close[i].client_id,
                                     data, length, request_id) == 0)
                ++sent;
        }
    }

    return sent;
}


/*
 * Add a peer to the group chat.
 *
 * return peernum if success or peer already in chat.
 * return -1 if error.
 */
static int addpeer(Group_Chat *chat, const uint8_t *client_id)
{
    int peernum = peer_in_chat(chat, client_id);

    if (peernum != -1)
        return peernum;

    Group_Peer *temp;
    temp = realloc(chat->group, sizeof(Group_Peer) * (chat->numpeers + 1));

    if (temp == NULL)
        return -1;

    memset(&(temp[chat->numpeers]), 0, sizeof(Group_Peer));
    chat->group = temp;

    id_copy(chat->group[chat->numpeers].client_id, client_id);
    chat->group[chat->numpeers].last_recv = unix_time();
    chat->group[chat->numpeers].last_recv_msgping = unix_time();
    ++chat->numpeers;

    if (chat->peer_namelistchange != NULL)
        (*chat->peer_namelistchange)(chat, chat->numpeers - 1, CHAT_CHANGE_PEER_ADD, chat->group_namelistchange_userdata);

    return (chat->numpeers - 1);
}

/*
 * Set a peer from the group chat to deleted.
 *
 * return 0 if success
 * return -1 if error.
 */
static int del_peer_set(Group_Chat *chat, int peernum)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return -1;

    chat->group[peernum].deleted = 1;
    chat->group[peernum].deleted_time = unix_time();
    return 0;
}

/*
 * Delete a peer from the group chat.
 *
 * return 0 if success
 * return -1 if error.
 */
static int delpeer(Group_Chat *chat, int peernum)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return -1;

    uint32_t i;

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) { /* If peer is in close list, time it out forcefully. */
        if (id_equal(chat->close[i].client_id, chat->group[peernum].client_id)) {
            chat->close[i].last_recv = 0;
            break;
        }
    }

    Group_Peer *temp;
    --chat->numpeers;

    if (chat->numpeers == 0) {
        free(chat->group);
        chat->group = NULL;
        return 0;
    }

    if (chat->numpeers != (uint32_t)peernum)
        memcpy(&chat->group[peernum], &chat->group[chat->numpeers], sizeof(Group_Peer));

    temp = realloc(chat->group, sizeof(Group_Peer) * (chat->numpeers));

    if (temp == NULL)
        return -1;

    chat->group = temp;

    if (chat->peer_namelistchange != NULL) {
        (*chat->peer_namelistchange)(chat, peernum, CHAT_CHANGE_PEER_DEL, chat->group_namelistchange_userdata);
    }

    return 0;
}

/* Copy the name of peernum to name.
 * name must be at least MAX_NICK_BYTES long.
 *
 * return length of name if success
 * return -1 if failure
 */
int group_peername(const Group_Chat *chat, int peernum, uint8_t *name)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return -1;

    if (chat->group[peernum].nick_len == 0) {
        /* memcpy(name, "NSA agent", 10); */ /* Srsly? */ /* Kindly remind the user that someone with no name might be a moronic NSA agent.*/
        name[0] = 0;
        return 0;
    }

    memcpy(name, chat->group[peernum].nick, chat->group[peernum].nick_len);
    return chat->group[peernum].nick_len;
}

static void setnick(Group_Chat *chat, int peernum, const uint8_t *contents, uint16_t contents_len)
{
    if (contents_len > MAX_NICK_BYTES || contents_len == 0)
        return;

    /* same name as already stored? */
    if (chat->group[peernum].nick_len == contents_len)
        if (!memcmp(chat->group[peernum].nick, contents, contents_len))
            return;

    memcpy(chat->group[peernum].nick, contents, contents_len);
    chat->group[peernum].nick_len = contents_len;

    if (chat->peer_namelistchange != NULL)
        (*chat->peer_namelistchange)(chat, peernum, CHAT_CHANGE_PEER_NAME, chat->group_namelistchange_userdata);
}

/* min time between pings sent to one peer in seconds */
/* TODO: move this to global section */
#define GROUP_PING_TIMEOUT 5

static int send_getnodes(const Group_Chat *chat, IP_Port ip_port, int peernum)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return -1;

    if (!is_timeout(chat->group[peernum].last_pinged, GROUP_PING_TIMEOUT))
        return -1;

    getnodes_data contents;
    contents.pingid = random_64b();

    chat->group[peernum].last_pinged = unix_time();
    chat->group[peernum].pingid = contents.pingid;
    chat->group[peernum].ping_via = ip_port;

    if (chat->assoc) {
        IPPTs ippts;
        ippts.timestamp = unix_time();
        ippts.ip_port = ip_port;

        Assoc_add_entry(chat->assoc, chat->group[peernum].client_id, &ippts, NULL, 1);
    }

    return send_groupchatpacket(chat, ip_port, chat->group[peernum].client_id, (uint8_t *)&contents, sizeof(contents),
                                CRYPTO_PACKET_GROUP_CHAT_GET_NODES);
}

static int send_sendnodes(const Group_Chat *chat, IP_Port ip_port, int peernum, uint64_t pingid)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return -1;

    sendnodes_data contents;
    contents.pingid = pingid;
    uint32_t i, j = 0;

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) {
        if (!is_timeout(chat->close[i].last_recv, BAD_GROUPNODE_TIMEOUT)) {
            id_copy(contents.nodes[j].client_id, chat->close[i].client_id);
            contents.nodes[j].ip_port = chat->close[i].ip_port;
            to_net_family(&contents.nodes[j].ip_port.ip);
            ++j;
        }
    }

    return send_groupchatpacket(chat, ip_port, chat->group[peernum].client_id, (uint8_t *)&contents,
                                sizeof(contents.pingid) + sizeof(groupchat_nodes) * j, CRYPTO_PACKET_GROUP_CHAT_SEND_NODES);
}

static int handle_getnodes(const Group_Chat *chat, IP_Port source, int peernum, const uint8_t *data, uint32_t len)
{
    if (len != sizeof(getnodes_data))
        return 1;

    if ((uint32_t)peernum >= chat->numpeers)
        return 1;

    getnodes_data contents;
    memcpy(&contents, data, sizeof(contents));
    send_sendnodes(chat, source, peernum, contents.pingid);

    if (peer_okping(chat, chat->group[peernum].client_id) > 0)
        send_getnodes(chat, source, peernum);

    return 0;
}

static int handle_sendnodes(Group_Chat *chat, IP_Port source, int peernum, const uint8_t *data, uint32_t len)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return 1;

    if (len > sizeof(sendnodes_data) || len < sizeof(uint64_t))
        return 1;

    if ((len - sizeof(uint64_t)) % sizeof(groupchat_nodes) != 0)
        return 1;

    if (is_timeout(chat->group[peernum].last_pinged, GROUP_PING_TIMEOUT))
        return 1;

    sendnodes_data contents;
    memcpy(&contents, data, len);

    if (contents.pingid != chat->group[peernum].pingid)
        return 1;

    uint16_t numnodes = (len - sizeof(contents.pingid)) / sizeof(groupchat_nodes);
    uint32_t i;

    IPPTs ippts_send;
    ippts_send.timestamp = unix_time();

    for (i = 0; i < numnodes; ++i) {
        if (peer_okping(chat, contents.nodes[i].client_id) > 0) {
            int peern = peer_in_chat(chat, contents.nodes[i].client_id);

            if (peern == -1) { /*NOTE: This is just for testing and will be removed later.*/
                peern = addpeer(chat, contents.nodes[i].client_id);
            }

            if (peern == -1)
                continue;

            to_host_family(&contents.nodes[i].ip_port.ip);
            send_getnodes(chat, contents.nodes[i].ip_port, peern);

            if (chat->assoc) {
                ippts_send.ip_port = contents.nodes[i].ip_port;
                Assoc_add_entry(chat->assoc, contents.nodes[i].client_id, &ippts_send, NULL, 0);
            }
        }
    }

    int ok = add_closepeer(chat, chat->group[peernum].client_id, source);

    return 0;
}

#define GROUP_DATA_MIN_SIZE (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t) + 1)
static void send_names_new_peer(Group_Chat *chat);

static int handle_data(Group_Chat *chat, const uint8_t *data, uint32_t len)
{
    if (len < GROUP_DATA_MIN_SIZE)
        return 1;

//TODO:
    int peernum = peer_in_chat(chat, data);

    if (peernum == -1) { /*NOTE: This is just for testing and will be removed later.*/
        if (data[crypto_box_PUBLICKEYBYTES + sizeof(uint32_t)] != GROUP_CHAT_QUIT)
            peernum = addpeer(chat, data);
    }

    if (peernum == -1)
        return 1;

    if (chat->group[peernum].deleted)
        return 1;

    /* Spam prevention (1 message per peer per second limit.)

        if (chat->group[peernum].last_recv == temp_time)
            return 1;
    */
    chat->group[peernum].last_recv = unix_time();

    uint32_t message_num;
    memcpy(&message_num, data + crypto_box_PUBLICKEYBYTES, sizeof(uint32_t));
    message_num = ntohl(message_num);

    if (chat->group[peernum].last_message_number == 0) {
        chat->group[peernum].last_message_number = message_num;
    } else if (message_num - chat->group[peernum].last_message_number > 64 ||
               message_num == chat->group[peernum].last_message_number)
        return 1;

    chat->group[peernum].last_message_number = message_num;

    int handled = 1;
    const uint8_t *contents = data + GROUP_DATA_MIN_SIZE;
    uint16_t contents_len = len - GROUP_DATA_MIN_SIZE;

    switch (data[crypto_box_PUBLICKEYBYTES + sizeof(message_num)]) {
        case GROUP_CHAT_PING: /* If message is ping */
            if (contents_len != 0)
                return 1;

            chat->group[peernum].last_recv_msgping = unix_time();
            break;

        case GROUP_CHAT_NEW_PEER: /* If message is new peer */
            if (contents_len != crypto_box_PUBLICKEYBYTES)
                return 1;

            addpeer(chat, contents);
            send_names_new_peer(chat);
            break;

        case GROUP_CHAT_QUIT: /* If peer tells us he is quitting */
            if (contents_len != 0)
                return 1;

            del_peer_set(chat, peernum);
            break;

        case GROUP_CHAT_PEER_NICK:
            if (contents_len > MAX_NICK_BYTES || contents_len == 0)
                return 1;

            setnick(chat, peernum, contents, contents_len);
            break;

        case GROUP_CHAT_CHAT_MESSAGE: /* If message is chat message */
            if (chat->group_message != NULL)
                (*chat->group_message)(chat, peernum, contents, contents_len, chat->group_message_userdata);

            break;

        case GROUP_CHAT_ACTION: /* if message is a peer action */
            if (chat->group_action != NULL)
                (*chat->group_action)(chat, peernum, contents, contents_len, chat->group_action_userdata);

            break;

        default:
            handled = 0;
            break;

    }

    if (handled == 1) {
        sendto_allpeers(chat, data, len, CRYPTO_PACKET_GROUP_CHAT_BROADCAST);
        return 0;
    }

    return 1;
}

static uint8_t send_data(Group_Chat *chat, const uint8_t *data, uint32_t len, uint8_t message_id)
{
    if (len + GROUP_DATA_MIN_SIZE > MAX_CRYPTO_REQUEST_SIZE) /*NOTE: not the real maximum len.*/
        return 1;

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    ++chat->message_number;

    if (chat->message_number == 0)
        chat->message_number = 1;

    uint32_t message_num = htonl(chat->message_number);
//TODO
    id_copy(packet, chat->self_public_key);
    memcpy(packet + crypto_box_PUBLICKEYBYTES, &message_num, sizeof(message_num));

    if (len != 0)
        memcpy(packet + GROUP_DATA_MIN_SIZE, data, len);

    packet[crypto_box_PUBLICKEYBYTES + sizeof(message_num)] = message_id;
    return sendto_allpeers(chat, packet, len + GROUP_DATA_MIN_SIZE, CRYPTO_PACKET_GROUP_CHAT_BROADCAST);
}
/*
 * Handle get nodes group packet.
 *
 * return 0 if handled correctly.
 * return 1 if error.
 */

int handle_groupchatpacket(Group_Chat *chat, IP_Port source, const uint8_t *packet, uint32_t length)
{
    if (length > MAX_CRYPTO_REQUEST_SIZE)
        return 1;

    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t data[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t number;
    int len = handle_request(chat->self_public_key, chat->self_secret_key, public_key, data, &number, packet, length);

    if (len <= 0)
        return 1;

    if (id_equal(chat->self_public_key, public_key))
        return 1;

    int peernum = peer_in_chat(chat, public_key);

    if (peernum == -1)
        return 1;

    switch (number) {
        case CRYPTO_PACKET_GROUP_CHAT_GET_NODES:
            return handle_getnodes(chat, source, peernum, data, len);

        case CRYPTO_PACKET_GROUP_CHAT_SEND_NODES:
            return handle_sendnodes(chat, source, peernum, data, len);

        case CRYPTO_PACKET_GROUP_CHAT_BROADCAST:
            return handle_data(chat, data, len);

        default:
            return 1;
    }

    return 1;
}

uint32_t group_sendmessage(Group_Chat *chat, const uint8_t *message, uint32_t length)
{
    return send_data(chat, message, length, GROUP_CHAT_CHAT_MESSAGE); //TODO: better return values?
}

uint32_t group_sendaction(Group_Chat *chat, const uint8_t *action, uint32_t length)
{
    return send_data(chat, action, length, GROUP_CHAT_ACTION);
}

/*
 * Send id/nick combo to the group.
 *
 * returns the number of peers it has sent it to.
 */
static uint32_t group_send_nick(Group_Chat *chat, uint8_t *nick, uint16_t nick_len)
{
    if (nick_len > MAX_NICK_BYTES)
        return 0;

    return send_data(chat, nick, nick_len, GROUP_CHAT_PEER_NICK);
}

int set_nick(Group_Chat *chat, const uint8_t *nick, uint16_t nick_len)
{
    if (nick_len > MAX_NICK_BYTES || nick_len == 0)
        return -1;

    memcpy(chat->nick, nick, nick_len);
    chat->nick_len = nick_len;
    group_send_nick(chat, chat->nick, chat->nick_len);
    return 0;
}

uint32_t group_newpeer(Group_Chat *chat, const uint8_t *client_id)
{
    addpeer(chat, client_id);
    return send_data(chat, client_id, crypto_box_PUBLICKEYBYTES, GROUP_CHAT_NEW_PEER); //TODO: better return values?
}

void callback_groupmessage(Group_Chat *chat, void (*function)(Group_Chat *chat, int, const uint8_t *, uint16_t, void *),
                           void *userdata)
{
    chat->group_message = function;
    chat->group_message_userdata = userdata;
}

void callback_groupaction(Group_Chat *chat, void (*function)(Group_Chat *chat, int, const uint8_t *, uint16_t, void *),
                          void *userdata)
{
    chat->group_action = function;
    chat->group_action_userdata = userdata;
}

void callback_namelistchange(Group_Chat *chat, void (*function)(Group_Chat *chat, int peer, uint8_t change, void *),
                             void *userdata)
{
    chat->peer_namelistchange = function;
    chat->group_namelistchange_userdata = userdata;
}

uint32_t group_numpeers(const Group_Chat *chat)
{
    return chat->numpeers;
}

uint32_t group_client_names(const Group_Chat *chat, uint8_t names[][MAX_NICK_BYTES], uint16_t lengths[],
                            uint16_t length)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers && i < length; ++i) {
        lengths[i] = group_peername(chat, i, names[i]);
    }

    return i;
}

Group_Chat *new_groupchat(Networking_Core *net)
{
    unix_time_update();

    if (net == 0)
        return 0;

    Group_Chat *chat = calloc(1, sizeof(Group_Chat));
    chat->net = net;
    crypto_box_keypair(chat->self_public_key, chat->self_secret_key);

    /* (2^4) * 5 = 80 entries seems to be a moderate size */
    chat->assoc = new_Assoc(4, 5, chat->self_public_key);

    return chat;
}

#define NODE_PING_INTERVAL 10

static void ping_close(Group_Chat *chat)
{
    uint32_t i;

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) {
        if (!is_timeout(chat->close[i].last_recv, BAD_GROUPNODE_TIMEOUT)) {
            int peernum = peer_in_chat(chat, chat->close[i].client_id);

            if (peernum == -1)
                continue;

            if (is_timeout(chat->group[peernum].last_pinged, NODE_PING_INTERVAL))
                send_getnodes(chat, chat->close[i].ip_port, peernum);
        }
    }
}

/* Interval in seconds to send ping messages */
#define GROUP_PING_INTERVAL 30

static void ping_group(Group_Chat *chat)
{
    if (is_timeout(chat->last_sent_ping, GROUP_PING_INTERVAL)) {
        if (send_data(chat, 0, 0, GROUP_CHAT_PING) != 0) /* Ping */
            chat->last_sent_ping = unix_time();
    }
}

#define DEL_PEER_DELAY 3
static void del_dead_peers(Group_Chat *chat)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (is_timeout(chat->group[i].last_recv_msgping, GROUP_PING_INTERVAL * 4)) {
            delpeer(chat, i);
        }

        if (chat->group == NULL || i >= chat->numpeers)
            break;

        if (chat->group[i].deleted) {
            if (is_timeout(chat->group[i].deleted_time, DEL_PEER_DELAY))
                delpeer(chat, i);
        }
    }
}

#define NICK_SEND_INTERVAL 180
static void send_names_new_peer(Group_Chat *chat)
{
    group_send_nick(chat, chat->nick, chat->nick_len);
    chat->last_sent_nick = (unix_time() - NICK_SEND_INTERVAL) + 15;
}
static void send_names(Group_Chat *chat)
{
    /* send own nick from time to time, to let newly added peers be informed
    * first time only: use a shorter timeframe, because we might not be in our own
    * peer list yet */
    if (is_timeout(chat->last_sent_nick, 180))
        if (group_send_nick(chat, chat->nick, chat->nick_len) > 0) {
            if (!chat->last_sent_nick)
                chat->last_sent_nick = (unix_time() - NICK_SEND_INTERVAL) + 10;
            else
                chat->last_sent_nick = unix_time();
        }
}

void do_groupchat(Group_Chat *chat)
{
    unix_time_update();
    ping_close(chat);
    ping_group(chat);
    /* TODO: Maybe run this less? */
    del_dead_peers(chat);
    send_names(chat);
}

void kill_groupchat(Group_Chat *chat)
{
    send_data(chat, 0, 0, GROUP_CHAT_QUIT);
    kill_Assoc(chat->assoc);
    free(chat->group);
    free(chat);
}

void chat_bootstrap(Group_Chat *chat, IP_Port ip_port, const uint8_t *client_id)
{
    send_getnodes(chat, ip_port, addpeer(chat, client_id));
}

void chat_bootstrap_nonlazy(Group_Chat *chat, IP_Port ip_port, const uint8_t *client_id)
{
    send_getnodes(chat, ip_port, addpeer(chat, client_id));
    add_closepeer(chat, client_id, ip_port);
}
