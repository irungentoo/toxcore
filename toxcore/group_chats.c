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

#include "group_chats.h"


#define GROUPCHAT_MAXDATA_LENGTH (MAX_DATA_SIZE - (1 + crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES))
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

static int peer_in_chat(Group_Chat *chat, uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        /* Equal */
        if (memcmp(chat->group[i].client_id, client_id, crypto_box_PUBLICKEYBYTES) == 0)
            return i;
    }

    return -1;
}

#define BAD_NODE_TIMEOUT 30

/*
 * Check if peer is closer to us that the other peers in the list and if the peer is in the list.
 * Return the number of peers it is closer to if it is not in the closelist.
 * Return -1 if the peer is in the closelist.
 */

static int peer_okping(Group_Chat *chat, uint8_t *client_id)
{
    uint32_t i, j = 0;
    uint64_t temp_time = unix_time();

    if (memcmp(chat->self_public_key, client_id, crypto_box_PUBLICKEYBYTES) == 0)
        return -1;

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) {
        if (chat->close[i].last_recv + BAD_NODE_TIMEOUT < temp_time) {
            ++j;
            continue;
        }

        /* Equal */
        if (memcmp(chat->close[i].client_id, client_id, crypto_box_PUBLICKEYBYTES) == 0)
            return -1;

        if (id_closest(chat->self_public_key, chat->close[i].client_id, client_id) == 2)
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
static int add_closepeer(Group_Chat *chat, uint8_t *client_id, IP_Port ip_port)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) { /* Check if node is already in list, if it is update its last_recv */
        if (memcmp(chat->close[i].client_id, client_id, crypto_box_PUBLICKEYBYTES) == 0) {
            chat->close[i].last_recv = temp_time;
            return 0;
        }
    }

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) { /* Try replacing bad nodes first */
        if (chat->close[i].last_recv + BAD_NODE_TIMEOUT < temp_time) {
            memcpy(chat->close[i].client_id, client_id, crypto_box_PUBLICKEYBYTES);
            chat->close[i].ip_port = ip_port;
            chat->close[i].last_recv = temp_time;
            return 0;
        }
    }

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) { /* Replace nodes if given one is closer. */
        if (id_closest(chat->self_public_key, chat->close[i].client_id, client_id) == 2) {
            memcpy(chat->close[i].client_id, client_id, crypto_box_PUBLICKEYBYTES);
            chat->close[i].ip_port = ip_port;
            chat->close[i].last_recv = temp_time;
            return 0;
        }
    }

    return -1;
}

static int send_groupchatpacket(Group_Chat *chat, IP_Port ip_port, uint8_t *public_key, uint8_t *data, uint32_t length,
                                uint8_t request_id)
{
    if (memcmp(chat->self_public_key, public_key, crypto_box_PUBLICKEYBYTES) == 0)
        return -1;

    uint8_t packet[MAX_DATA_SIZE];
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
static uint8_t sendto_allpeers(Group_Chat *chat, uint8_t *data, uint16_t length, uint8_t request_id)
{
    uint16_t sent = 0;
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) {
        if (ip_isset(&chat->close[i].ip_port.ip) && chat->close[i].last_recv + BAD_NODE_TIMEOUT > temp_time) {
            if (send_groupchatpacket(chat, chat->close[i].ip_port, chat->close[i].client_id, data, length, request_id) == 0)
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
static int addpeer(Group_Chat *chat, uint8_t *client_id)
{
    int peernum = peer_in_chat(chat, client_id);

    if (peernum != -1)
        return peernum;

    Group_Peer *temp;
    temp = realloc(chat->group, sizeof(Group_Peer) * (chat->numpeers + 1));
    memset(&(temp[chat->numpeers]), 0, sizeof(Group_Peer));

    if (temp == NULL)
        return -1;

    chat->group = temp;
    memcpy(chat->group[chat->numpeers].client_id, client_id, crypto_box_PUBLICKEYBYTES);
    ++chat->numpeers;
    return (chat->numpeers - 1);
}

/*
 * Delete a peer to the group chat.
 *
 * return 0 if success
 * return -1 if error.
 */
static int delpeer(Group_Chat *chat, uint8_t *client_id)
{
    uint32_t i;
    Group_Peer *temp;

    for (i = 0; i < chat->numpeers; ++i) {
        /* Equal */
        if (memcmp(chat->group[i].client_id, client_id, crypto_box_PUBLICKEYBYTES) == 0) {
            --chat->numpeers;

            if (chat->numpeers != i) {
                memcpy( chat->group[i].client_id,
                        chat->group[chat->numpeers].client_id,
                        crypto_box_PUBLICKEYBYTES );
            }

            temp = realloc(chat->group, sizeof(Group_Peer) * (chat->numpeers));

            if (temp == NULL)
                return -1;

            chat->group = temp;
            return 0;
        }
    }

    return -1;
}

/* Copy the name of peernum to name.
 * name must be at least MAX_NICK_BYTES long.
 *
 * return length of name if success
 * return -1 if failure
 */
int group_peername(Group_Chat *chat, int peernum, uint8_t *name)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return -1;

    if (chat->group[peernum].nick_len == 0) {
        memcpy(name, "NSA Agent", 10); /* Kindly remind the user that someone with no name might be a NSA agent.*/
        return 10;
    }

    memcpy(name, chat->group[peernum].nick, chat->group[peernum].nick_len);
    return chat->group[peernum].nick_len;
}


/* min time between pings sent to one peer in seconds */
#define PING_TIMEOUT 5
static int send_getnodes(Group_Chat *chat, IP_Port ip_port, int peernum)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return -1;

    uint64_t temp_time = unix_time();

    getnodes_data contents;

    if (chat->group[peernum].last_pinged + PING_TIMEOUT > temp_time)
        return -1;

    contents.pingid = ((uint64_t)random_int() << 32) + random_int();
    chat->group[peernum].last_pinged = temp_time;
    chat->group[peernum].pingid = contents.pingid;
    return send_groupchatpacket(chat, ip_port, chat->group[peernum].client_id, (uint8_t *)&contents, sizeof(contents), 48);
}

static int send_sendnodes(Group_Chat *chat, IP_Port ip_port, int peernum, uint64_t pingid)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return -1;

    sendnodes_data contents;
    contents.pingid = pingid;
    uint32_t i, j = 0;
    uint64_t temp_time = unix_time();

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) {
        if (chat->close[i].last_recv + BAD_NODE_TIMEOUT > temp_time) {
            memcpy(contents.nodes[j].client_id, chat->close[i].client_id, crypto_box_PUBLICKEYBYTES);
            contents.nodes[j].ip_port = chat->close[i].ip_port;
            ++j;
        }
    }

    return send_groupchatpacket(chat, ip_port, chat->group[peernum].client_id, (uint8_t *)&contents,
                                sizeof(contents.pingid) + sizeof(groupchat_nodes) * j, 49);
}

static int handle_getnodes(Group_Chat *chat, IP_Port source, int peernum, uint8_t *data, uint32_t len)
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

static int handle_sendnodes(Group_Chat *chat, IP_Port source, int peernum, uint8_t *data, uint32_t len)
{
    if ((uint32_t)peernum >= chat->numpeers)
        return 1;

    if (len > sizeof(sendnodes_data) || len < sizeof(uint64_t))
        return 1;

    if ((len - sizeof(uint64_t)) % sizeof(groupchat_nodes) != 0)
        return 1;

    if (chat->group[peernum].last_pinged + PING_TIMEOUT < unix_time())
        return 1;

    sendnodes_data contents;
    memcpy(&contents, data, len);

    if (contents.pingid != chat->group[peernum].pingid)
        return 1;

    uint16_t numnodes = (len - sizeof(contents.pingid)) / sizeof(groupchat_nodes);
    uint32_t i;

    for (i = 0; i < numnodes; ++i) {
        if (peer_okping(chat, contents.nodes[i].client_id) > 0) {
            int peern = peer_in_chat(chat, contents.nodes[i].client_id);

            if (peern == -1) { /*NOTE: This is just for testing and will be removed later.*/
                peern = addpeer(chat, contents.nodes[i].client_id);
            }

            if (peern == -1)
                continue;

            send_getnodes(chat, contents.nodes[i].ip_port, peern);
        }
    }

    add_closepeer(chat, chat->group[peernum].client_id, source);
    return 0;
}
#define GROUP_DATA_MIN_SIZE (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t) + 1)
static int handle_data(Group_Chat *chat, uint8_t *data, uint32_t len)
{
    if (len < GROUP_DATA_MIN_SIZE)
        return 1;

//TODO:
    int peernum = peer_in_chat(chat, data);

    if (peernum == -1) { /*NOTE: This is just for testing and will be removed later.*/
        peernum = addpeer(chat, data);
    }

    if (peernum == -1)
        return 1;

    uint64_t temp_time = unix_time();
    /* Spam prevention (1 message per peer per second limit.)

        if (chat->group[peernum].last_recv == temp_time)
            return 1;

        chat->group[peernum].last_recv = temp_time;
    */
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
    uint8_t *contents = data + GROUP_DATA_MIN_SIZE;
    uint16_t contents_len = len - GROUP_DATA_MIN_SIZE;

    switch (data[crypto_box_PUBLICKEYBYTES + sizeof(message_num)]) {
        case 0: /* If message is ping */
            if (contents_len != 0)
                return 1;

            chat->group[peernum].last_recv_msgping = temp_time;
            break;

        case 16: /* If message is new peer */
            if (contents_len != crypto_box_PUBLICKEYBYTES)
                return 1;

            addpeer(chat, contents);
            break;

        case 64: /* If message is chat message */
            if (chat->group_message != NULL)
                (*chat->group_message)(chat, peernum, contents, contents_len, chat->group_message_userdata);

            break;

        default:
            handled = 0;
            break;

    }

    if (handled == 1) {
        sendto_allpeers(chat, data, len, 50);
        return 0;
    }

    return 1;
}

static uint8_t send_data(Group_Chat *chat, uint8_t *data, uint32_t len, uint8_t message_id)
{
    if (len + GROUP_DATA_MIN_SIZE > MAX_DATA_SIZE) /*NOTE: not the real maximum len.*/
        return 1;

    uint8_t packet[MAX_DATA_SIZE];
    ++chat->message_number;

    if (chat->message_number == 0)
        chat->message_number = 1;

    uint32_t message_num = htonl(chat->message_number);
//TODO
    memcpy(packet, chat->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(packet + crypto_box_PUBLICKEYBYTES, &message_num, sizeof(message_num));
    memcpy(packet + GROUP_DATA_MIN_SIZE, data, len);
    packet[crypto_box_PUBLICKEYBYTES + sizeof(message_num)] = message_id;
    return sendto_allpeers(chat, packet, len + GROUP_DATA_MIN_SIZE, 50);
}
/*
 * Handle get nodes group packet.
 *
 * return 0 if handled correctly.
 * return 1 if error.
 */

int handle_groupchatpacket(Group_Chat *chat, IP_Port source, uint8_t *packet, uint32_t length)
{
    if (length > MAX_DATA_SIZE)
        return 1;

    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t data[MAX_DATA_SIZE];
    uint8_t number;
    int len = handle_request(chat->self_public_key, chat->self_secret_key, public_key, data, &number, packet, length);

    if (len <= 0)
        return 1;

    if (memcmp(chat->self_public_key, public_key, crypto_box_PUBLICKEYBYTES) == 0)
        return 1;

    int peernum = peer_in_chat(chat, public_key);

    if (peernum == -1)
        return 1;

    switch (number) {
        case 48:
            return handle_getnodes(chat, source, peernum, data, len);

        case 49:
            return handle_sendnodes(chat, source, peernum, data, len);

        case 50:
            return handle_data(chat, data, len);

        default:
            return 1;
    }

    return 1;
}

uint32_t group_sendmessage(Group_Chat *chat, uint8_t *message, uint32_t length)
{
    return send_data(chat, message, length, 64); //TODO: better return values?
}

uint32_t group_newpeer(Group_Chat *chat, uint8_t *client_id)
{
    addpeer(chat, client_id);
    return send_data(chat, client_id, crypto_box_PUBLICKEYBYTES, 16); //TODO: better return values?
}

void callback_groupmessage(Group_Chat *chat, void (*function)(Group_Chat *chat, int, uint8_t *, uint16_t, void *),
                           void *userdata)
{
    chat->group_message = function;
    chat->group_message_userdata = userdata;
}

Group_Chat *new_groupchat(Networking_Core *net)
{
    if (net == 0)
        return 0;

    Group_Chat *chat = calloc(1, sizeof(Group_Chat));
    chat->net = net;
    crypto_box_keypair(chat->self_public_key, chat->self_secret_key);
    return chat;
}

Group_Chat *load_groupchat(Networking_Core *net, uint8_t *chat_old, size_t length)
{
    if (!net || !chat_old || (length < sizeof(Group_Chat)))
        return NULL;

    /* chat itself: allocate */
    Group_Chat *chat_new = calloc(1, sizeof(Group_Chat));
    if (!chat_new)
        return NULL;

    /* chat itself: load */
    memcpy(chat_new, chat_old, sizeof(Group_Chat));
    chat_old += sizeof(Group_Chat);
    length -= sizeof(Group_Chat);

    /* peers: check size */
    if (length != chat_new->numpeers * sizeof(Group_Peer)) {
        free(chat_new);
        return NULL;
    }

    /* peers: allocate */
    chat_new->group = calloc(chat_new->numpeers, sizeof(Group_Peer));
    if (!chat_new->group) {
        free(chat_new);
        return NULL;
    }

    /* peers: load */
    memcpy(chat_new->group, chat_old, chat_new->numpeers * sizeof(Group_Peer));

    /* pointers */
    chat_new->net = net;
    chat_new->group_message = NULL;
    chat_new->group_message_userdata = NULL;

    return chat_new;
}


#define NODE_PING_INTERVAL 10

static void ping_close(Group_Chat *chat)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < GROUP_CLOSE_CONNECTIONS; ++i) {
        if (chat->close[i].last_recv < temp_time + BAD_NODE_TIMEOUT) {
            int peernum = peer_in_chat(chat, chat->close[i].client_id);

            if (peernum == -1)
                continue;

            if (chat->group[peernum].last_pinged + NODE_PING_INTERVAL < temp_time)
                send_getnodes(chat, chat->close[i].ip_port, peernum);
        }
    }
}

void do_groupchat(Group_Chat *chat)
{
    ping_close(chat);
}

void kill_groupchat(Group_Chat *chat)
{
    free(chat->group);
    free(chat);
}

void chat_bootstrap(Group_Chat *chat, IP_Port ip_port, uint8_t *client_id)
{
    send_getnodes(chat, ip_port, addpeer(chat, client_id));
}

void chat_bootstrap_nonlazy(Group_Chat *chat, IP_Port ip_port, uint8_t *client_id)
{
    send_getnodes(chat, ip_port, addpeer(chat, client_id));
    add_closepeer(chat, client_id, ip_port);
}

