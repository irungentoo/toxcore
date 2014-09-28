/* group.c
 *
 * Slightly better groupchats implementation.
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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

#include "group.h"
#include "util.h"

/* return 1 if the groupnumber is not valid.
 * return 0 if the groupnumber is valid.
 */
static uint8_t groupnumber_not_valid(const Group_Chats *g_c, int groupnumber)
{
    if ((unsigned int)groupnumber >= g_c->num_chats)
        return 1;

    if (g_c->chats == NULL)
        return 1;

    if (g_c->chats[groupnumber].status == GROUPCHAT_STATUS_NONE)
        return 1;

    return 0;
}


/* Set the size of the groupchat list to num.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_groupchats(Group_Chats *g_c, uint32_t num)
{
    if (num == 0) {
        free(g_c->chats);
        g_c->chats = NULL;
        return 0;
    }

    Group_c *newgroup_chats = realloc(g_c->chats, num * sizeof(Group_c));

    if (newgroup_chats == NULL)
        return -1;

    g_c->chats = newgroup_chats;
    return 0;
}


/* Create a new empty groupchat connection.
 *
 * return -1 on failure.
 * return groupnumber on success.
 */
static int create_group_chat(Group_Chats *g_c)
{
    uint32_t i;

    for (i = 0; i < g_c->num_chats; ++i) {
        if (g_c->chats[i].status == GROUPCHAT_STATUS_NONE)
            return i;
    }

    int id = -1;

    if (realloc_groupchats(g_c, g_c->num_chats + 1) == 0) {
        id = g_c->num_chats;
        ++g_c->num_chats;
        memset(&(g_c->chats[id]), 0, sizeof(Group_c));
    }

    return id;
}


/* Wipe a groupchat.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_group_chat(Group_Chats *g_c, int groupnumber)
{
    if (groupnumber_not_valid(g_c, groupnumber))
        return -1;

    uint32_t i;
    memset(&(g_c->chats[groupnumber]), 0 , sizeof(Group_c));

    for (i = g_c->num_chats; i != 0; --i) {
        if (g_c->chats[i - 1].status != GROUPCHAT_STATUS_NONE)
            break;
    }

    if (g_c->num_chats != i) {
        g_c->num_chats = i;
        realloc_groupchats(g_c, g_c->num_chats);
    }

    return 0;
}

static Group_c *get_group_c(const Group_Chats *g_c, int groupnumber)
{
    if (groupnumber_not_valid(g_c, groupnumber))
        return 0;

    return &g_c->chats[groupnumber];
}

/*
 * check if peer with client_id is in peer array.
 *
 * return peer index if peer is in chat.
 * return -1 if peer is not in chat.
 *
 * TODO: make this more efficient.
 */

static int peer_in_chat(const Group_c *chat, const uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i)
        if (id_equal(chat->group[i].client_id, client_id))
            return i;

    return -1;
}

/*
 * check if group with identifier is in group array.
 *
 * return group number if peer is in list.
 * return -1 if group is not in list.
 *
 * TODO: make this more efficient and maybe use constant time comparisons?
 */
static int get_group_num(const Group_Chats *g_c, const uint8_t *identifier)
{
    uint32_t i;

    for (i = 0; i < g_c->num_chats; ++i)
        if (memcmp(g_c->chats[i].identifier, identifier, GROUP_IDENTIFIER_LENGTH) == 0)
            return i;

    return -1;
}

/*
 * check if peer with peer_number is in peer array.
 *
 * return peer number if peer is in chat.
 * return -1 if peer is not in chat.
 *
 * TODO: make this more efficient.
 */
int get_peer_index(Group_c *g, uint16_t peer_number)
{
    uint32_t i;

    for (i = 0; i < g->numpeers; ++i)
        if (g->group[i].peer_number == peer_number)
            return i;

    return -1;
}

/*
 * Add a peer to the group chat.
 *
 * return peer_index if success or peer already in chat.
 * return -1 if error.
 */
static int addpeer(Group_c *chat, const uint8_t *client_id, uint16_t peer_number)
{
    //TODO
    //int peer_index = peer_in_chat(chat, client_id);

    //if (peer_index != -1)
    //    return peer_index;

    Group_Peer *temp;
    temp = realloc(chat->group, sizeof(Group_Peer) * (chat->numpeers + 1));

    if (temp == NULL)
        return -1;

    memset(&(temp[chat->numpeers]), 0, sizeof(Group_Peer));
    chat->group = temp;

    id_copy(chat->group[chat->numpeers].client_id, client_id);
    chat->group[chat->numpeers].peer_number = peer_number;

    chat->group[chat->numpeers].last_recv = unix_time();
    chat->group[chat->numpeers].last_recv_msgping = unix_time();
    ++chat->numpeers;

    //if (chat->peer_namelistchange != NULL)
    //    (*chat->peer_namelistchange)(chat, chat->numpeers - 1, CHAT_CHANGE_PEER_ADD, chat->group_namelistchange_userdata);

    return (chat->numpeers - 1);
}

static int handle_packet(void *object, int number, uint8_t *data, uint16_t length);

/* Add friend to group chat.
 *
 * return 0 on success
 * return -1 on failure.
 */
static int add_friend_to_groupchat(Group_Chats *g_c, int32_t friendnumber, int groupnumber, uint16_t other_groupnum)
{
    if (!m_friend_exists(g_c->m, friendnumber))
        return -1;

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    uint16_t i, ind = MAX_GROUP_CONNECTIONS;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_NONE) {
            ind = i;
            continue;
        }

        if (g->close[i].type == GROUPCHAT_CLOSE_CONNECTION && g->close[i].number == (uint32_t)friendnumber) {
            g->close[i].group_number = other_groupnum; /* update groupnum. */
            return 0; /* Already in list. */
        }

        break;
    }

    if (ind == MAX_GROUP_CONNECTIONS)
        return -1;

    g->close[ind].type = GROUPCHAT_CLOSE_CONNECTION;
    g->close[ind].number = friendnumber;
    g->close[ind].group_number = other_groupnum;
    int friendcon_id = g_c->m->friendlist[friendnumber].friendcon_id;
    //TODO
    friend_connection_callbacks(g_c->m->fr_c, friendcon_id, GROUPCHAT_CALLBACK_INDEX, 0, &handle_packet, 0, g_c->m,
                                friendnumber);

    return 0;
}

/* Creates a new groupchat and puts it in the chats array.
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_groupchat(Group_Chats *g_c)
{
    int groupnumber = create_group_chat(g_c);

    if (groupnumber == -1)
        return -1;

    Group_c *g = &g_c->chats[groupnumber];

    g->status = GROUPCHAT_STATUS_VALID;
    new_symmetric_key(g->identifier);
    g->peer_number = 0; /* Founder is peer 0. */
    return groupnumber;
}

/* Delete a groupchat from the chats array.
 *
 * return 0 on success.
 * return -1 if failure.
 */
int del_groupchat(Group_Chats *g_c, int groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    free(g->group);
    return wipe_group_chat(g_c, groupnumber);
}

/* Send a group message packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int send_group_message_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    if (length >= MAX_CRYPTO_DATA_SIZE)
        return 0;

    uint8_t packet[1 + length];
    packet[0] = PACKET_ID_MESSAGE_GROUPCHAT;
    memcpy(packet + 1, data, length);
    return write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                             m->friendlist[friendnumber].friendcon_id), packet, sizeof(packet), 0) != -1;
}

#define INVITE_PACKET_SIZE (1 + sizeof(uint16_t) + GROUP_IDENTIFIER_LENGTH)
#define INVITE_ID 0

#define INVITE_RESPONSE_PACKET_SIZE (1 + sizeof(uint16_t) * 2 + GROUP_IDENTIFIER_LENGTH)
#define INVITE_RESPONSE_ID 1

/* invite friendnumber to groupnumber
 * return 0 on success
 * return -1 on failure
 */
int invite_friend(Group_Chats *g_c, int32_t friendnumber, int groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    uint8_t invite[INVITE_PACKET_SIZE];
    invite[0] = INVITE_ID;
    uint16_t groupchat_num = htons((uint16_t)groupnumber);
    memcpy(invite + 1, &groupchat_num, sizeof(groupchat_num));
    memcpy(invite + 1 + sizeof(groupchat_num), g->identifier, GROUP_IDENTIFIER_LENGTH);

    if (send_group_invite_packet(g_c->m, friendnumber, invite, sizeof(invite))) {
        return 0;
    } else {
        wipe_group_chat(g_c, groupnumber);
        return -1;
    }
}

/* Join a group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 */
int join_groupchat(Group_Chats *g_c, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    if (length != sizeof(uint16_t) + GROUP_IDENTIFIER_LENGTH)
        return -1;

    int groupnumber = create_group_chat(g_c);

    if (groupnumber == -1)
        return -1;

    Group_c *g = &g_c->chats[groupnumber];

    uint16_t group_num = htons(groupnumber);
    g->status = GROUPCHAT_STATUS_VALID;
    uint8_t response[INVITE_RESPONSE_PACKET_SIZE];
    response[0] = INVITE_RESPONSE_ID;
    memcpy(response + 1, &group_num, sizeof(uint16_t));
    memcpy(response + 1 + sizeof(uint16_t), data, sizeof(uint16_t) + GROUP_IDENTIFIER_LENGTH);

    if (send_group_invite_packet(g_c->m, friendnumber, response, sizeof(response))) {
        uint16_t other_groupnum;
        memcpy(&other_groupnum, data, sizeof(other_groupnum));
        other_groupnum = htons(other_groupnum);
        memcpy(g->identifier, data + sizeof(uint16_t), GROUP_IDENTIFIER_LENGTH);
        add_friend_to_groupchat(g_c, friendnumber, groupnumber, other_groupnum);
        g->peer_number = rand(); /* TODO */
        return groupnumber;
    } else {
        return -1;
    }
}

/* Set the callback for group invites.
 *
 *  Function(Group_Chats *g_c, int32_t friendnumber, uint8_t *data, uint16_t length, void *userdata)
 *
 *  data of length is what needs to be passed to join_groupchat().
 */
void g_callback_group_invite(Group_Chats *g_c, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t,
                             void *), void *userdata)
{
    g_c->invite_callback = function;
    g_c->invite_callback_userdata = userdata;
}

/* Set the callback for group messages.
 *
 *  Function(Group_Chats *g_c, int groupnumber, int friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void g_callback_group_message(Group_Chats *g_c, void (*function)(Messenger *m, int, int, const uint8_t *, uint16_t,
                              void *), void *userdata)
{
    g_c->message_callback = function;
    g_c->message_callback_userdata = userdata;
}

static void handle_friend_invite_packet(Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    Group_Chats *g_c = m->group_chat_object;

    if (length <= 1)
        return;

    const uint8_t *invite_data = data + 1;
    uint16_t invite_length = length - 1;

    switch (data[0]) {
        case INVITE_ID: {
            if (length != INVITE_PACKET_SIZE)
                return;

            int groupnumber = get_group_num(g_c, data + 1 + sizeof(uint16_t));

            if (groupnumber == -1) {
                if (g_c->invite_callback)
                    g_c->invite_callback(m, friendnumber, invite_data, invite_length, g_c->invite_callback_userdata);

                return;
            } else {
                //TODO
                uint16_t other_groupnum;
                memcpy(&other_groupnum, data + 1, sizeof(uint16_t));
                other_groupnum = ntohs(other_groupnum);
                add_friend_to_groupchat(g_c, friendnumber, groupnumber, other_groupnum);
            }

            break;
        }

        case INVITE_RESPONSE_ID: {
            if (length != INVITE_RESPONSE_PACKET_SIZE)
                return;

            uint16_t other_groupnum, groupnum;
            memcpy(&groupnum, data + 1 + sizeof(uint16_t), sizeof(uint16_t));
            groupnum = ntohs(groupnum);

            Group_c *g = get_group_c(g_c, groupnum);

            if (!g)
                return;

            if (memcmp(data + 1 + sizeof(uint16_t) * 2, g->identifier, GROUP_IDENTIFIER_LENGTH) != 0)
                return;

            memcpy(&other_groupnum, data + 1, sizeof(uint16_t));
            other_groupnum = ntohs(other_groupnum);

            add_friend_to_groupchat(g_c, friendnumber, groupnum, other_groupnum);

            break;
        }

        default:
            return;
    }
}

/* Find index of friend in the close list;
 *
 * returns index on success
 * returns -1 on failure.
 */
static int friend_in_close(Group_c *g, int32_t friendnumber)
{
    int i;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type != GROUPCHAT_CLOSE_CONNECTION)
            continue;

        if (g->close[i].number != (uint32_t)friendnumber)
            continue;

        return i;
    }

    return -1;
}

#define MIN_MESSAGE_PACKET_LEN (sizeof(uint16_t) * 2 + sizeof(uint32_t) + 1)

/* Send message to all close except receiver (if receiver isn't -1)
 * NOTE: this function appends the group chat number to the data passed to it.
 *
 * return number of messages sent.
 */
static unsigned int send_message_all_close(const Group_Chats *g_c, int groupnumber, const uint8_t *data,
        uint16_t length, int receiver)
{

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return 0;

    uint16_t i, sent = 0;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_NONE)
            continue;

        if ((int)i == receiver)
            continue;

        uint16_t other_groupnum = htons(g->close[i].group_number);
        uint8_t packet[sizeof(uint16_t) + length];
        memcpy(packet, &other_groupnum, sizeof(uint16_t));
        memcpy(packet + sizeof(uint16_t), data, length);

        if (send_group_message_packet(g_c->m, g->close[i].number, packet, sizeof(packet)))
            ++sent;
    }

    return sent;
}

#define MAX_GROUP_MESSAGE_DATA_LEN (MAX_CRYPTO_DATA_SIZE - (1 + MIN_MESSAGE_PACKET_LEN))

/* Send data of len with message_id to groupnumber.
 *
 * return number of peers it was sent to on success.
 * return 0 on failure.
 */
static unsigned int send_message_group(const Group_Chats *g_c, int groupnumber, uint8_t message_id, const uint8_t *data,
                                       uint16_t len)
{
    if (len > MAX_GROUP_MESSAGE_DATA_LEN)
        return 0;

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return 0;

    uint8_t packet[sizeof(uint16_t) + sizeof(uint32_t) + 1 + len];
    uint16_t peer_num = htons(g->peer_number);
    memcpy(packet, &peer_num, sizeof(peer_num));

    ++g->message_number;

    if (!g->message_number)
        ++g->message_number;

    uint32_t message_num = htonl(g->message_number);
    memcpy(packet + sizeof(uint16_t), &message_num, sizeof(message_num));

    packet[sizeof(uint16_t) + sizeof(uint32_t)] = message_id;

    if (len)
        memcpy(packet + sizeof(uint16_t) + sizeof(uint32_t) + 1, data, len);

    return send_message_all_close(g_c, groupnumber, packet, sizeof(packet), -1);
}

/* send a group message
 * return 0 on success
 * return -1 on failure
 */
int group_message_send(const Group_Chats *g_c, int groupnumber, const uint8_t *message, uint16_t length)
{
    if (send_message_group(g_c, groupnumber, PACKET_ID_MESSAGE, message, length)) {
        return 0;
    } else {
        return -1;
    }
}

static void handle_message_packet_group(Group_Chats *g_c, int groupnumber, const uint8_t *data, uint16_t length,
                                        int close_index)
{
    if (length < MIN_MESSAGE_PACKET_LEN)
        return;

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return;

    uint16_t peer_number;
    memcpy(&peer_number, data + sizeof(uint16_t), sizeof(uint16_t));
    peer_number = ntohs(peer_number);

    int index = get_peer_index(g, peer_number);

    //TODO remove
    if (index == -1) {
        uint8_t empty_key[crypto_box_PUBLICKEYBYTES];
        index = addpeer(g, empty_key, peer_number);
    }

    if (index == -1)
        return;

    uint32_t message_number;
    memcpy(&message_number, data + sizeof(uint16_t) * 2, sizeof(message_number));
    message_number = ntohl(message_number);

    if (g->group[index].last_message_number == 0) {
        g->group[index].last_message_number = message_number;
    } else if (message_number - g->group[index].last_message_number > 64 ||
               message_number == g->group[index].last_message_number) {
        return;
    }

    g->group[index].last_message_number = message_number;

    uint8_t message_id = data[sizeof(uint16_t) * 2 + sizeof(message_number)];
    const uint8_t *msg_data = data + sizeof(uint16_t) * 2 + sizeof(message_number) + 1;
    uint16_t msg_data_len = length - (sizeof(uint16_t) * 2 + sizeof(message_number) + 1);

    switch (message_id) {
        case PACKET_ID_MESSAGE: {
            if (msg_data_len == 0)
                return;

            //TODO
            if (g_c->message_callback)
                g_c->message_callback(g_c->m, groupnumber, index, msg_data, msg_data_len, g_c->message_callback_userdata);

            break;
        }

        default:
            return;
    }

    send_message_all_close(g_c, groupnumber, data + sizeof(uint16_t), length - sizeof(uint16_t), close_index);
}

static void handle_friend_message_packet(Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    Group_Chats *g_c = m->group_chat_object;

    if (length < MIN_MESSAGE_PACKET_LEN)
        return;

    uint16_t groupnumber;
    memcpy(&groupnumber, data, sizeof(uint16_t));
    groupnumber = ntohs(groupnumber);
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return;

    int index = friend_in_close(g, friendnumber);

    if (index == -1)
        return;

    handle_message_packet_group(g_c, groupnumber, data, length, index);
}

static int handle_packet(void *object, int number, uint8_t *data, uint16_t length)
{
    if (length <= 1)
        return -1;

    switch (data[0]) {
        case PACKET_ID_INVITE_GROUPCHAT: {
            handle_friend_invite_packet(object, number, data + 1, length - 1);
            break;
        }

        case PACKET_ID_MESSAGE_GROUPCHAT: {
            handle_friend_message_packet(object, number, data + 1, length - 1);
            break;
        }

        default: {
            return 0;
        }
    }

    return 0;
}


/* Create new groupchat instance. */
Group_Chats *new_groupchats(Messenger *m)
{
    if (!m)
        return NULL;

    Group_Chats *temp = calloc(1, sizeof(Group_Chats));

    if (temp == NULL)
        return NULL;

    temp->m = m;
    m->group_chat_object = temp;
    m_callback_group_invite(m, &handle_friend_invite_packet);

    return temp;
}

/* main groupchats loop. */
void do_groupchats(Group_Chats *g_c)
{
    //TODO
}

/* Free everything related with group chats. */
void kill_groupchats(Group_Chats *g_c)
{
    //TODO
    g_c->m->group_chat_object = 0;
    free(g_c);
}

/* Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist. */
/*
uint32_t count_chatlist(const Messenger *m)
{
    uint32_t ret = 0;
    uint32_t i;

    for (i = 0; i < m->numchats; i++) {
        if (m->chats[i]) {
            ret++;
        }
    }

    return ret;
}*/

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
/*
uint32_t copy_chatlist(const Messenger *m, int *out_list, uint32_t list_size)
{
    if (!out_list)
        return 0;

    if (m->numchats == 0) {
        return 0;
    }

    uint32_t i;
    uint32_t ret = 0;

    for (i = 0; i < m->numchats; i++) {
        if (ret >= list_size) {
            break; *//* Abandon ship *//*
        }

        if (m->chats[i]) {
            out_list[ret] = i;
            ret++;
        }
    }

    return ret;
}
*/