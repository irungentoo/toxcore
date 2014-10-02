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
 * check if peer with real_pk is in peer array.
 *
 * return peer index if peer is in chat.
 * return -1 if peer is not in chat.
 *
 * TODO: make this more efficient.
 */

static int peer_in_chat(const Group_c *chat, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i)
        if (id_equal(chat->group[i].real_pk, real_pk))
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
static int get_peer_index(Group_c *g, uint16_t peer_number)
{
    uint32_t i;

    for (i = 0; i < g->numpeers; ++i)
        if (g->group[i].peer_number == peer_number)
            return i;

    return -1;
}


static uint16_t calculate_comp_value(const uint8_t *pk1, const uint8_t *pk2)
{
    uint8_t cmp1, cmp2;

    for (cmp1 = crypto_box_PUBLICKEYBYTES; cmp1 != 0; --cmp1) {
        uint8_t index = crypto_box_PUBLICKEYBYTES - cmp1;

        if (pk1[index] == pk2[index])
            continue;

        cmp2 = abs((int)pk1[index] - (int)pk2[index]);
        break;
    }

    return (cmp1 << 8) + cmp2;
}

enum {
    GROUPCHAT_CLOSEST_NONE,
    GROUPCHAT_CLOSEST_ADDED,
    GROUPCHAT_CLOSEST_REMOVED
};

static int friend_in_close(Group_c *g, int friendcon_id);
static int add_conn_to_groupchat(Group_Chats *g_c, int friendcon_id, int groupnumber, uint8_t closest);

static int add_to_closest(Group_Chats *g_c, int groupnumber, const uint8_t *real_pk, const uint8_t *temp_pk)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    if (memcmp(g->real_pk, real_pk, crypto_box_PUBLICKEYBYTES) == 0)
        return -1;

    unsigned int i;
    unsigned int index = DESIRED_CLOSE_CONNECTIONS;

    for (i = 0; i < DESIRED_CLOSE_CONNECTIONS; ++i) {
        if (g->closest_peers[i].entry && memcmp(real_pk, g->closest_peers[i].real_pk, crypto_box_PUBLICKEYBYTES) == 0) {
            return 0;
        }
    }

    for (i = 0; i < DESIRED_CLOSE_CONNECTIONS; ++i) {
        if (g->closest_peers[i].entry == 0) {
            index = i;
            break;
        }
    }

    if (index == DESIRED_CLOSE_CONNECTIONS) {
        uint16_t comp_val = calculate_comp_value(g->real_pk, real_pk);
        uint16_t comp_d = 0;

        for (i = 0; i < DESIRED_CLOSE_CONNECTIONS; ++i) {
            uint16_t comp = calculate_comp_value(g->real_pk, g->closest_peers[i].real_pk);

            if (comp > comp_val && comp > comp_d) {
                index = i;
                comp_d = comp;
            }
        }
    }

    if (index == DESIRED_CLOSE_CONNECTIONS) {
        return -1;
    }

    g->closest_peers[index].entry = 1;
    memcpy(g->closest_peers[index].real_pk, real_pk, crypto_box_PUBLICKEYBYTES);
    memcpy(g->closest_peers[index].temp_pk, temp_pk, crypto_box_PUBLICKEYBYTES);

    if (!g->changed)
        g->changed = GROUPCHAT_CLOSEST_ADDED;

    return 0;
}

static unsigned int pk_in_closest_peers(Group_c *g, uint8_t *real_pk)
{
    unsigned int i;

    for (i = 0; i < DESIRED_CLOSE_CONNECTIONS; ++i) {
        if (!g->closest_peers[i].entry)
            continue;

        if (memcmp(g->closest_peers[i].real_pk, real_pk, crypto_box_PUBLICKEYBYTES) == 0)
            return 1;

    }

    return 0;
}

static int send_packet_online(Friend_Connections *fr_c, int friendcon_id, uint16_t group_num, uint8_t *identifier);

static int connect_to_closest(Group_Chats *g_c, int groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    if (!g->changed)
        return 0;

    unsigned int i;

    if (g->changed == GROUPCHAT_CLOSEST_REMOVED) {
        for (i = 0; i < g->numpeers; ++i) {
            add_to_closest(g_c, groupnumber, g->group[i].real_pk, g->group[i].temp_pk);
        }
    }

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_NONE)
            continue;

        if (!g->close[i].closest)
            continue;

        uint8_t real_pk[crypto_box_PUBLICKEYBYTES];
        uint8_t dht_temp_pk[crypto_box_PUBLICKEYBYTES];
        get_friendcon_public_keys(real_pk, dht_temp_pk, g_c->fr_c, g->close[i].number);

        if (!pk_in_closest_peers(g, real_pk)) {
            g->close[i].type = GROUPCHAT_CLOSE_NONE;
            kill_friend_connection(g_c->fr_c, g->close[i].number);
        }
    }

    for (i = 0; i < DESIRED_CLOSE_CONNECTIONS; ++i) {
        if (!g->closest_peers[i].entry)
            continue;

        int friendcon_id = getfriend_conn_id_pk(g_c->fr_c, g->closest_peers[i].real_pk);

        if (friendcon_id == -1) {
            friendcon_id = new_friend_connection(g_c->fr_c, g->closest_peers[i].real_pk);

            if (friendcon_id == -1) {
                continue;
            }

            set_dht_temp_pk(g_c->fr_c, friendcon_id, g->closest_peers[i].temp_pk);
        }

        add_conn_to_groupchat(g_c, friendcon_id, groupnumber, 1);

        if (friend_con_connected(g_c->fr_c, friendcon_id) == FRIENDCONN_STATUS_CONNECTED) {
            send_packet_online(g_c->fr_c, friendcon_id, groupnumber, g->identifier);
        }
    }

    g->changed = GROUPCHAT_CLOSEST_NONE;

    return 0;
}

/*
 * Add a peer to the group chat.
 *
 * return peer_index if success or peer already in chat.
 * return -1 if error.
 */
static int addpeer(Group_Chats *g_c, int groupnumber, const uint8_t *real_pk, const uint8_t *temp_pk,
                   uint16_t peer_number)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    //TODO
    int peer_index = peer_in_chat(g, real_pk);

    if (peer_index != -1) {
        id_copy(g->group[peer_index].temp_pk, temp_pk);

        if (g->group[peer_index].peer_number != peer_number)
            return -1;

        return peer_index;
    }

    peer_index = get_peer_index(g, peer_number);

    if (peer_index != -1)
        return -1;

    Group_Peer *temp;
    temp = realloc(g->group, sizeof(Group_Peer) * (g->numpeers + 1));

    if (temp == NULL)
        return -1;

    memset(&(temp[g->numpeers]), 0, sizeof(Group_Peer));
    g->group = temp;

    id_copy(g->group[g->numpeers].real_pk, real_pk);
    id_copy(g->group[g->numpeers].temp_pk, temp_pk);
    g->group[g->numpeers].peer_number = peer_number;

    g->group[g->numpeers].last_recv = unix_time();
    g->group[g->numpeers].last_recv_msgping = unix_time();
    ++g->numpeers;

    add_to_closest(g_c, groupnumber, real_pk, temp_pk);

    if (g_c->peer_namelistchange)
        g_c->peer_namelistchange(g_c->m, groupnumber, g->numpeers - 1, CHAT_CHANGE_PEER_ADD,
                                 g_c->group_namelistchange_userdata);

    return (g->numpeers - 1);
}

/*
 * Delete a peer from the group chat.
 *
 * return 0 if success
 * return -1 if error.
 */
static int delpeer(Group_Chats *g_c, int groupnumber, int peer_index)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    uint32_t i;

    for (i = 0; i < DESIRED_CLOSE_CONNECTIONS; ++i) { /* If peer is in closest_peers list, remove it. */
        if (g->closest_peers[i].entry && id_equal(g->closest_peers[i].real_pk, g->group[peer_index].real_pk)) {
            g->closest_peers[i].entry = 0;
            g->changed = GROUPCHAT_CLOSEST_REMOVED;
            break;
        }
    }

    Group_Peer *temp;
    --g->numpeers;

    if (g->numpeers == 0) {
        free(g->group);
        g->group = NULL;
        return 0;
    }

    if (g->numpeers != (uint32_t)peer_index)
        memcpy(&g->group[peer_index], &g->group[g->numpeers], sizeof(Group_Peer));

    temp = realloc(g->group, sizeof(Group_Peer) * (g->numpeers));

    if (temp == NULL)
        return -1;

    g->group = temp;

    if (g_c->peer_namelistchange)
        g_c->peer_namelistchange(g_c->m, groupnumber, peer_index, CHAT_CHANGE_PEER_DEL, g_c->group_namelistchange_userdata);

    return 0;
}

static int remove_close_conn(Group_Chats *g_c, int groupnumber, int friendcon_id)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    uint32_t i;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_NONE)
            continue;

        if (g->close[i].number == friendcon_id) {
            g->close[i].type = GROUPCHAT_CLOSE_NONE;
            kill_friend_connection(g_c->fr_c, friendcon_id);
            return 0;
        }
    }

    return -1;
}

static void set_conns_type_close(Group_Chats *g_c, int groupnumber, int friendcon_id, uint8_t type)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return;

    uint32_t i;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_NONE)
            continue;

        if (g->close[i].number != friendcon_id)
            continue;

        if (type == GROUPCHAT_CLOSE_ONLINE) {
            send_packet_online(g_c->fr_c, friendcon_id, groupnumber, g->identifier);
        } else {
            g->close[i].type = type;
        }
    }
}
/* Set the type for all close connections with friendcon_id */
static void set_conns_status_groups(Group_Chats *g_c, int friendcon_id, uint8_t type)
{
    uint32_t i;

    for (i = 0; i < g_c->num_chats; ++i) {
        set_conns_type_close(g_c, i, friendcon_id, type);
    }
}

static int handle_status(void *object, int friendcon_id, uint8_t status)
{
    Group_Chats *g_c = object;

    if (status) { /* Went online */
        set_conns_status_groups(g_c, friendcon_id, GROUPCHAT_CLOSE_ONLINE);
    } else { /* Went offline */
        set_conns_status_groups(g_c, friendcon_id, GROUPCHAT_CLOSE_CONNECTION);
        //TODO remove timedout connections?
    }

    return 0;
}

static int handle_packet(void *object, int friendcon_id, uint8_t *data, uint16_t length);

/* Add friend to group chat.
 *
 * return close index on success
 * return -1 on failure.
 */
static int add_conn_to_groupchat(Group_Chats *g_c, int friendcon_id, int groupnumber, uint8_t closest)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    uint16_t i, ind = MAX_GROUP_CONNECTIONS;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_NONE) {
            ind = i;
            continue;
        }

        if (g->close[i].number == (uint32_t)friendcon_id) {
            return i; /* Already in list. */
        }
    }

    if (ind == MAX_GROUP_CONNECTIONS)
        return -1;

    friend_connection_lock(g_c->fr_c, friendcon_id);
    g->close[ind].type = GROUPCHAT_CLOSE_CONNECTION;
    g->close[ind].number = friendcon_id;
    g->close[ind].closest = closest;
    //TODO
    friend_connection_callbacks(g_c->m->fr_c, friendcon_id, GROUPCHAT_CALLBACK_INDEX, &handle_status, &handle_packet, 0,
                                g_c, friendcon_id);

    return ind;
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

    g->status = GROUPCHAT_STATUS_CONNECTED;
    new_symmetric_key(g->identifier);
    g->peer_number = 0; /* Founder is peer 0. */
    memcpy(g->real_pk, g_c->m->net_crypto->self_public_key, crypto_box_PUBLICKEYBYTES);
    addpeer(g_c, groupnumber, g->real_pk, g_c->m->dht->self_public_key, 0);
    return groupnumber;
}

static int group_kill_peer_send(const Group_Chats *g_c, int groupnumber, uint16_t peer_num);
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

    group_kill_peer_send(g_c, groupnumber, g->peer_number);

    unsigned int i;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_NONE)
            continue;

        g->close[i].type = GROUPCHAT_CLOSE_NONE;
        kill_friend_connection(g_c->fr_c, g->close[i].number);
    }

    free(g->group);
    return wipe_group_chat(g_c, groupnumber);
}

/* Copy the name of peernumber who is in groupnumber to name.
 * name must be at least MAX_NAME_LENGTH long.
 *
 * return length of name if success
 * return -1 if failure
 */
int group_peername(const Group_Chats *g_c, int groupnumber, int peernumber, uint8_t *name)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    if ((uint32_t)peernumber >= g->numpeers)
        return -1;

    if (g->group[peernumber].nick_len == 0) {
        memcpy(name, "Tox User", 8);
        return 8;
    }

    memcpy(name, g->group[peernumber].nick, g->group[peernumber].nick_len);
    return g->group[peernumber].nick_len;
}

/* Return the number of peers in the group chat on success.
 * return -1 on failure
 */
int group_number_peers(const Group_Chats *g_c, int groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    return g->numpeers;
}

/* Send a group packet to friendcon_id.
 *
 *  return 1 on success
 *  return 0 on failure
 */
static unsigned int send_packet_group_peer(Friend_Connections *fr_c, int friendcon_id, uint8_t packet_id,
        uint16_t group_num, const uint8_t *data, uint16_t length)
{
    if (1 + sizeof(uint16_t) + length > MAX_CRYPTO_DATA_SIZE)
        return 0;

    group_num = htons(group_num);
    uint8_t packet[1 + sizeof(uint16_t) + length];
    packet[0] = packet_id;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    memcpy(packet + 1 + sizeof(uint16_t), data, length);
    return write_cryptpacket(fr_c->net_crypto, friend_connection_crypt_connection_id(fr_c, friendcon_id), packet,
                             sizeof(packet), 0) != -1;
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

static unsigned int send_peer_query(Group_Chats *g_c, int friendcon_id, uint16_t group_num);

/* Join a group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 */
int join_groupchat(Group_Chats *g_c, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    if (length != sizeof(uint16_t) + GROUP_IDENTIFIER_LENGTH)
        return -1;

    int friendcon_id = getfriendcon_id(g_c->m, friendnumber);

    if (friendcon_id == -1)
        return -1;

    int groupnumber = create_group_chat(g_c);

    if (groupnumber == -1)
        return -1;

    Group_c *g = &g_c->chats[groupnumber];

    uint16_t group_num = htons(groupnumber);
    g->status = GROUPCHAT_STATUS_VALID;
    memcpy(g->real_pk, g_c->m->net_crypto->self_public_key, crypto_box_PUBLICKEYBYTES);

    uint8_t response[INVITE_RESPONSE_PACKET_SIZE];
    response[0] = INVITE_RESPONSE_ID;
    memcpy(response + 1, &group_num, sizeof(uint16_t));
    memcpy(response + 1 + sizeof(uint16_t), data, sizeof(uint16_t) + GROUP_IDENTIFIER_LENGTH);

    if (send_group_invite_packet(g_c->m, friendnumber, response, sizeof(response))) {
        uint16_t other_groupnum;
        memcpy(&other_groupnum, data, sizeof(other_groupnum));
        other_groupnum = ntohs(other_groupnum);
        memcpy(g->identifier, data + sizeof(uint16_t), GROUP_IDENTIFIER_LENGTH);
        int close_index = add_conn_to_groupchat(g_c, friendcon_id, groupnumber, 0);

        if (close_index != -1) {
            g->close[close_index].group_number = other_groupnum;
            g->close[close_index].type = GROUPCHAT_CLOSE_ONLINE;
        }

        send_peer_query(g_c, friendcon_id, other_groupnum);
        return groupnumber;
    } else {
        g->status = GROUPCHAT_STATUS_NONE;
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

/* Set callback function for peer name list changes.
 *
 * It gets called every time the name list changes(new peer/name, deleted peer)
 *  Function(Group_Chats *g_c, int groupnumber, int peernumber, TOX_CHAT_CHANGE change, void *userdata)
 */
void g_callback_group_namelistchange(Group_Chats *g_c, void (*function)(Messenger *m, int, int, uint8_t, void *),
                                     void *userdata)
{
    g_c->peer_namelistchange = function;
    g_c->group_namelistchange_userdata = userdata;
}

static unsigned int send_message_group(const Group_Chats *g_c, int groupnumber, uint8_t message_id, const uint8_t *data,
                                       uint16_t len);

#define GROUP_MESSAGE_PING_ID 0
int group_ping_send(const Group_Chats *g_c, int groupnumber)
{
    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_PING_ID, 0, 0)) {
        return 0;
    } else {
        return -1;
    }
}

#define GROUP_MESSAGE_NEW_PEER_ID 16
#define GROUP_MESSAGE_NEW_PEER_LENGTH (sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES * 2)
/* send a new_peer message
 * return 0 on success
 * return -1 on failure
 */
int group_new_peer_send(const Group_Chats *g_c, int groupnumber, uint16_t peer_num, const uint8_t *real_pk,
                        uint8_t *temp_pk)
{
    uint8_t packet[GROUP_MESSAGE_NEW_PEER_LENGTH];

    peer_num = htons(peer_num);
    memcpy(packet, &peer_num, sizeof(uint16_t));
    memcpy(packet + sizeof(uint16_t), real_pk, crypto_box_PUBLICKEYBYTES);
    memcpy(packet + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES, temp_pk, crypto_box_PUBLICKEYBYTES);

    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_NEW_PEER_ID, packet, sizeof(packet))) {
        return 0;
    } else {
        return -1;
    }
}

#define GROUP_MESSAGE_KILL_PEER_ID 17
#define GROUP_MESSAGE_KILL_PEER_LENGTH (sizeof(uint16_t))

/* send a kill_peer message
 * return 0 on success
 * return -1 on failure
 */
int group_kill_peer_send(const Group_Chats *g_c, int groupnumber, uint16_t peer_num)
{

    uint8_t packet[GROUP_MESSAGE_KILL_PEER_LENGTH];

    peer_num = htons(peer_num);
    memcpy(packet, &peer_num, sizeof(uint16_t));

    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_KILL_PEER_ID, packet, sizeof(packet))) {
        return 0;
    } else {
        return -1;
    }
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

            int friendcon_id = getfriendcon_id(m, friendnumber);
            uint8_t real_pk[crypto_box_PUBLICKEYBYTES], temp_pk[crypto_box_PUBLICKEYBYTES];
            get_friendcon_public_keys(real_pk, temp_pk, g_c->fr_c, friendcon_id);

            uint16_t peer_number = rand(); /* TODO: make it not random. */
            addpeer(g_c, groupnum, real_pk, temp_pk, peer_number);
            int close_index = add_conn_to_groupchat(g_c, friendcon_id, groupnum, 0);

            if (close_index != -1) {
                g->close[close_index].group_number = other_groupnum;
                g->close[close_index].type = GROUPCHAT_CLOSE_ONLINE;
            }

            group_new_peer_send(g_c, groupnum, peer_number, real_pk, temp_pk);
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
static int friend_in_close(Group_c *g, int friendcon_id)
{
    int i;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_NONE)
            continue;

        if (g->close[i].number != (uint32_t)friendcon_id)
            continue;

        return i;
    }

    return -1;
}

#define ONLINE_PACKET_DATA_SIZE (sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES)

static int send_packet_online(Friend_Connections *fr_c, int friendcon_id, uint16_t group_num, uint8_t *identifier)
{
    uint8_t packet[1 + ONLINE_PACKET_DATA_SIZE];
    group_num = htons(group_num);
    packet[0] = PACKET_ID_ONLINE_PACKET;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    memcpy(packet + 1 + sizeof(uint16_t), identifier, crypto_box_PUBLICKEYBYTES);
    return write_cryptpacket(fr_c->net_crypto, friend_connection_crypt_connection_id(fr_c, friendcon_id), packet,
                             sizeof(packet), 0) != -1;
}

static int handle_packet_online(Group_Chats *g_c, int friendcon_id, uint8_t *data, uint16_t length)
{
    if (length != ONLINE_PACKET_DATA_SIZE)
        return -1;

    int groupnumber = get_group_num(g_c, data + sizeof(uint16_t));
    uint16_t other_groupnum;
    memcpy(&other_groupnum, data, sizeof(uint16_t));
    other_groupnum = ntohs(other_groupnum);

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    int index = friend_in_close(g, friendcon_id);

    if (index == -1)
        return -1;

    g->close[index].group_number = other_groupnum;
    g->close[index].type = GROUPCHAT_CLOSE_ONLINE;
    return 0;
}

#define PEER_QUERY_ID 4
#define PEER_RESPONSE_ID 8

/* return 1 on success.
 * return 0 on failure
 */
static unsigned int send_peer_query(Group_Chats *g_c, int friendcon_id, uint16_t group_num)
{
    uint8_t packet[1];
    packet[0] = PEER_QUERY_ID;
    return send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_GROUPCHAT, group_num, packet, sizeof(packet));
}

/* return number of peers sent on success.
 * return 0 on failure.
 */
static unsigned int send_peers(Group_Chats *g_c, int groupnumber, int friendcon_id, uint16_t group_num)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    uint8_t packet[MAX_CRYPTO_DATA_SIZE - (1 + sizeof(uint16_t))];
    packet[0] = PEER_RESPONSE_ID;
    uint8_t *p = packet + 1;

    uint16_t sent = 0;
    unsigned int i;

    for (i = 0; i < g->numpeers; ++i) {
        uint16_t peer_num = htons(g->group[i].peer_number);
        memcpy(p, &peer_num, sizeof(peer_num));
        p += sizeof(peer_num);
        memcpy(p, g->group[i].real_pk, crypto_box_PUBLICKEYBYTES);
        p += crypto_box_PUBLICKEYBYTES;
        memcpy(p, g->group[i].temp_pk, crypto_box_PUBLICKEYBYTES);
        p += crypto_box_PUBLICKEYBYTES;

        if ((p - packet) + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES * 2 > sizeof(packet)) {
            if (send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_GROUPCHAT, group_num, packet, (p - packet))) {
                sent = i;
            } else {
                return sent;
            }

            p = packet + 1;
        }
    }

    if (sent != i) {
        if (send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_GROUPCHAT, group_num, packet, (p - packet))) {
            sent = i;
        }
    }

    return sent;
}

static int handle_send_peers(Group_Chats *g_c, int groupnumber, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    if (length % (sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES * 2) != 0)
        return -1;

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    unsigned int i;
    const uint8_t *d = data;

    while ((length - (d - data)) >= sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES * 2) {
        uint16_t peer_num;
        memcpy(&peer_num, d, sizeof(peer_num));
        peer_num = ntohs(peer_num);
        d += sizeof(uint16_t);
        addpeer(g_c, groupnumber, d, d + crypto_box_PUBLICKEYBYTES, peer_num);

        if (g->status == GROUPCHAT_STATUS_VALID
                && memcmp(d, g_c->m->net_crypto->self_public_key, crypto_box_PUBLICKEYBYTES) == 0) {
            g->peer_number = peer_num;
            g->status = GROUPCHAT_STATUS_CONNECTED;
        }

        d += crypto_box_PUBLICKEYBYTES * 2;
    }

    return 0;
}

static void handle_direct_packet(Group_Chats *g_c, int groupnumber, const uint8_t *data, uint16_t length,
                                 int close_index)
{
    if (length == 0)
        return;

    switch (data[0]) {
        case PEER_QUERY_ID: {
            Group_c *g = get_group_c(g_c, groupnumber);

            if (!g)
                return;

            send_peers(g_c, groupnumber, g->close[close_index].number, g->close[close_index].group_number);
        }

        break;

        case PEER_RESPONSE_ID: {
            handle_send_peers(g_c, groupnumber, data + 1, length - 1);
        }

        break;

    }
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
        if (g->close[i].type != GROUPCHAT_CLOSE_ONLINE)
            continue;

        if ((int)i == receiver)
            continue;

        if (send_packet_group_peer(g_c->fr_c, g->close[i].number, PACKET_ID_MESSAGE_GROUPCHAT, g->close[i].group_number, data,
                                   length))
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

    if (g->status != GROUPCHAT_STATUS_CONNECTED)
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
    if (length < sizeof(uint16_t) + sizeof(uint32_t) + 1)
        return;

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return;

    uint16_t peer_number;
    memcpy(&peer_number, data, sizeof(uint16_t));
    peer_number = ntohs(peer_number);

    int index = get_peer_index(g, peer_number);

    if (index == -1)
        return;

    uint32_t message_number;
    memcpy(&message_number, data + sizeof(uint16_t), sizeof(message_number));
    message_number = ntohl(message_number);

    if (g->group[index].last_message_number == 0) {
        g->group[index].last_message_number = message_number;
    } else if (message_number - g->group[index].last_message_number > 64 ||
               message_number == g->group[index].last_message_number) {
        return;
    }

    g->group[index].last_message_number = message_number;

    uint8_t message_id = data[sizeof(uint16_t) + sizeof(message_number)];
    const uint8_t *msg_data = data + sizeof(uint16_t) + sizeof(message_number) + 1;
    uint16_t msg_data_len = length - (sizeof(uint16_t) + sizeof(message_number) + 1);

    switch (message_id) {
        case GROUP_MESSAGE_PING_ID: {
            if (msg_data_len != 0)
                return;

            g->group[index].last_recv = unix_time();
        }
        break;

        case GROUP_MESSAGE_NEW_PEER_ID: {
            if (msg_data_len != GROUP_MESSAGE_NEW_PEER_LENGTH)
                return;

            uint16_t new_peer_number;
            memcpy(&new_peer_number, msg_data, sizeof(uint16_t));
            new_peer_number = ntohs(new_peer_number);
            addpeer(g_c, groupnumber, msg_data + sizeof(uint16_t), msg_data + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES,
                    new_peer_number);
        }
        break;

        case GROUP_MESSAGE_KILL_PEER_ID: {
            if (msg_data_len != GROUP_MESSAGE_KILL_PEER_LENGTH)
                return;

            uint16_t kill_peer_number;
            memcpy(&kill_peer_number, msg_data, sizeof(uint16_t));
            kill_peer_number = ntohs(kill_peer_number);

            if (peer_number == kill_peer_number) {
                delpeer(g_c, groupnumber, index);
                return;
            } else {
                //TODO
            }

            return;
        }
        break;

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

    send_message_all_close(g_c, groupnumber, data, length, -1/*TODO close_index*/);
}

static int handle_packet(void *object, int friendcon_id, uint8_t *data, uint16_t length)
{
    Group_Chats *g_c = object;

    if (length < 1 + sizeof(uint16_t) + 1)
        return -1;

    if (data[0] == PACKET_ID_ONLINE_PACKET) {
        return handle_packet_online(g_c, friendcon_id, data + 1, length - 1);
    }

    if (data[0] != PACKET_ID_DIRECT_GROUPCHAT && data[0] != PACKET_ID_MESSAGE_GROUPCHAT)
        return -1;

    uint16_t groupnumber;
    memcpy(&groupnumber, data + 1, sizeof(uint16_t));
    groupnumber = ntohs(groupnumber);
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    int index = friend_in_close(g, friendcon_id);

    if (index == -1)
        return -1;

    switch (data[0]) {
        case PACKET_ID_DIRECT_GROUPCHAT: {
            handle_direct_packet(g_c, groupnumber, data + 1 + sizeof(uint16_t), length - (1 + sizeof(uint16_t)), index);
            break;
        }

        case PACKET_ID_MESSAGE_GROUPCHAT: {
            handle_message_packet_group(g_c, groupnumber, data + 1 + sizeof(uint16_t), length - (1 + sizeof(uint16_t)), index);
            break;
        }

        default: {
            return 0;
        }
    }

    return 0;
}

/* Interval in seconds to send ping messages */
#define GROUP_PING_INTERVAL 30

static int ping_groupchat(Group_Chats *g_c, int groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    if (is_timeout(g->last_sent_ping, GROUP_PING_INTERVAL)) {
        if (group_ping_send(g_c, groupnumber) != -1) /* Ping */
            g->last_sent_ping = unix_time();
    }

    return 0;
}

static int groupchat_clear_timedout(Group_Chats *g_c, int groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    uint32_t i;

    for (i = 0; i < g->numpeers; ++i) {
        if (g->peer_number != g->group[i].peer_number && is_timeout(g->group[i].last_recv, GROUP_PING_INTERVAL * 2)) {
            delpeer(g_c, groupnumber, i);
        }

        if (g->group == NULL || i >= g->numpeers)
            break;
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
    temp->fr_c = m->fr_c;
    m->group_chat_object = temp;
    m_callback_group_invite(m, &handle_friend_invite_packet);

    return temp;
}

/* main groupchats loop. */
void do_groupchats(Group_Chats *g_c)
{
    unsigned int i;

    for (i = 0; i < g_c->num_chats; ++i) {
        Group_c *g = get_group_c(g_c, i);

        if (!g)
            continue;

        if (g->status == GROUPCHAT_STATUS_CONNECTED) {
            connect_to_closest(g_c, i);
            ping_groupchat(g_c, i);
            groupchat_clear_timedout(g_c, i);
        }
    }

    //TODO
}

/* Free everything related with group chats. */
void kill_groupchats(Group_Chats *g_c)
{
    unsigned int i;

    for (i = 0; i < g_c->num_chats; ++i) {
        del_groupchat(g_c, i);
    }

    m_callback_group_invite(g_c->m, NULL);
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