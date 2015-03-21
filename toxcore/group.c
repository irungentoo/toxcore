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


static uint64_t calculate_comp_value(const uint8_t *pk1, const uint8_t *pk2)
{
    uint64_t cmp1 = 0, cmp2 = 0;

    unsigned int i;

    for (i = 0; i < sizeof(uint64_t); ++i) {
        cmp1 = (cmp1 << 8) + (uint64_t)pk1[i];
        cmp2 = (cmp2 << 8) + (uint64_t)pk2[i];
    }

    return (cmp1 - cmp2);
}

enum {
    GROUPCHAT_CLOSEST_NONE,
    GROUPCHAT_CLOSEST_ADDED,
    GROUPCHAT_CLOSEST_REMOVED
};

static int friend_in_close(Group_c *g, int friendcon_id);
static int add_conn_to_groupchat(Group_Chats *g_c, int friendcon_id, int groupnumber, uint8_t closest, uint8_t lock);

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
        uint64_t comp_val = calculate_comp_value(g->real_pk, real_pk);
        uint64_t comp_d = 0;

        for (i = 0; i < (DESIRED_CLOSE_CONNECTIONS / 2); ++i) {
            uint64_t comp;
            comp = calculate_comp_value(g->real_pk, g->closest_peers[i].real_pk);

            if (comp > comp_val && comp > comp_d) {
                index = i;
                comp_d = comp;
            }
        }

        comp_val = calculate_comp_value(real_pk, g->real_pk);

        for (i = (DESIRED_CLOSE_CONNECTIONS / 2); i < DESIRED_CLOSE_CONNECTIONS; ++i) {
            uint64_t comp = calculate_comp_value(g->closest_peers[i].real_pk, g->real_pk);

            if (comp > comp_val && comp > comp_d) {
                index = i;
                comp_d = comp;
            }
        }
    }

    if (index == DESIRED_CLOSE_CONNECTIONS) {
        return -1;
    }

    uint8_t old_real_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t old_temp_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t old = 0;

    if (g->closest_peers[index].entry) {
        memcpy(old_real_pk, g->closest_peers[index].real_pk, crypto_box_PUBLICKEYBYTES);
        memcpy(old_temp_pk, g->closest_peers[index].temp_pk, crypto_box_PUBLICKEYBYTES);
        old = 1;
    }

    g->closest_peers[index].entry = 1;
    memcpy(g->closest_peers[index].real_pk, real_pk, crypto_box_PUBLICKEYBYTES);
    memcpy(g->closest_peers[index].temp_pk, temp_pk, crypto_box_PUBLICKEYBYTES);

    if (old) {
        add_to_closest(g_c, groupnumber, old_real_pk, old_temp_pk);
    }

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

        uint8_t lock = 1;

        if (friendcon_id == -1) {
            friendcon_id = new_friend_connection(g_c->fr_c, g->closest_peers[i].real_pk);
            lock = 0;

            if (friendcon_id == -1) {
                continue;
            }

            set_dht_temp_pk(g_c->fr_c, friendcon_id, g->closest_peers[i].temp_pk);
        }

        add_conn_to_groupchat(g_c, friendcon_id, groupnumber, 1, lock);

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
    ++g->numpeers;

    add_to_closest(g_c, groupnumber, real_pk, temp_pk);

    if (g_c->peer_namelistchange)
        g_c->peer_namelistchange(g_c->m, groupnumber, g->numpeers - 1, CHAT_CHANGE_PEER_ADD,
                                 g_c->group_namelistchange_userdata);

    if (g->peer_on_join)
        g->peer_on_join(g->object, groupnumber, g->numpeers - 1);

    return (g->numpeers - 1);
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

        if (g->close[i].number == (unsigned int)friendcon_id) {
            g->close[i].type = GROUPCHAT_CLOSE_NONE;
            kill_friend_connection(g_c->fr_c, friendcon_id);
            return 0;
        }
    }

    return -1;
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

    int friendcon_id = getfriend_conn_id_pk(g_c->fr_c, g->group[peer_index].real_pk);

    if (friendcon_id != -1) {
        remove_close_conn(g_c, groupnumber, friendcon_id);
    }

    Group_Peer *temp;
    --g->numpeers;

    void *peer_object = g->group[peer_index].object;

    if (g->numpeers == 0) {
        free(g->group);
        g->group = NULL;
    } else {
        if (g->numpeers != (uint32_t)peer_index)
            memcpy(&g->group[peer_index], &g->group[g->numpeers], sizeof(Group_Peer));

        temp = realloc(g->group, sizeof(Group_Peer) * (g->numpeers));

        if (temp == NULL)
            return -1;

        g->group = temp;
    }

    if (g_c->peer_namelistchange)
        g_c->peer_namelistchange(g_c->m, groupnumber, peer_index, CHAT_CHANGE_PEER_DEL, g_c->group_namelistchange_userdata);

    if (g->peer_on_leave)
        g->peer_on_leave(g->object, groupnumber, peer_index, peer_object);

    return 0;
}

static int setnick(Group_Chats *g_c, int groupnumber, int peer_index, const uint8_t *nick, uint16_t nick_len)
{
    if (nick_len > MAX_NAME_LENGTH || nick_len == 0)
        return -1;

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    /* same name as already stored? */
    if (g->group[peer_index].nick_len == nick_len)
        if (!memcmp(g->group[peer_index].nick, nick, nick_len))
            return 0;

    memcpy(g->group[peer_index].nick, nick, nick_len);
    g->group[peer_index].nick_len = nick_len;

    if (g_c->peer_namelistchange)
        g_c->peer_namelistchange(g_c->m, groupnumber, peer_index, CHAT_CHANGE_PEER_NAME, g_c->group_namelistchange_userdata);

    return 0;
}

static int settitle(Group_Chats *g_c, int groupnumber, int peer_index, const uint8_t *title, uint8_t title_len)
{
    if (title_len > MAX_NAME_LENGTH || title_len == 0)
        return -1;

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    /* same as already set? */
    if (g->title_len == title_len && !memcmp(g->title, title, title_len))
        return 0;

    memcpy(g->title, title, title_len);
    g->title_len = title_len;

    if (g_c->title_callback)
        g_c->title_callback(g_c->m, groupnumber, peer_index, title, title_len, g_c->title_callback_userdata);

    return 0;
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

        if (g->close[i].number != (unsigned int)friendcon_id)
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
static int handle_lossy(void *object, int friendcon_id, const uint8_t *data, uint16_t length);

/* Add friend to group chat.
 *
 * return close index on success
 * return -1 on failure.
 */
static int add_conn_to_groupchat(Group_Chats *g_c, int friendcon_id, int groupnumber, uint8_t closest, uint8_t lock)
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
            g->close[i].closest = closest;
            return i; /* Already in list. */
        }
    }

    if (ind == MAX_GROUP_CONNECTIONS)
        return -1;

    if (lock)
        friend_connection_lock(g_c->fr_c, friendcon_id);

    g->close[ind].type = GROUPCHAT_CLOSE_CONNECTION;
    g->close[ind].number = friendcon_id;
    g->close[ind].closest = closest;
    //TODO
    friend_connection_callbacks(g_c->m->fr_c, friendcon_id, GROUPCHAT_CALLBACK_INDEX, &handle_status, &handle_packet,
                                &handle_lossy, g_c, friendcon_id);

    return ind;
}

/* Creates a new groupchat and puts it in the chats array.
 *
 * type is one of GROUPCHAT_TYPE_*
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_groupchat(Group_Chats *g_c, uint8_t type)
{
    int groupnumber = create_group_chat(g_c);

    if (groupnumber == -1)
        return -1;

    Group_c *g = &g_c->chats[groupnumber];

    g->status = GROUPCHAT_STATUS_CONNECTED;
    g->number_joined = -1;
    new_symmetric_key(g->identifier + 1);
    g->identifier[0] = type;
    g->peer_number = 0; /* Founder is peer 0. */
    memcpy(g->real_pk, g_c->m->net_crypto->self_public_key, crypto_box_PUBLICKEYBYTES);
    int peer_index = addpeer(g_c, groupnumber, g->real_pk, g_c->m->dht->self_public_key, 0);

    if (peer_index == -1) {
        return -1;
    }

    setnick(g_c, groupnumber, peer_index, g_c->m->name, g_c->m->name_length);

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

    for (i = 0; i < g->numpeers; ++i) {
        if (g->peer_on_leave)
            g->peer_on_leave(g->object, groupnumber, i, g->group[i].object);
    }

    free(g->group);

    if (g->group_on_delete)
        g->group_on_delete(g->object, groupnumber);

    return wipe_group_chat(g_c, groupnumber);
}

/* Copy the public key of peernumber who is in groupnumber to pk.
 * pk must be crypto_box_PUBLICKEYBYTES long.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int group_peer_pubkey(const Group_Chats *g_c, int groupnumber, int peernumber, uint8_t *pk)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    if ((uint32_t)peernumber >= g->numpeers)
        return -1;

    memcpy(pk, g->group[peernumber].real_pk, crypto_box_PUBLICKEYBYTES);
    return 0;
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

/* List all the peers in the group chat.
 *
 * Copies the names of the peers to the name[length][MAX_NAME_LENGTH] array.
 *
 * Copies the lengths of the names to lengths[length]
 *
 * returns the number of peers on success.
 *
 * return -1 on failure.
 */
int group_names(const Group_Chats *g_c, int groupnumber, uint8_t names[][MAX_NAME_LENGTH], uint16_t lengths[],
                uint16_t length)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    unsigned int i;

    for (i = 0; i < g->numpeers && i < length; ++i) {
        lengths[i] = group_peername(g_c, groupnumber, i, names[i]);
    }

    return i;
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

/* return 1 if the peernumber corresponds to ours.
 * return 0 on failure.
 */
unsigned int group_peernumber_is_ours(const Group_Chats *g_c, int groupnumber, int peernumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return 0;

    if (g->status != GROUPCHAT_STATUS_CONNECTED)
        return 0;

    if ((uint32_t)peernumber >= g->numpeers)
        return 0;

    return g->peer_number == g->group[peernumber].peer_number;
}

/* return the type of groupchat (GROUPCHAT_TYPE_) that groupnumber is.
 *
 * return -1 on failure.
 * return type on success.
 */
int group_get_type(const Group_Chats *g_c, int groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    return g->identifier[0];
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

/* Send a group lossy packet to friendcon_id.
 *
 *  return 1 on success
 *  return 0 on failure
 */
static unsigned int send_lossy_group_peer(Friend_Connections *fr_c, int friendcon_id, uint8_t packet_id,
        uint16_t group_num, const uint8_t *data, uint16_t length)
{
    if (1 + sizeof(uint16_t) + length > MAX_CRYPTO_DATA_SIZE)
        return 0;

    group_num = htons(group_num);
    uint8_t packet[1 + sizeof(uint16_t) + length];
    packet[0] = packet_id;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    memcpy(packet + 1 + sizeof(uint16_t), data, length);
    return send_lossy_cryptpacket(fr_c->net_crypto, friend_connection_crypt_connection_id(fr_c, friendcon_id), packet,
                                  sizeof(packet)) != -1;
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
 * expected_type is the groupchat type we expect the chat we are joining is.
 *
 * returns group number on success
 * returns -1 on failure.
 */
int join_groupchat(Group_Chats *g_c, int32_t friendnumber, uint8_t expected_type, const uint8_t *data, uint16_t length)
{
    if (length != sizeof(uint16_t) + GROUP_IDENTIFIER_LENGTH)
        return -1;

    if (data[sizeof(uint16_t)] != expected_type)
        return -1;

    int friendcon_id = getfriendcon_id(g_c->m, friendnumber);

    if (friendcon_id == -1)
        return -1;

    if (get_group_num(g_c, data + sizeof(uint16_t)) != -1)
        return -1;

    int groupnumber = create_group_chat(g_c);

    if (groupnumber == -1)
        return -1;

    Group_c *g = &g_c->chats[groupnumber];

    uint16_t group_num = htons(groupnumber);
    g->status = GROUPCHAT_STATUS_VALID;
    g->number_joined = -1;
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
        int close_index = add_conn_to_groupchat(g_c, friendcon_id, groupnumber, 0, 1);

        if (close_index != -1) {
            g->close[close_index].group_number = other_groupnum;
            g->close[close_index].type = GROUPCHAT_CLOSE_ONLINE;
            g->number_joined = friendcon_id;
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
 *  Function(Group_Chats *g_c, int32_t friendnumber, uint8_t type, uint8_t *data, uint16_t length, void *userdata)
 *
 *  data of length is what needs to be passed to join_groupchat().
 */
void g_callback_group_invite(Group_Chats *g_c, void (*function)(Messenger *m, int32_t, uint8_t, const uint8_t *,
                             uint16_t, void *), void *userdata)
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

/* Set the callback for group actions.
 *
 *  Function(Group_Chats *g_c, int groupnumber, int friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void g_callback_group_action(Group_Chats *g_c, void (*function)(Messenger *m, int, int, const uint8_t *, uint16_t,
                             void *), void *userdata)
{
    g_c->action_callback = function;
    g_c->action_callback_userdata = userdata;
}

/* Set handlers for custom lossy packets.
 *
 * NOTE: Handler must return 0 if packet is to be relayed, -1 if the packet should not be relayed.
 *
 * Function(void *group object (set with group_set_object), int groupnumber, int friendgroupnumber, void *group peer object (set with group_peer_set_object), const uint8_t *packet, uint16_t length)
 */
void group_lossy_packet_registerhandler(Group_Chats *g_c, uint8_t byte, int (*function)(void *, int, int, void *,
                                        const uint8_t *, uint16_t))
{
    g_c->lossy_packethandlers[byte].function = function;
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

/* Set callback function for title changes.
 *
 * Function(Group_Chats *g_c, int groupnumber, int friendgroupnumber, uint8_t * title, uint8_t length, void *userdata)
 * if friendgroupnumber == -1, then author is unknown (e.g. initial joining the group)
 */
void g_callback_group_title(Group_Chats *g_c, void (*function)(Messenger *m, int, int, const uint8_t *, uint8_t,
                            void *), void *userdata)
{
    g_c->title_callback = function;
    g_c->title_callback_userdata = userdata;
}

/* Set a function to be called when a new peer joins a group chat.
 *
 * Function(void *group object (set with group_set_object), int groupnumber, int friendgroupnumber)
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_new(const Group_Chats *g_c, int groupnumber, void (*function)(void *, int, int))
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    g->peer_on_join = function;
    return 0;
}

/* Set a function to be called when a peer leaves a group chat.
 *
 * Function(void *group object (set with group_set_object), int groupnumber, int friendgroupnumber, void *group peer object (set with group_peer_set_object))
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_delete(Group_Chats *g_c, int groupnumber, void (*function)(void *, int, int, void *))
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    g->peer_on_leave = function;
    return 0;
}

/* Set a function to be called when the group chat is deleted.
 *
 * Function(void *group object (set with group_set_object), int groupnumber)
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_delete(Group_Chats *g_c, int groupnumber, void (*function)(void *, int))
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    g->group_on_delete = function;
    return 0;
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

#define GROUP_MESSAGE_NAME_ID 48

/* send a name message
 * return 0 on success
 * return -1 on failure
 */
static int group_name_send(const Group_Chats *g_c, int groupnumber, const uint8_t *nick, uint16_t nick_len)
{
    if (nick_len > MAX_NAME_LENGTH)
        return -1;

    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_NAME_ID, nick, nick_len)) {
        return 0;
    } else {
        return -1;
    }
}

#define GROUP_MESSAGE_TITLE_ID 49

/* set the group's title, limited to MAX_NAME_LENGTH
 * return 0 on success
 * return -1 on failure
 */
int group_title_send(const Group_Chats *g_c, int groupnumber, const uint8_t *title, uint8_t title_len)
{
    if (title_len > MAX_NAME_LENGTH || title_len == 0)
        return -1;

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    /* same as already set? */
    if (g->title_len == title_len && !memcmp(g->title, title, title_len))
        return 0;

    memcpy(g->title, title, title_len);
    g->title_len = title_len;

    if (g->numpeers == 1)
        return 0;

    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_TITLE_ID, title, title_len))
        return 0;
    else
        return -1;
}

/* Get group title from groupnumber and put it in title.
 * title needs to be a valid memory location with a max_length size of at least MAX_NAME_LENGTH (128) bytes.
 *
 *  return length of copied title if success.
 *  return -1 if failure.
 */
int group_title_get(const Group_Chats *g_c, int groupnumber, uint8_t *title, uint32_t max_length)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    if (g->title_len == 0 || g->title_len > MAX_NAME_LENGTH)
        return -1;

    if (max_length > g->title_len)
        max_length = g->title_len;

    memcpy(title, g->title, max_length);
    return max_length;
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
                    g_c->invite_callback(m, friendnumber, *(invite_data + sizeof(uint16_t)), invite_data, invite_length,
                                         g_c->invite_callback_userdata);

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

            uint16_t peer_number = rand(); /* TODO: what if two people enter the group at the same time and
  are given the same peer_number by different nodes? */

            unsigned int tries = 0;

            while (get_peer_index(g, peer_number) != -1) {
                peer_number = rand();
                ++tries;

                if (tries > 32)
                    return;
            }

            memcpy(&other_groupnum, data + 1, sizeof(uint16_t));
            other_groupnum = ntohs(other_groupnum);

            int friendcon_id = getfriendcon_id(m, friendnumber);
            uint8_t real_pk[crypto_box_PUBLICKEYBYTES], temp_pk[crypto_box_PUBLICKEYBYTES];
            get_friendcon_public_keys(real_pk, temp_pk, g_c->fr_c, friendcon_id);

            addpeer(g_c, groupnum, real_pk, temp_pk, peer_number);
            int close_index = add_conn_to_groupchat(g_c, friendcon_id, groupnum, 0, 1);

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
    unsigned int i;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_NONE)
            continue;

        if (g->close[i].number != (uint32_t)friendcon_id)
            continue;

        return i;
    }

    return -1;
}

/* return number of connected close connections.
 */
static unsigned int count_close_connected(Group_c *g)
{
    unsigned int i, count = 0;

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type == GROUPCHAT_CLOSE_ONLINE) {
            ++count;
        }
    }

    return count;
}

#define ONLINE_PACKET_DATA_SIZE (sizeof(uint16_t) + GROUP_IDENTIFIER_LENGTH)

static int send_packet_online(Friend_Connections *fr_c, int friendcon_id, uint16_t group_num, uint8_t *identifier)
{
    uint8_t packet[1 + ONLINE_PACKET_DATA_SIZE];
    group_num = htons(group_num);
    packet[0] = PACKET_ID_ONLINE_PACKET;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    memcpy(packet + 1 + sizeof(uint16_t), identifier, GROUP_IDENTIFIER_LENGTH);
    return write_cryptpacket(fr_c->net_crypto, friend_connection_crypt_connection_id(fr_c, friendcon_id), packet,
                             sizeof(packet), 0) != -1;
}

static unsigned int send_peer_kill(Group_Chats *g_c, int friendcon_id, uint16_t group_num);

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

    if (g->close[index].type == GROUPCHAT_CLOSE_ONLINE) {
        return -1;
    }

    if (count_close_connected(g) == 0) {
        send_peer_query(g_c, friendcon_id, other_groupnum);
    }

    g->close[index].group_number = other_groupnum;
    g->close[index].type = GROUPCHAT_CLOSE_ONLINE;
    send_packet_online(g_c->fr_c, friendcon_id, groupnumber, g->identifier);

    if (g->number_joined != -1 && count_close_connected(g) >= DESIRED_CLOSE_CONNECTIONS) {
        int fr_close_index = friend_in_close(g, g->number_joined);

        if (fr_close_index == -1)
            return -1;

        if (!g->close[fr_close_index].closest) {
            g->close[fr_close_index].type = GROUPCHAT_CLOSE_NONE;
            send_peer_kill(g_c, g->close[fr_close_index].number, g->close[fr_close_index].group_number);
            kill_friend_connection(g_c->fr_c, g->close[fr_close_index].number);
            g->number_joined = -1;
        }
    }

    return 0;
}

#define PEER_KILL_ID 1
#define PEER_QUERY_ID 8
#define PEER_RESPONSE_ID 9
#define PEER_TITLE_ID 10
// we could send title with invite, but then if it changes between sending and accepting inv, joinee won't see it

/* return 1 on success.
 * return 0 on failure
 */
static unsigned int send_peer_kill(Group_Chats *g_c, int friendcon_id, uint16_t group_num)
{
    uint8_t packet[1];
    packet[0] = PEER_KILL_ID;
    return send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_GROUPCHAT, group_num, packet, sizeof(packet));
}


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
        if ((p - packet) + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES * 2 + 1 + g->group[i].nick_len > sizeof(packet)) {
            if (send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_GROUPCHAT, group_num, packet, (p - packet))) {
                sent = i;
            } else {
                return sent;
            }

            p = packet + 1;
        }

        uint16_t peer_num = htons(g->group[i].peer_number);
        memcpy(p, &peer_num, sizeof(peer_num));
        p += sizeof(peer_num);
        memcpy(p, g->group[i].real_pk, crypto_box_PUBLICKEYBYTES);
        p += crypto_box_PUBLICKEYBYTES;
        memcpy(p, g->group[i].temp_pk, crypto_box_PUBLICKEYBYTES);
        p += crypto_box_PUBLICKEYBYTES;
        *p = g->group[i].nick_len;
        p += 1;
        memcpy(p, g->group[i].nick, g->group[i].nick_len);
        p += g->group[i].nick_len;
    }

    if (sent != i) {
        if (send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_GROUPCHAT, group_num, packet, (p - packet))) {
            sent = i;
        }
    }

    if (g->title_len) {
        uint8_t Packet[1 + g->title_len];
        Packet[0] = PEER_TITLE_ID;
        memcpy(Packet + 1, g->title, g->title_len);
        send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_GROUPCHAT, group_num, Packet, sizeof(Packet));
    }

    return sent;
}

static int handle_send_peers(Group_Chats *g_c, int groupnumber, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    const uint8_t *d = data;

    while ((length - (d - data)) >= sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES * 2 + 1) {
        uint16_t peer_num;
        memcpy(&peer_num, d, sizeof(peer_num));
        peer_num = ntohs(peer_num);
        d += sizeof(uint16_t);
        int peer_index = addpeer(g_c, groupnumber, d, d + crypto_box_PUBLICKEYBYTES, peer_num);

        if (peer_index == -1)
            return -1;

        if (g->status == GROUPCHAT_STATUS_VALID
                && memcmp(d, g_c->m->net_crypto->self_public_key, crypto_box_PUBLICKEYBYTES) == 0) {
            g->peer_number = peer_num;
            g->status = GROUPCHAT_STATUS_CONNECTED;
            group_name_send(g_c, groupnumber, g_c->m->name, g_c->m->name_length);
        }

        d += crypto_box_PUBLICKEYBYTES * 2;
        uint8_t name_length = *d;
        d += 1;

        if (name_length > (length - (d - data)) || name_length > MAX_NAME_LENGTH)
            return -1;

        setnick(g_c, groupnumber, peer_index, d, name_length);
        d += name_length;
    }

    return 0;
}

static void handle_direct_packet(Group_Chats *g_c, int groupnumber, const uint8_t *data, uint16_t length,
                                 int close_index)
{
    if (length == 0)
        return;

    switch (data[0]) {
        case PEER_KILL_ID: {
            Group_c *g = get_group_c(g_c, groupnumber);

            if (!g)
                return;

            if (!g->close[close_index].closest) {
                g->close[close_index].type = GROUPCHAT_CLOSE_NONE;
                kill_friend_connection(g_c->fr_c, g->close[close_index].number);
            }
        }

        break;

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

        case PEER_TITLE_ID: {
            settitle(g_c, groupnumber, -1, data + 1, length - 1);
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

/* Send lossy message to all close except receiver (if receiver isn't -1)
 * NOTE: this function appends the group chat number to the data passed to it.
 *
 * return number of messages sent.
 */
static unsigned int send_lossy_all_close(const Group_Chats *g_c, int groupnumber, const uint8_t *data, uint16_t length,
        int receiver)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return 0;

    unsigned int i, sent = 0, num_connected_closest = 0, connected_closest[DESIRED_CLOSE_CONNECTIONS];

    for (i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->close[i].type != GROUPCHAT_CLOSE_ONLINE)
            continue;

        if ((int)i == receiver)
            continue;

        if (g->close[i].closest) {
            connected_closest[num_connected_closest] = i;
            ++num_connected_closest;
            continue;
        }

        if (send_lossy_group_peer(g_c->fr_c, g->close[i].number, PACKET_ID_LOSSY_GROUPCHAT, g->close[i].group_number, data,
                                  length))
            ++sent;
    }

    if (!num_connected_closest) {
        return sent;
    }

    unsigned int to_send = 0;
    uint64_t comp_val_old = ~0;

    for (i = 0; i < num_connected_closest; ++i) {
        uint8_t real_pk[crypto_box_PUBLICKEYBYTES];
        uint8_t dht_temp_pk[crypto_box_PUBLICKEYBYTES];
        get_friendcon_public_keys(real_pk, dht_temp_pk, g_c->fr_c, g->close[connected_closest[i]].number);
        uint64_t comp_val = calculate_comp_value(g->real_pk, real_pk);

        if (comp_val < comp_val_old) {
            to_send = connected_closest[i];
            comp_val_old = comp_val;
        }
    }

    if (send_lossy_group_peer(g_c->fr_c, g->close[to_send].number, PACKET_ID_LOSSY_GROUPCHAT,
                              g->close[to_send].group_number, data, length)) {
        ++sent;
    }

    unsigned int to_send_other = 0;
    comp_val_old = ~0;

    for (i = 0; i < num_connected_closest; ++i) {
        uint8_t real_pk[crypto_box_PUBLICKEYBYTES];
        uint8_t dht_temp_pk[crypto_box_PUBLICKEYBYTES];
        get_friendcon_public_keys(real_pk, dht_temp_pk, g_c->fr_c, g->close[connected_closest[i]].number);
        uint64_t comp_val = calculate_comp_value(real_pk, g->real_pk);

        if (comp_val < comp_val_old) {
            to_send_other = connected_closest[i];
            comp_val_old = comp_val;
        }
    }

    if (to_send_other == to_send) {
        return sent;
    }

    if (send_lossy_group_peer(g_c->fr_c, g->close[to_send_other].number, PACKET_ID_LOSSY_GROUPCHAT,
                              g->close[to_send_other].group_number, data, length)) {
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

/* send a group action
 * return 0 on success
 * return -1 on failure
 */
int group_action_send(const Group_Chats *g_c, int groupnumber, const uint8_t *action, uint16_t length)
{
    if (send_message_group(g_c, groupnumber, PACKET_ID_ACTION, action, length)) {
        return 0;
    } else {
        return -1;
    }
}

/* High level function to send custom lossy packets.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_group_lossy_packet(const Group_Chats *g_c, int groupnumber, const uint8_t *data, uint16_t length)
{
    //TODO: length check here?
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    uint8_t packet[sizeof(uint16_t) * 2 + length];
    uint16_t peer_number = htons(g->peer_number);
    memcpy(packet, &peer_number, sizeof(uint16_t));
    uint16_t message_num = htons(g->lossy_message_number);
    memcpy(packet + sizeof(uint16_t), &message_num, sizeof(uint16_t));
    memcpy(packet + sizeof(uint16_t) * 2, data, length);

    if (send_lossy_all_close(g_c, groupnumber, packet, sizeof(packet), -1) == 0) {
        return -1;
    }

    ++g->lossy_message_number;
    return 0;
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

    if (index == -1) {
        /* We don't know the peer this packet came from so we query the list of peers from that peer.
          (They would not have relayed it if they didn't know the peer.) */
        send_peer_query(g_c, g->close[close_index].number, g->close[close_index].group_number);
        return;
    }

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
            } else {
                return;
                //TODO
            }
        }
        break;

        case GROUP_MESSAGE_NAME_ID: {
            if (setnick(g_c, groupnumber, index, msg_data, msg_data_len) == -1)
                return;
        }
        break;

        case GROUP_MESSAGE_TITLE_ID: {
            if (settitle(g_c, groupnumber, index, msg_data, msg_data_len) == -1)
                return;
        }
        break;

        case PACKET_ID_MESSAGE: {
            if (msg_data_len == 0)
                return;

            uint8_t newmsg[msg_data_len + 1];
            memcpy(newmsg, msg_data, msg_data_len);
            newmsg[msg_data_len] = 0;

            //TODO
            if (g_c->message_callback)
                g_c->message_callback(g_c->m, groupnumber, index, newmsg, msg_data_len, g_c->message_callback_userdata);

            break;
        }

        case PACKET_ID_ACTION: {
            if (msg_data_len == 0)
                return;

            uint8_t newmsg[msg_data_len + 1];
            memcpy(newmsg, msg_data, msg_data_len);
            newmsg[msg_data_len] = 0;

            //TODO
            if (g_c->action_callback)
                g_c->action_callback(g_c->m, groupnumber, index, newmsg, msg_data_len, g_c->action_callback_userdata);

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

/* Did we already receive the lossy packet or not.
 *
 * return -1 on failure.
 * return 0 if packet was not received.
 * return 1 if packet was received.
 *
 * TODO: test this
 */
static unsigned int lossy_packet_not_received(Group_c *g, int peer_index, uint16_t message_number)
{
    if (peer_index == -1)
        return -1;

    if (g->group[peer_index].bottom_lossy_number == g->group[peer_index].top_lossy_number) {
        g->group[peer_index].top_lossy_number = message_number;
        g->group[peer_index].bottom_lossy_number = (message_number - MAX_LOSSY_COUNT) + 1;
        g->group[peer_index].recv_lossy[message_number % MAX_LOSSY_COUNT] = 1;
        return 0;
    }

    if ((uint16_t)(message_number - g->group[peer_index].bottom_lossy_number) < MAX_LOSSY_COUNT) {
        if (g->group[peer_index].recv_lossy[message_number % MAX_LOSSY_COUNT]) {
            return 1;
        }

        g->group[peer_index].recv_lossy[message_number % MAX_LOSSY_COUNT] = 1;
        return 0;
    }

    if ((uint16_t)(message_number - g->group[peer_index].bottom_lossy_number) > (1 << 15))
        return -1;

    uint16_t top_distance = message_number - g->group[peer_index].top_lossy_number;

    if (top_distance >= MAX_LOSSY_COUNT) {
        memset(g->group[peer_index].recv_lossy, 0, sizeof(g->group[peer_index].recv_lossy));
        g->group[peer_index].top_lossy_number = message_number;
        g->group[peer_index].bottom_lossy_number = (message_number - MAX_LOSSY_COUNT) + 1;
        g->group[peer_index].recv_lossy[message_number % MAX_LOSSY_COUNT] = 1;
        return 0;
    }

    if (top_distance < MAX_LOSSY_COUNT) {
        unsigned int i;

        for (i = g->group[peer_index].bottom_lossy_number; i != (g->group[peer_index].bottom_lossy_number + top_distance);
                ++i) {
            g->group[peer_index].recv_lossy[i % MAX_LOSSY_COUNT] = 0;
        }

        g->group[peer_index].top_lossy_number = message_number;
        g->group[peer_index].bottom_lossy_number = (message_number - MAX_LOSSY_COUNT) + 1;
        g->group[peer_index].recv_lossy[message_number % MAX_LOSSY_COUNT] = 1;
        return 0;
    }

    return -1;
}

static int handle_lossy(void *object, int friendcon_id, const uint8_t *data, uint16_t length)
{
    Group_Chats *g_c = object;

    if (length < 1 + sizeof(uint16_t) * 3 + 1)
        return -1;

    if (data[0] != PACKET_ID_LOSSY_GROUPCHAT)
        return -1;

    uint16_t groupnumber, peer_number, message_number;
    memcpy(&groupnumber, data + 1, sizeof(uint16_t));
    memcpy(&peer_number, data + 1 + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&message_number, data + 1 + sizeof(uint16_t) * 2, sizeof(uint16_t));
    groupnumber = ntohs(groupnumber);
    peer_number = ntohs(peer_number);
    message_number = ntohs(message_number);

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    int index = friend_in_close(g, friendcon_id);

    if (index == -1)
        return -1;

    if (peer_number == g->peer_number)
        return -1;

    int peer_index = get_peer_index(g, peer_number);

    if (peer_index == -1)
        return -1;

    if (lossy_packet_not_received(g, peer_index, message_number))
        return -1;

    const uint8_t *lossy_data = data + 1 + sizeof(uint16_t) * 3;
    uint16_t lossy_length = length - (1 + sizeof(uint16_t) * 3);
    uint8_t message_id = lossy_data[0];
    ++lossy_data;
    --lossy_length;

    if (g_c->lossy_packethandlers[message_id].function) {
        if (g_c->lossy_packethandlers[message_id].function(g->object, groupnumber, peer_index, g->group[peer_index].object,
                lossy_data, lossy_length) == -1) {
            return -1;
        }
    } else {
        return -1;
    }

    send_lossy_all_close(g_c, groupnumber, data + 1 + sizeof(uint16_t), length - (1 + sizeof(uint16_t)), index);
    return 0;
}

/* Set the object that is tied to the group chat.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_set_object(const Group_Chats *g_c, int groupnumber, void *object)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    g->object = object;
    return 0;
}

/* Set the object that is tied to the group peer.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_peer_set_object(const Group_Chats *g_c, int groupnumber, int peernumber, void *object)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return -1;

    if ((uint32_t)peernumber >= g->numpeers)
        return -1;

    g->group[peernumber].object = object;
    return 0;
}

/* Return the object tide to the group chat previously set by group_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_get_object(const Group_Chats *g_c, int groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return NULL;

    return g->object;
}

/* Return the object tide to the group chat peer previously set by group_peer_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_peer_get_object(const Group_Chats *g_c, int groupnumber, int peernumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g)
        return NULL;

    if ((uint32_t)peernumber >= g->numpeers)
        return NULL;

    return g->group[peernumber].object;
}

/* Interval in seconds to send ping messages */
#define GROUP_PING_INTERVAL 20

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
        if (g->peer_number != g->group[i].peer_number && is_timeout(g->group[i].last_recv, GROUP_PING_INTERVAL * 3)) {
            delpeer(g_c, groupnumber, i);
        }

        if (g->group == NULL || i >= g->numpeers)
            break;
    }

    return 0;
}

/* Send current name (set in messenger) to all online groups.
 */
void send_name_all_groups(Group_Chats *g_c)
{
    unsigned int i;

    for (i = 0; i < g_c->num_chats; ++i) {
        Group_c *g = get_group_c(g_c, i);

        if (!g)
            continue;

        if (g->status == GROUPCHAT_STATUS_CONNECTED) {
            group_name_send(g_c, i, g_c->m->name, g_c->m->name_length);
        }
    }
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
 * for copy_chatlist.
 */
uint32_t count_chatlist(Group_Chats *g_c)
{
    uint32_t ret = 0;
    uint32_t i;

    for (i = 0; i < g_c->num_chats; i++) {
        if (g_c->chats[i].status != GROUPCHAT_STATUS_NONE) {
            ret++;
        }
    }

    return ret;
}

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_chatlist(Group_Chats *g_c, int32_t *out_list, uint32_t list_size)
{
    if (!out_list) {
        return 0;
    }

    if (g_c->num_chats == 0) {
        return 0;
    }

    uint32_t i, ret = 0;

    for (i = 0; i < g_c->num_chats; ++i) {
        if (ret >= list_size) {
            break;  /* Abandon ship */
        }

        if (g_c->chats[i].status > GROUPCHAT_STATUS_NONE) {
            out_list[ret] = i;
            ret++;
        }
    }

    return ret;
}
