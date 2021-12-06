/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/*
 * Slightly better groupchats implementation.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "group.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "mono_time.h"
#include "state.h"
#include "util.h"

/**
 * Packet type IDs as per the protocol specification.
 */
typedef enum Group_Message_Id {
    GROUP_MESSAGE_PING_ID        = 0,
    GROUP_MESSAGE_NEW_PEER_ID    = 16,
    GROUP_MESSAGE_KILL_PEER_ID   = 17,
    GROUP_MESSAGE_FREEZE_PEER_ID = 18,
    GROUP_MESSAGE_NAME_ID        = 48,
    GROUP_MESSAGE_TITLE_ID       = 49,
} Group_Message_Id;

#define GROUP_MESSAGE_NEW_PEER_LENGTH (sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE * 2)
#define GROUP_MESSAGE_KILL_PEER_LENGTH (sizeof(uint16_t))

#define MAX_GROUP_MESSAGE_DATA_LEN (MAX_CRYPTO_DATA_SIZE - (1 + MIN_MESSAGE_PACKET_LEN))

typedef enum Invite_Id {
    INVITE_ID             = 0,
    INVITE_ACCEPT_ID      = 1,
    INVITE_MEMBER_ID      = 2,
} Invite_Id;

#define INVITE_PACKET_SIZE (1 + sizeof(uint16_t) + 1 + GROUP_ID_LENGTH)
#define INVITE_ACCEPT_PACKET_SIZE (1 + sizeof(uint16_t) * 2 + 1 + GROUP_ID_LENGTH)
#define INVITE_MEMBER_PACKET_SIZE (1 + sizeof(uint16_t) * 2 + 1 + GROUP_ID_LENGTH + sizeof(uint16_t))

#define ONLINE_PACKET_DATA_SIZE (sizeof(uint16_t) + 1 + GROUP_ID_LENGTH)

typedef enum Peer_Id {
    PEER_INTRODUCED_ID  = 1,
    PEER_QUERY_ID       = 8,
    PEER_RESPONSE_ID    = 9,
    PEER_TITLE_ID       = 10,
} Peer_Id;

#define MIN_MESSAGE_PACKET_LEN (sizeof(uint16_t) * 2 + sizeof(uint32_t) + 1)

/* return false if the groupnumber is not valid.
 * return true if the groupnumber is valid.
 */
static bool is_groupnumber_valid(const Group_Chats *g_c, uint32_t groupnumber)
{
    return groupnumber < g_c->num_chats
           && g_c->chats != nullptr
           && g_c->chats[groupnumber].status != GROUPCHAT_STATUS_NONE;
}


/* Set the size of the groupchat list to num.
 *
 *  return false if realloc fails.
 *  return true if it succeeds.
 */
static bool realloc_conferences(Group_Chats *g_c, uint16_t num)
{
    if (num == 0) {
        free(g_c->chats);
        g_c->chats = nullptr;
        return true;
    }

    Group_c *newgroup_chats = (Group_c *)realloc(g_c->chats, num * sizeof(Group_c));

    if (newgroup_chats == nullptr) {
        return false;
    }

    g_c->chats = newgroup_chats;
    return true;
}

static void setup_conference(Group_c *g)
{
    memset(g, 0, sizeof(Group_c));

    g->maxfrozen = MAX_FROZEN_DEFAULT;
}

/* Create a new empty groupchat connection.
 *
 * return -1 on failure.
 * return groupnumber on success.
 */
static int32_t create_group_chat(Group_Chats *g_c)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        if (g_c->chats[i].status == GROUPCHAT_STATUS_NONE) {
            return i;
        }
    }

    if (realloc_conferences(g_c, g_c->num_chats + 1)) {
        uint16_t id = g_c->num_chats;
        ++g_c->num_chats;
        setup_conference(&g_c->chats[id]);
        return id;
    }

    return -1;
}


/* Wipe a groupchat.
 *
 * return true on success.
 */
static bool wipe_group_chat(Group_Chats *g_c, uint32_t groupnumber)
{
    if (!is_groupnumber_valid(g_c, groupnumber)) {
        return false;
    }

    uint16_t i;
    crypto_memzero(&g_c->chats[groupnumber], sizeof(Group_c));

    for (i = g_c->num_chats; i != 0; --i) {
        if (g_c->chats[i - 1].status != GROUPCHAT_STATUS_NONE) {
            break;
        }
    }

    if (g_c->num_chats != i) {
        g_c->num_chats = i;
        realloc_conferences(g_c, g_c->num_chats);
    }

    return true;
}

static Group_c *get_group_c(const Group_Chats *g_c, uint32_t groupnumber)
{
    if (!is_groupnumber_valid(g_c, groupnumber)) {
        return nullptr;
    }

    return &g_c->chats[groupnumber];
}

/*
 * check if peer with real_pk is in peer array.
 *
 * return peer index if peer is in group.
 * return -1 if peer is not in group.
 *
 * TODO(irungentoo): make this more efficient.
 */

static int peer_in_group(const Group_c *g, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < g->numpeers; ++i) {
        if (id_equal(g->group[i].real_pk, real_pk)) {
            return i;
        }
    }

    return -1;
}

static int frozen_in_group(const Group_c *g, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < g->numfrozen; ++i) {
        if (id_equal(g->frozen[i].real_pk, real_pk)) {
            return i;
        }
    }

    return -1;
}

/*
 * check if group with the given type and id is in group array.
 *
 * return group number if peer is in list.
 * return -1 if group is not in list.
 *
 * TODO(irungentoo): make this more efficient and maybe use constant time comparisons?
 */
static int32_t get_group_num(const Group_Chats *g_c, const uint8_t type, const uint8_t *id)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        if (g_c->chats[i].type == type && crypto_memcmp(g_c->chats[i].id, id, GROUP_ID_LENGTH) == 0) {
            return i;
        }
    }

    return -1;
}

int32_t conference_by_id(const Group_Chats *g_c, const uint8_t *id)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        if (crypto_memcmp(g_c->chats[i].id, id, GROUP_ID_LENGTH) == 0) {
            return i;
        }
    }

    return -1;
}

/*
 * check if peer with peer_number is in peer array.
 *
 * return peer index if peer is in chat.
 * return -1 if peer is not in chat.
 *
 * TODO(irungentoo): make this more efficient.
 */
static int get_peer_index(const Group_c *g, uint16_t peer_number)
{
    for (uint32_t i = 0; i < g->numpeers; ++i) {
        if (g->group[i].peer_number == peer_number) {
            return i;
        }
    }

    return -1;
}


static uint64_t calculate_comp_value(const uint8_t *pk1, const uint8_t *pk2)
{
    uint64_t cmp1 = 0;
    uint64_t cmp2 = 0;

    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        cmp1 = (cmp1 << 8) + (uint64_t)pk1[i];
        cmp2 = (cmp2 << 8) + (uint64_t)pk2[i];
    }

    return cmp1 - cmp2;
}

typedef enum Groupchat_Closest_Change {
    GROUPCHAT_CLOSEST_CHANGE_NONE,
    GROUPCHAT_CLOSEST_CHANGE_ADDED,
    GROUPCHAT_CLOSEST_CHANGE_REMOVED,
} Groupchat_Closest_Change;

static bool add_to_closest(Group_c *g, const uint8_t *real_pk, const uint8_t *temp_pk)
{
    if (public_key_cmp(g->real_pk, real_pk) == 0) {
        return false;
    }

    unsigned int index = DESIRED_CLOSEST;

    for (unsigned int i = 0; i < DESIRED_CLOSEST; ++i) {
        if (g->closest_peers[i].entry && public_key_cmp(real_pk, g->closest_peers[i].real_pk) == 0) {
            return true;
        }
    }

    for (unsigned int i = 0; i < DESIRED_CLOSEST; ++i) {
        if (g->closest_peers[i].entry == 0) {
            index = i;
            break;
        }
    }

    if (index == DESIRED_CLOSEST) {
        uint64_t comp_val = calculate_comp_value(g->real_pk, real_pk);
        uint64_t comp_d = 0;

        for (unsigned int i = 0; i < (DESIRED_CLOSEST / 2); ++i) {
            uint64_t comp = calculate_comp_value(g->real_pk, g->closest_peers[i].real_pk);

            if (comp > comp_val && comp > comp_d) {
                index = i;
                comp_d = comp;
            }
        }

        comp_val = calculate_comp_value(real_pk, g->real_pk);

        for (unsigned int i = (DESIRED_CLOSEST / 2); i < DESIRED_CLOSEST; ++i) {
            uint64_t comp = calculate_comp_value(g->closest_peers[i].real_pk, g->real_pk);

            if (comp > comp_val && comp > comp_d) {
                index = i;
                comp_d = comp;
            }
        }
    }

    if (index == DESIRED_CLOSEST) {
        return false;
    }

    uint8_t old_real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t old_temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t old = 0;

    if (g->closest_peers[index].entry) {
        memcpy(old_real_pk, g->closest_peers[index].real_pk, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(old_temp_pk, g->closest_peers[index].temp_pk, CRYPTO_PUBLIC_KEY_SIZE);
        old = 1;
    }

    g->closest_peers[index].entry = 1;
    memcpy(g->closest_peers[index].real_pk, real_pk, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(g->closest_peers[index].temp_pk, temp_pk, CRYPTO_PUBLIC_KEY_SIZE);

    if (old) {
        add_to_closest(g, old_real_pk, old_temp_pk);
    }

    if (!g->changed) {
        g->changed = GROUPCHAT_CLOSEST_CHANGE_ADDED;
    }

    return true;
}

static bool pk_in_closest_peers(const Group_c *g, uint8_t *real_pk)
{
    for (unsigned int i = 0; i < DESIRED_CLOSEST; ++i) {
        if (!g->closest_peers[i].entry) {
            continue;
        }

        if (public_key_cmp(g->closest_peers[i].real_pk, real_pk) == 0) {
            return true;
        }
    }

    return false;
}

static void remove_connection_reason(Group_Chats *g_c, Group_c *g, uint16_t i, uint8_t reason);

static void purge_closest(Group_Chats *g_c, uint32_t groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return;
    }

    for (uint32_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_NONE) {
            continue;
        }

        if (!(g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_CLOSEST)) {
            continue;
        }

        uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
        get_friendcon_public_keys(real_pk, nullptr, g_c->fr_c, g->connections[i].number);

        if (!pk_in_closest_peers(g, real_pk)) {
            remove_connection_reason(g_c, g, i, GROUPCHAT_CONNECTION_REASON_CLOSEST);
        }
    }
}

static int send_packet_online(Friend_Connections *fr_c, int friendcon_id, uint16_t group_num, uint8_t type,
                              const uint8_t *id);

static int add_conn_to_groupchat(Group_Chats *g_c, int friendcon_id, Group_c *g, uint8_t reason,
                                 uint8_t lock);

static void add_closest_connections(Group_Chats *g_c, uint32_t groupnumber, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return;
    }

    for (uint32_t i = 0; i < DESIRED_CLOSEST; ++i) {
        if (!g->closest_peers[i].entry) {
            continue;
        }

        int friendcon_id = getfriend_conn_id_pk(g_c->fr_c, g->closest_peers[i].real_pk);

        uint8_t fresh = 0;

        if (friendcon_id == -1) {
            friendcon_id = new_friend_connection(g_c->fr_c, g->closest_peers[i].real_pk);
            fresh = 1;

            if (friendcon_id == -1) {
                continue;
            }

            set_dht_temp_pk(g_c->fr_c, friendcon_id, g->closest_peers[i].temp_pk, userdata);
        }

        const int connection_index = add_conn_to_groupchat(g_c, friendcon_id, g,
                                     GROUPCHAT_CONNECTION_REASON_CLOSEST, !fresh);

        if (connection_index == -1) {
            if (fresh) {
                kill_friend_connection(g_c->fr_c, friendcon_id);
            }

            continue;
        }

        if (friend_con_connected(g_c->fr_c, friendcon_id) == FRIENDCONN_STATUS_CONNECTED
                && g->connections[connection_index].type == GROUPCHAT_CONNECTION_CONNECTING) {
            send_packet_online(g_c->fr_c, friendcon_id, groupnumber, g->type, g->id);
        }
    }
}

static bool connect_to_closest(Group_Chats *g_c, uint32_t groupnumber, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return false;
    }

    if (!g->changed) {
        return true;
    }

    if (g->changed == GROUPCHAT_CLOSEST_CHANGE_REMOVED) {
        for (uint32_t i = 0; i < g->numpeers; ++i) {
            add_to_closest(g, g->group[i].real_pk, g->group[i].temp_pk);
        }
    }

    purge_closest(g_c, groupnumber);

    add_closest_connections(g_c, groupnumber, userdata);

    g->changed = GROUPCHAT_CLOSEST_CHANGE_NONE;

    return true;
}

static int get_frozen_index(const Group_c *g, uint16_t peer_number)
{
    for (uint32_t i = 0; i < g->numfrozen; ++i) {
        if (g->frozen[i].peer_number == peer_number) {
            return i;
        }
    }

    return -1;
}

static bool delete_frozen(Group_c *g, uint32_t frozen_index)
{
    if (frozen_index >= g->numfrozen) {
        return false;
    }

    --g->numfrozen;

    if (g->numfrozen == 0) {
        free(g->frozen);
        g->frozen = nullptr;
    } else {
        if (g->numfrozen != frozen_index) {
            g->frozen[frozen_index] = g->frozen[g->numfrozen];
        }

        Group_Peer *const frozen_temp = (Group_Peer *)realloc(g->frozen, sizeof(Group_Peer) * (g->numfrozen));

        if (frozen_temp == nullptr) {
            return false;
        }

        g->frozen = frozen_temp;
    }

    return true;
}

/* Update last_active timestamp on peer, and thaw the peer if it is frozen.
 *
 * return peer index if peer is in the conference.
 * return -1 otherwise, and on error.
 */
static int note_peer_active(Group_Chats *g_c, uint32_t groupnumber, uint16_t peer_number, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    const int peer_index = get_peer_index(g, peer_number);

    if (peer_index != -1) {
        g->group[peer_index].last_active = mono_time_get(g_c->mono_time);
        return peer_index;
    }

    const int frozen_index = get_frozen_index(g, peer_number);

    if (frozen_index == -1) {
        return -1;
    }

    /* Now thaw the peer */

    Group_Peer *temp = (Group_Peer *)realloc(g->group, sizeof(Group_Peer) * (g->numpeers + 1));

    if (temp == nullptr) {
        return -1;
    }

    const uint32_t thawed_index = g->numpeers;

    g->group = temp;
    g->group[thawed_index] = g->frozen[frozen_index];
    g->group[thawed_index].temp_pk_updated = false;
    g->group[thawed_index].last_active = mono_time_get(g_c->mono_time);

    add_to_closest(g, g->group[thawed_index].real_pk, g->group[thawed_index].temp_pk);

    ++g->numpeers;

    delete_frozen(g, frozen_index);

    if (g_c->peer_list_changed_callback) {
        g_c->peer_list_changed_callback(g_c->m, groupnumber, userdata);
    }

    if (g->peer_on_join) {
        g->peer_on_join(g->object, groupnumber, thawed_index);
    }

    g->need_send_name = true;

    return thawed_index;
}

static bool delpeer(Group_Chats *g_c, uint32_t groupnumber, int peer_index, void *userdata);

static void delete_any_peer_with_pk(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *real_pk, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return;
    }

    const int peer_index = peer_in_group(g, real_pk);

    if (peer_index >= 0) {
        delpeer(g_c, groupnumber, peer_index, userdata);
    }

    const int frozen_index = frozen_in_group(g, real_pk);

    if (frozen_index >= 0) {
        delete_frozen(g, frozen_index);
    }
}

/* Add a peer to the group chat, or update an existing peer.
 *
 * fresh indicates whether we should consider this information on the peer to
 * be current, and so should update temp_pk and consider the peer active.
 *
 * do_gc_callback indicates whether we want to trigger callbacks set by the client
 * via the public API. This should be set to false if this function is called
 * from outside of the tox_iterate() loop.
 *
 * return peer_index if success or peer already in chat.
 * return -1 if error.
 */
static int addpeer(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *real_pk, const uint8_t *temp_pk,
                   uint16_t peer_number, void *userdata, bool fresh, bool do_gc_callback)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    const int peer_index = fresh ?
                           note_peer_active(g_c, groupnumber, peer_number, userdata) :
                           get_peer_index(g, peer_number);

    if (peer_index != -1) {
        if (!id_equal(g->group[peer_index].real_pk, real_pk)) {
            return -1;
        }

        if (fresh || !g->group[peer_index].temp_pk_updated) {
            id_copy(g->group[peer_index].temp_pk, temp_pk);
            g->group[peer_index].temp_pk_updated = true;
        }

        return peer_index;
    }

    if (!fresh) {
        const int frozen_index = get_frozen_index(g, peer_number);

        if (frozen_index != -1) {
            if (!id_equal(g->frozen[frozen_index].real_pk, real_pk)) {
                return -1;
            }

            id_copy(g->frozen[frozen_index].temp_pk, temp_pk);

            return -1;
        }
    }

    delete_any_peer_with_pk(g_c, groupnumber, real_pk, userdata);

    Group_Peer *temp = (Group_Peer *)realloc(g->group, sizeof(Group_Peer) * (g->numpeers + 1));

    if (temp == nullptr) {
        return -1;
    }

    memset(&temp[g->numpeers], 0, sizeof(Group_Peer));
    g->group = temp;

    const uint32_t new_index = g->numpeers;

    id_copy(g->group[new_index].real_pk, real_pk);
    id_copy(g->group[new_index].temp_pk, temp_pk);
    g->group[new_index].temp_pk_updated = true;
    g->group[new_index].peer_number = peer_number;
    g->group[new_index].last_active = mono_time_get(g_c->mono_time);
    g->group[new_index].is_friend = (getfriend_id(g_c->m, real_pk) != -1);
    ++g->numpeers;

    add_to_closest(g, real_pk, temp_pk);

    if (do_gc_callback && g_c->peer_list_changed_callback) {
        g_c->peer_list_changed_callback(g_c->m, groupnumber, userdata);
    }

    if (g->peer_on_join) {
        g->peer_on_join(g->object, groupnumber, new_index);
    }

    return new_index;
}

static void remove_connection(Group_Chats *g_c, Group_c *g, uint16_t i)
{
    if (g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_INTRODUCER) {
        --g->num_introducer_connections;
    }

    kill_friend_connection(g_c->fr_c, g->connections[i].number);
    g->connections[i].type = GROUPCHAT_CONNECTION_NONE;
}

static void remove_from_closest(Group_c *g, int peer_index)
{
    for (uint32_t i = 0; i < DESIRED_CLOSEST; ++i) {
        if (g->closest_peers[i].entry
                && id_equal(g->closest_peers[i].real_pk, g->group[peer_index].real_pk)) {
            g->closest_peers[i].entry = 0;
            g->changed = GROUPCHAT_CLOSEST_CHANGE_REMOVED;
            break;
        }
    }
}

/*
 * Delete a peer from the group chat.
 *
 * return true on success
 */
static bool delpeer(Group_Chats *g_c, uint32_t groupnumber, int peer_index, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return false;
    }

    remove_from_closest(g, peer_index);

    const int friendcon_id = getfriend_conn_id_pk(g_c->fr_c, g->group[peer_index].real_pk);

    if (friendcon_id != -1) {
        for (uint32_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
            if (g->connections[i].type == GROUPCHAT_CONNECTION_NONE) {
                continue;
            }

            if (g->connections[i].number == (unsigned int)friendcon_id) {
                remove_connection(g_c, g, i);
                break;
            }
        }
    }

    --g->numpeers;

    void *peer_object = g->group[peer_index].object;

    if (g->numpeers == 0) {
        free(g->group);
        g->group = nullptr;
    } else {
        if (g->numpeers != (uint32_t)peer_index) {
            g->group[peer_index] = g->group[g->numpeers];
        }

        Group_Peer *temp = (Group_Peer *)realloc(g->group, sizeof(Group_Peer) * (g->numpeers));

        if (temp == nullptr) {
            return false;
        }

        g->group = temp;
    }

    if (g_c->peer_list_changed_callback) {
        g_c->peer_list_changed_callback(g_c->m, groupnumber, userdata);
    }

    if (g->peer_on_leave) {
        g->peer_on_leave(g->object, groupnumber, peer_object);
    }

    return true;
}

static int cmp_u64(uint64_t a, uint64_t b)
{
    return (a > b) - (a < b);
}

/* Order peers with friends first and with more recently active earlier */
static int cmp_frozen(const void *a, const void *b)
{
    const Group_Peer *pa = (const Group_Peer *) a;
    const Group_Peer *pb = (const Group_Peer *) b;

    if (pa->is_friend ^ pb->is_friend) {
        return pa->is_friend ? -1 : 1;
    }

    return cmp_u64(pb->last_active, pa->last_active);
}

/* Delete frozen peers as necessary to ensure at most g->maxfrozen remain.
 *
 * return true if any frozen peers are removed.
 */
static bool delete_old_frozen(Group_c *g)
{
    if (g->numfrozen <= g->maxfrozen) {
        return false;
    }

    if (g->maxfrozen == 0) {
        free(g->frozen);
        g->frozen = nullptr;
        g->numfrozen = 0;
        return true;
    }

    qsort(g->frozen, g->numfrozen, sizeof(Group_Peer), cmp_frozen);

    Group_Peer *temp = (Group_Peer *)realloc(g->frozen, sizeof(Group_Peer) * g->maxfrozen);

    if (temp == nullptr) {
        return false;
    }

    g->frozen = temp;

    g->numfrozen = g->maxfrozen;

    return true;
}

static bool try_send_rejoin(Group_Chats *g_c, Group_c *g, const uint8_t *real_pk);

static bool freeze_peer(Group_Chats *g_c, uint32_t groupnumber, int peer_index, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return false;
    }

    Group_Peer *temp = (Group_Peer *)realloc(g->frozen, sizeof(Group_Peer) * (g->numfrozen + 1));

    if (temp == nullptr) {
        return false;
    }

    g->frozen = temp;
    g->frozen[g->numfrozen] = g->group[peer_index];
    g->frozen[g->numfrozen].object = nullptr;

    if (!delpeer(g_c, groupnumber, peer_index, userdata)) {
        return false;
    }

    try_send_rejoin(g_c, g, g->frozen[g->numfrozen].real_pk);

    ++g->numfrozen;

    delete_old_frozen(g);

    return true;
}


/* Set the nick for a peer.
 *
 * do_gc_callback indicates whether we want to trigger callbacks set by the client
 * via the public API. This should be set to false if this function is called
 * from outside of the tox_iterate() loop.
 *
 * return true on success.
 */
static bool setnick(Group_Chats *g_c, uint32_t groupnumber, int peer_index, const uint8_t *nick, uint16_t nick_len,
                    void *userdata, bool do_gc_callback)
{
    if (nick_len > MAX_NAME_LENGTH) {
        return false;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return false;
    }

    g->group[peer_index].nick_updated = true;

    if (g->group[peer_index].nick_len == nick_len
            && (nick_len == 0 || !memcmp(g->group[peer_index].nick, nick, nick_len))) {
        /* same name as already stored */
        return true;
    }

    if (nick_len) {
        memcpy(g->group[peer_index].nick, nick, nick_len);
    }

    g->group[peer_index].nick_len = nick_len;

    if (do_gc_callback && g_c->peer_name_callback) {
        g_c->peer_name_callback(g_c->m, groupnumber, peer_index, nick, nick_len, userdata);
    }

    return true;
}

/* Set the title for a group.
 *
 * return true on success.
 */
static bool settitle(Group_Chats *g_c, uint32_t groupnumber, int peer_index, const uint8_t *title, uint8_t title_len,
                     void *userdata)
{
    if (title_len > MAX_NAME_LENGTH || title_len == 0) {
        return false;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return false;
    }

    if (g->title_len == title_len && !memcmp(g->title, title, title_len)) {
        /* same title as already set */
        return true;
    }

    memcpy(g->title, title, title_len);
    g->title_len = title_len;

    g->title_fresh = true;

    if (g_c->title_callback) {
        g_c->title_callback(g_c->m, groupnumber, peer_index, title, title_len, userdata);
    }

    return true;
}

/* Check if the group has no online connection, and freeze all peers if so */
static void check_disconnected(Group_Chats *g_c, uint32_t groupnumber, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return;
    }

    for (uint32_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_ONLINE) {
            return;
        }
    }

    for (uint32_t i = 0; i < g->numpeers; ++i) {
        while (i < g->numpeers && !id_equal(g->group[i].real_pk, g->real_pk)) {
            freeze_peer(g_c, groupnumber, i, userdata);
        }
    }
}

static void set_conns_type_connections(Group_Chats *g_c, uint32_t groupnumber, int friendcon_id, uint8_t type,
                                       void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return;
    }

    for (uint32_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_NONE) {
            continue;
        }

        if (g->connections[i].number != (unsigned int)friendcon_id) {
            continue;
        }

        if (type == GROUPCHAT_CONNECTION_ONLINE) {
            send_packet_online(g_c->fr_c, friendcon_id, groupnumber, g->type, g->id);
        } else {
            g->connections[i].type = type;
            check_disconnected(g_c, groupnumber, userdata);
        }
    }
}

/* Set the type for all connections with friendcon_id */
static void set_conns_status_groups(Group_Chats *g_c, int friendcon_id, uint8_t type, void *userdata)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        set_conns_type_connections(g_c, i, friendcon_id, type, userdata);
    }
}

static void rejoin_frozen_friend(Group_Chats *g_c, int friendcon_id)
{
    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    get_friendcon_public_keys(real_pk, nullptr, g_c->fr_c, friendcon_id);

    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        Group_c *g = get_group_c(g_c, i);

        if (!g) {
            continue;
        }

        for (uint32_t j = 0; j < g->numfrozen; ++j) {
            if (id_equal(g->frozen[j].real_pk, real_pk)) {
                try_send_rejoin(g_c, g, real_pk);
                break;
            }
        }
    }
}

static int g_handle_any_status(void *object, int friendcon_id, uint8_t status, void *userdata)
{
    Group_Chats *g_c = (Group_Chats *)object;

    if (status) {
        rejoin_frozen_friend(g_c, friendcon_id);
    }

    return 0;
}

static int g_handle_status(void *object, int friendcon_id, uint8_t status, void *userdata)
{
    Group_Chats *g_c = (Group_Chats *)object;

    if (status) { /* Went online */
        set_conns_status_groups(g_c, friendcon_id, GROUPCHAT_CONNECTION_ONLINE, userdata);
    } else { /* Went offline */
        set_conns_status_groups(g_c, friendcon_id, GROUPCHAT_CONNECTION_CONNECTING, userdata);
        // TODO(irungentoo): remove timedout connections?
    }

    return 0;
}

static int g_handle_packet(void *object, int friendcon_id, const uint8_t *data, uint16_t length, void *userdata);
static int handle_lossy(void *object, int friendcon_id, const uint8_t *data, uint16_t length, void *userdata);

/* Add friend to group chat.
 *
 * return connections index on success
 * return -1 on failure.
 */
static int add_conn_to_groupchat(Group_Chats *g_c, int friendcon_id, Group_c *g, uint8_t reason,
                                 uint8_t lock)
{
    uint16_t empty = MAX_GROUP_CONNECTIONS;
    uint16_t ind = MAX_GROUP_CONNECTIONS;

    for (uint16_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_NONE) {
            empty = i;
            continue;
        }

        if (g->connections[i].number == (uint32_t)friendcon_id) {
            ind = i; /* Already in list. */
            break;
        }
    }

    if (ind == MAX_GROUP_CONNECTIONS) {
        if (empty == MAX_GROUP_CONNECTIONS) {
            return -1;
        }

        if (lock) {
            friend_connection_lock(g_c->fr_c, friendcon_id);
        }

        g->connections[empty].type = GROUPCHAT_CONNECTION_CONNECTING;
        g->connections[empty].number = friendcon_id;
        g->connections[empty].reasons = 0;
        // TODO(irungentoo):
        friend_connection_callbacks(g_c->m->fr_c, friendcon_id, GROUPCHAT_CALLBACK_INDEX, &g_handle_status, &g_handle_packet,
                                    &handle_lossy, g_c, friendcon_id);
        ind = empty;
    }

    if (!(g->connections[ind].reasons & reason)) {
        g->connections[ind].reasons |= reason;

        if (reason == GROUPCHAT_CONNECTION_REASON_INTRODUCER) {
            ++g->num_introducer_connections;
        }
    }

    return ind;
}

static unsigned int send_peer_introduced(Group_Chats *g_c, int friendcon_id, uint16_t group_num);

/* Removes reason for keeping connection.
 *
 * Kills connection if this was the last reason.
 */
static void remove_connection_reason(Group_Chats *g_c, Group_c *g, uint16_t i, uint8_t reason)
{
    if (!(g->connections[i].reasons & reason)) {
        return;
    }

    g->connections[i].reasons &= ~reason;

    if (reason == GROUPCHAT_CONNECTION_REASON_INTRODUCER) {
        --g->num_introducer_connections;

        if (g->connections[i].type == GROUPCHAT_CONNECTION_ONLINE) {
            send_peer_introduced(g_c, g->connections[i].number, g->connections[i].group_number);
        }
    }

    if (g->connections[i].reasons == 0) {
        kill_friend_connection(g_c->fr_c, g->connections[i].number);
        g->connections[i].type = GROUPCHAT_CONNECTION_NONE;
    }
}

/* Creates a new groupchat and puts it in the chats array.
 *
 * type is one of `GROUPCHAT_TYPE_*`
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_groupchat(Group_Chats *g_c, uint8_t type)
{
    const int32_t groupnumber = create_group_chat(g_c);

    if (groupnumber == -1) {
        return -1;
    }

    Group_c *g = &g_c->chats[groupnumber];

    g->status = GROUPCHAT_STATUS_CONNECTED;
    g->type = type;
    new_symmetric_key(g->id);
    g->peer_number = 0; /* Founder is peer 0. */
    memcpy(g->real_pk, nc_get_self_public_key(g_c->m->net_crypto), CRYPTO_PUBLIC_KEY_SIZE);
    const int peer_index = addpeer(g_c, groupnumber, g->real_pk, dht_get_self_public_key(g_c->m->dht), 0, nullptr, true,
                                   false);

    if (peer_index == -1) {
        return -1;
    }

    setnick(g_c, groupnumber, peer_index, g_c->m->name, g_c->m->name_length, nullptr, false);

    return groupnumber;
}

static bool group_leave(const Group_Chats *g_c, uint32_t groupnumber, bool permanent);

/* Delete a groupchat from the chats array, informing the group first as
 * appropriate.
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 */
int del_groupchat(Group_Chats *g_c, uint32_t groupnumber, bool leave_permanently)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    group_leave(g_c, groupnumber, leave_permanently);

    for (uint32_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_NONE) {
            continue;
        }

        g->connections[i].type = GROUPCHAT_CONNECTION_NONE;
        kill_friend_connection(g_c->fr_c, g->connections[i].number);
    }

    for (uint32_t i = 0; i < g->numpeers; ++i) {
        if (g->peer_on_leave) {
            g->peer_on_leave(g->object, groupnumber, g->group[i].object);
        }
    }

    free(g->group);
    free(g->frozen);

    if (g->group_on_delete) {
        g->group_on_delete(g->object, groupnumber);
    }

    return wipe_group_chat(g_c, groupnumber);
}

static const Group_Peer *peer_in_list(const Group_c *g, uint32_t peernumber, bool frozen)
{
    const Group_Peer *list = frozen ? g->frozen : g->group;
    const uint32_t num = frozen ? g->numfrozen : g->numpeers;

    if (peernumber >= num) {
        return nullptr;
    }

    return &list[peernumber];
}


/* Copy the public key of (frozen, if frozen is true) peernumber who is in
 * groupnumber to pk. pk must be CRYPTO_PUBLIC_KEY_SIZE long.
 *
 * return 0 on success
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_peer_pubkey(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, uint8_t *pk, bool frozen)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    const Group_Peer *peer = peer_in_list(g, peernumber, frozen);

    if (peer == nullptr) {
        return -2;
    }

    memcpy(pk, peer->real_pk, CRYPTO_PUBLIC_KEY_SIZE);
    return 0;
}

/*
 * Return the size of (frozen, if frozen is true) peernumber's name.
 *
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_peername_size(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, bool frozen)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    const Group_Peer *peer = peer_in_list(g, peernumber, frozen);

    if (peer == nullptr) {
        return -2;
    }

    return peer->nick_len;
}

/* Copy the name of (frozen, if frozen is true) peernumber who is in
 * groupnumber to name. name must be at least MAX_NAME_LENGTH long.
 *
 * return length of name if success
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_peername(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, uint8_t *name, bool frozen)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    const Group_Peer *peer = peer_in_list(g, peernumber, frozen);

    if (peer == nullptr) {
        return -2;
    }

    if (peer->nick_len > 0) {
        memcpy(name, peer->nick, peer->nick_len);
    }

    return peer->nick_len;
}

/* Copy last active timestamp of frozennumber who is in groupnumber to
 * last_active.
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 * return -2 if frozennumber is invalid.
 */
int group_frozen_last_active(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber,
                             uint64_t *last_active)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    if (peernumber >= g->numfrozen) {
        return -2;
    }

    *last_active = g->frozen[peernumber].last_active;
    return 0;
}

/* Set maximum number of frozen peers.
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 */
int group_set_max_frozen(const Group_Chats *g_c, uint32_t groupnumber, uint32_t maxfrozen)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    g->maxfrozen = maxfrozen;
    delete_old_frozen(g);
    return 0;
}

/* Return the number of (frozen, if frozen is true) peers in the group chat on
 * success.
 * return -1 if groupnumber is invalid.
 */
int group_number_peers(const Group_Chats *g_c, uint32_t groupnumber, bool frozen)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    return frozen ? g->numfrozen : g->numpeers;
}

/* return 1 if the peernumber corresponds to ours.
 * return 0 if the peernumber is not ours.
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 * return -3 if we are not connected to the group chat.
 */
int group_peernumber_is_ours(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    if (peernumber >= g->numpeers) {
        return -2;
    }

    if (g->status != GROUPCHAT_STATUS_CONNECTED) {
        return -3;
    }

    return g->peer_number == g->group[peernumber].peer_number;
}

/* return the type of groupchat (GROUPCHAT_TYPE_) that groupnumber is.
 *
 * return -1 on failure.
 * return type on success.
 */
int group_get_type(const Group_Chats *g_c, uint32_t groupnumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    return g->type;
}

/* Copies the unique id of `group_chat[groupnumber]` into `id`.
 *
 * return false on failure.
 * return true on success.
 */
bool conference_get_id(const Group_Chats *g_c, uint32_t groupnumber, uint8_t *id)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return false;
    }

    if (id != nullptr) {
        memcpy(id, g->id, sizeof(g->id));
    }

    return true;
}

/* Send a group packet to friendcon_id.
 *
 *  return 1 on success
 *  return 0 on failure
 */
static unsigned int send_packet_group_peer(Friend_Connections *fr_c, int friendcon_id, uint8_t packet_id,
        uint16_t group_num, const uint8_t *data, uint16_t length)
{
    if (1 + sizeof(uint16_t) + length > MAX_CRYPTO_DATA_SIZE) {
        return 0;
    }

    group_num = net_htons(group_num);
    VLA(uint8_t, packet, 1 + sizeof(uint16_t) + length);
    packet[0] = packet_id;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    memcpy(packet + 1 + sizeof(uint16_t), data, length);
    return write_cryptpacket(friendconn_net_crypto(fr_c), friend_connection_crypt_connection_id(fr_c, friendcon_id), packet,
                             SIZEOF_VLA(packet), 0) != -1;
}

/* Send a group lossy packet to friendcon_id.
 *
 *  return 1 on success
 *  return 0 on failure
 */
static unsigned int send_lossy_group_peer(Friend_Connections *fr_c, int friendcon_id, uint8_t packet_id,
        uint16_t group_num, const uint8_t *data, uint16_t length)
{
    if (1 + sizeof(uint16_t) + length > MAX_CRYPTO_DATA_SIZE) {
        return 0;
    }

    group_num = net_htons(group_num);
    VLA(uint8_t, packet, 1 + sizeof(uint16_t) + length);
    packet[0] = packet_id;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    memcpy(packet + 1 + sizeof(uint16_t), data, length);
    return send_lossy_cryptpacket(friendconn_net_crypto(fr_c), friend_connection_crypt_connection_id(fr_c, friendcon_id),
                                  packet, SIZEOF_VLA(packet)) != -1;
}

/* invite friendnumber to groupnumber.
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 * return -2 if invite packet failed to send.
 * return -3 if we are not connected to the group chat.
 */
int invite_friend(Group_Chats *g_c, uint32_t friendnumber, uint32_t groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    if (g->status != GROUPCHAT_STATUS_CONNECTED) {
        return -3;
    }

    uint8_t invite[INVITE_PACKET_SIZE];
    invite[0] = INVITE_ID;
    const uint16_t groupchat_num = net_htons((uint16_t)groupnumber);
    memcpy(invite + 1, &groupchat_num, sizeof(groupchat_num));
    invite[1 + sizeof(groupchat_num)] = g->type;
    memcpy(invite + 1 + sizeof(groupchat_num) + 1, g->id, GROUP_ID_LENGTH);

    if (send_conference_invite_packet(g_c->m, friendnumber, invite, sizeof(invite))) {
        return 0;
    }

    return -2;
}

/* Send a rejoin packet to a peer if we have a friend connection to the peer.
 * return true if a packet was sent.
 * return false otherwise.
 */
static bool try_send_rejoin(Group_Chats *g_c, Group_c *g, const uint8_t *real_pk)
{
    const int friendcon_id = getfriend_conn_id_pk(g_c->fr_c, real_pk);

    if (friendcon_id == -1) {
        return false;
    }

    uint8_t packet[1 + 1 + GROUP_ID_LENGTH];
    packet[0] = PACKET_ID_REJOIN_CONFERENCE;
    packet[1] = g->type;
    memcpy(packet + 2, g->id, GROUP_ID_LENGTH);

    if (write_cryptpacket(friendconn_net_crypto(g_c->fr_c), friend_connection_crypt_connection_id(g_c->fr_c, friendcon_id),
                          packet, sizeof(packet), 0) == -1) {
        return false;
    }

    add_conn_to_groupchat(g_c, friendcon_id, g, GROUPCHAT_CONNECTION_REASON_INTRODUCER, 1);

    return true;
}

static unsigned int send_peer_query(Group_Chats *g_c, int friendcon_id, uint16_t group_num);

static bool send_invite_response(Group_Chats *g_c, int groupnumber, uint32_t friendnumber, const uint8_t *data,
                                 uint16_t length);

/* Join a group (we need to have been invited first.)
 *
 * expected_type is the groupchat type we expect the chat we are joining to
 * have.
 *
 * return group number on success.
 * return -1 if data length is invalid.
 * return -2 if group is not the expected type.
 * return -3 if friendnumber is invalid.
 * return -4 if client is already in this group.
 * return -5 if group instance failed to initialize.
 * return -6 if join packet fails to send.
 */
int join_groupchat(Group_Chats *g_c, uint32_t friendnumber, uint8_t expected_type, const uint8_t *data, uint16_t length)
{
    if (length != sizeof(uint16_t) + 1 + GROUP_ID_LENGTH) {
        return -1;
    }

    if (data[sizeof(uint16_t)] != expected_type) {
        return -2;
    }

    const int friendcon_id = getfriendcon_id(g_c->m, friendnumber);

    if (friendcon_id == -1) {
        return -3;
    }

    if (get_group_num(g_c, data[sizeof(uint16_t)], data + sizeof(uint16_t) + 1) != -1) {
        return -4;
    }

    const int groupnumber = create_group_chat(g_c);

    if (groupnumber == -1) {
        return -5;
    }

    Group_c *g = &g_c->chats[groupnumber];

    g->status = GROUPCHAT_STATUS_VALID;
    memcpy(g->real_pk, nc_get_self_public_key(g_c->m->net_crypto), CRYPTO_PUBLIC_KEY_SIZE);

    if (!send_invite_response(g_c, groupnumber, friendnumber, data, length)) {
        g->status = GROUPCHAT_STATUS_NONE;
        return -6;
    }

    return groupnumber;
}

static bool send_invite_response(Group_Chats *g_c, int groupnumber, uint32_t friendnumber, const uint8_t *data,
                                 uint16_t length)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return false;
    }

    const bool member = (g->status == GROUPCHAT_STATUS_CONNECTED);

    VLA(uint8_t, response, member ? INVITE_MEMBER_PACKET_SIZE : INVITE_ACCEPT_PACKET_SIZE);
    response[0] = member ? INVITE_MEMBER_ID : INVITE_ACCEPT_ID;
    net_pack_u16(response + 1, groupnumber);
    memcpy(response + 1 + sizeof(uint16_t), data, length);

    if (member) {
        net_pack_u16(response + 1 + sizeof(uint16_t) + length, g->peer_number);
    }

    if (!send_conference_invite_packet(g_c->m, friendnumber, response, SIZEOF_VLA(response))) {
        return false;
    }

    if (!member) {
        g->type = data[sizeof(uint16_t)];
        memcpy(g->id, data + sizeof(uint16_t) + 1, GROUP_ID_LENGTH);
    }

    uint16_t other_groupnum;
    net_unpack_u16(data, &other_groupnum);

    const int friendcon_id = getfriendcon_id(g_c->m, friendnumber);

    if (friendcon_id == -1) {
        return false;
    }

    const int connection_index = add_conn_to_groupchat(g_c, friendcon_id, g, GROUPCHAT_CONNECTION_REASON_INTRODUCER, 1);

    if (member) {
        add_conn_to_groupchat(g_c, friendcon_id, g, GROUPCHAT_CONNECTION_REASON_INTRODUCING, 0);
    }

    if (connection_index != -1) {
        g->connections[connection_index].group_number = other_groupnum;
        g->connections[connection_index].type = GROUPCHAT_CONNECTION_ONLINE;
    }

    send_peer_query(g_c, friendcon_id, other_groupnum);

    return true;
}

/* Set handlers for custom lossy packets. */
void group_lossy_packet_registerhandler(Group_Chats *g_c, uint8_t byte, lossy_packet_cb *function)
{
    g_c->lossy_packethandlers[byte].function = function;
}

/* Set the callback for group invites. */
void g_callback_group_invite(Group_Chats *g_c, g_conference_invite_cb *function)
{
    g_c->invite_callback = function;
}

/* Set the callback for group connection. */
void g_callback_group_connected(Group_Chats *g_c, g_conference_connected_cb *function)
{
    g_c->connected_callback = function;
}

/* Set the callback for group messages. */
void g_callback_group_message(Group_Chats *g_c, g_conference_message_cb *function)
{
    g_c->message_callback = function;
}

/* Set callback function for peer nickname changes.
 *
 * It gets called every time a peer changes their nickname.
 */
void g_callback_peer_name(Group_Chats *g_c, peer_name_cb *function)
{
    g_c->peer_name_callback = function;
}

/* Set callback function for peer list changes.
 *
 * It gets called every time the name list changes(new peer, deleted peer)
 */
void g_callback_peer_list_changed(Group_Chats *g_c, peer_list_changed_cb *function)
{
    g_c->peer_list_changed_callback = function;
}

/* Set callback function for title changes. */
void g_callback_group_title(Group_Chats *g_c, title_cb *function)
{
    g_c->title_callback = function;
}

/* Set a function to be called when a new peer joins a group chat.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_new(const Group_Chats *g_c, uint32_t groupnumber, peer_on_join_cb *function)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    g->peer_on_join = function;
    return 0;
}

/* Set a function to be called when a peer leaves a group chat.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_delete(Group_Chats *g_c, uint32_t groupnumber, peer_on_leave_cb *function)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    g->peer_on_leave = function;
    return 0;
}

/* Set a function to be called when the group chat is deleted.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_delete(Group_Chats *g_c, uint32_t groupnumber, group_on_delete_cb *function)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    g->group_on_delete = function;
    return 0;
}

static int send_message_group(const Group_Chats *g_c, uint32_t groupnumber, uint8_t message_id, const uint8_t *data,
                              uint16_t len);

/* send a ping message
 * return true on success
 */
static bool group_ping_send(const Group_Chats *g_c, uint32_t groupnumber)
{
    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_PING_ID, nullptr, 0) > 0) {
        return true;
    }

    return false;
}

/* send a new_peer message
 * return true on success
 */
static bool group_new_peer_send(const Group_Chats *g_c, uint32_t groupnumber, uint16_t peer_num, const uint8_t *real_pk,
                                uint8_t *temp_pk)
{
    uint8_t packet[GROUP_MESSAGE_NEW_PEER_LENGTH];

    peer_num = net_htons(peer_num);
    memcpy(packet, &peer_num, sizeof(uint16_t));
    memcpy(packet + sizeof(uint16_t), real_pk, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(packet + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE, temp_pk, CRYPTO_PUBLIC_KEY_SIZE);

    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_NEW_PEER_ID, packet, sizeof(packet)) > 0) {
        return true;
    }

    return false;
}

/* send a kill_peer message
 * return true on success
 */
static bool group_kill_peer_send(const Group_Chats *g_c, uint32_t groupnumber, uint16_t peer_num)
{
    uint8_t packet[GROUP_MESSAGE_KILL_PEER_LENGTH];

    peer_num = net_htons(peer_num);
    memcpy(packet, &peer_num, sizeof(uint16_t));

    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_KILL_PEER_ID, packet, sizeof(packet)) > 0) {
        return true;
    }

    return false;
}

/* send a freeze_peer message
 * return true on success
 */
static bool group_freeze_peer_send(const Group_Chats *g_c, uint32_t groupnumber, uint16_t peer_num)
{
    uint8_t packet[GROUP_MESSAGE_KILL_PEER_LENGTH];

    peer_num = net_htons(peer_num);
    memcpy(packet, &peer_num, sizeof(uint16_t));

    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_FREEZE_PEER_ID, packet, sizeof(packet)) > 0) {
        return true;
    }

    return false;
}

/* send a name message
 * return true on success
 */
static bool group_name_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *nick, uint16_t nick_len)
{
    if (nick_len > MAX_NAME_LENGTH) {
        return false;
    }

    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_NAME_ID, nick, nick_len) > 0) {
        return true;
    }

    return false;
}

/* send message to announce leaving group
 * return true on success
 */
static bool group_leave(const Group_Chats *g_c, uint32_t groupnumber, bool permanent)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return false;
    }

    if (permanent) {
        return group_kill_peer_send(g_c, groupnumber, g->peer_number);
    } else {
        return group_freeze_peer_send(g_c, groupnumber, g->peer_number);
    }
}


/* set the group's title, limited to MAX_NAME_LENGTH
 * return 0 on success
 * return -1 if groupnumber is invalid.
 * return -2 if title is too long or empty.
 * return -3 if packet fails to send.
 */
int group_title_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *title, uint8_t title_len)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    if (title_len > MAX_NAME_LENGTH || title_len == 0) {
        return -2;
    }

    /* same as already set? */
    if (g->title_len == title_len && !memcmp(g->title, title, title_len)) {
        return 0;
    }

    memcpy(g->title, title, title_len);
    g->title_len = title_len;

    if (g->numpeers == 1) {
        return 0;
    }

    if (send_message_group(g_c, groupnumber, GROUP_MESSAGE_TITLE_ID, title, title_len) > 0) {
        return 0;
    }

    return -3;
}

/* return the group's title size.
 * return -1 of groupnumber is invalid.
 * return -2 if title is too long or empty.
 */
int group_title_get_size(const Group_Chats *g_c, uint32_t groupnumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    if (g->title_len > MAX_NAME_LENGTH || g->title_len == 0) {
        return -2;
    }

    return g->title_len;
}

/* Get group title from groupnumber and put it in title.
 * Title needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 * return length of copied title if success.
 * return -1 if groupnumber is invalid.
 * return -2 if title is too long or empty.
 */
int group_title_get(const Group_Chats *g_c, uint32_t groupnumber, uint8_t *title)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    if (g->title_len > MAX_NAME_LENGTH || g->title_len == 0) {
        return -2;
    }

    memcpy(title, g->title, g->title_len);
    return g->title_len;
}

static bool get_peer_number(const Group_c *g, const uint8_t *real_pk, uint16_t *peer_number)
{
    const int peer_index = peer_in_group(g, real_pk);

    if (peer_index >= 0) {
        *peer_number = g->group[peer_index].peer_number;
        return true;
    }

    const int frozen_index = frozen_in_group(g, real_pk);

    if (frozen_index >= 0) {
        *peer_number = g->frozen[frozen_index].peer_number;
        return true;
    }

    return false;
}

static void handle_friend_invite_packet(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length,
                                        void *userdata)
{
    Group_Chats *g_c = m->conferences_object;

    if (length <= 1) {
        return;
    }

    const uint8_t *invite_data = data + 1;
    const uint16_t invite_length = length - 1;

    switch (data[0]) {
        case INVITE_ID: {
            if (length != INVITE_PACKET_SIZE) {
                return;
            }

            const int groupnumber = get_group_num(g_c, data[1 + sizeof(uint16_t)], data + 1 + sizeof(uint16_t) + 1);

            if (groupnumber == -1) {
                if (g_c->invite_callback) {
                    g_c->invite_callback(m, friendnumber, invite_data[sizeof(uint16_t)], invite_data, invite_length, userdata);
                }

                return;
            } else {
                Group_c *g = get_group_c(g_c, groupnumber);

                if (g && g->status == GROUPCHAT_STATUS_CONNECTED) {
                    send_invite_response(g_c, groupnumber, friendnumber, invite_data, invite_length);
                }
            }

            break;
        }

        case INVITE_ACCEPT_ID:
        case INVITE_MEMBER_ID: {
            const bool member = (data[0] == INVITE_MEMBER_ID);

            if (length != (member ? INVITE_MEMBER_PACKET_SIZE : INVITE_ACCEPT_PACKET_SIZE)) {
                return;
            }

            uint16_t other_groupnum;
            uint16_t groupnum;
            net_unpack_u16(data + 1, &other_groupnum);
            net_unpack_u16(data + 1 + sizeof(uint16_t), &groupnum);

            Group_c *g = get_group_c(g_c, groupnum);

            if (!g) {
                return;
            }

            if (data[1 + sizeof(uint16_t) * 2] != g->type) {
                return;
            }

            if (crypto_memcmp(data + 1 + sizeof(uint16_t) * 2 + 1, g->id, GROUP_ID_LENGTH) != 0) {
                return;
            }

            uint16_t peer_number;

            if (member) {
                net_unpack_u16(data + 1 + sizeof(uint16_t) * 2 + 1 + GROUP_ID_LENGTH, &peer_number);
            } else {
                /* TODO(irungentoo): what if two people enter the group at the
                 * same time and are given the same peer_number by different
                 * nodes? */
                peer_number = random_u16();

                unsigned int tries = 0;

                while (get_peer_index(g, peer_number) != -1 || get_frozen_index(g, peer_number) != -1) {
                    peer_number = random_u16();
                    ++tries;

                    if (tries > 32) {
                        return;
                    }
                }
            }

            const int friendcon_id = getfriendcon_id(m, friendnumber);

            if (friendcon_id == -1) {
                // TODO(iphydf): Log something?
                return;
            }

            uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
            uint8_t temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
            get_friendcon_public_keys(real_pk, temp_pk, g_c->fr_c, friendcon_id);

            addpeer(g_c, groupnum, real_pk, temp_pk, peer_number, userdata, true, true);
            const int connection_index = add_conn_to_groupchat(g_c, friendcon_id, g,
                                         GROUPCHAT_CONNECTION_REASON_INTRODUCING, 1);

            if (member) {
                add_conn_to_groupchat(g_c, friendcon_id, g, GROUPCHAT_CONNECTION_REASON_INTRODUCER, 0);
                send_peer_query(g_c, friendcon_id, other_groupnum);
            }

            if (connection_index != -1) {
                g->connections[connection_index].group_number = other_groupnum;
                g->connections[connection_index].type = GROUPCHAT_CONNECTION_ONLINE;
            }

            group_new_peer_send(g_c, groupnum, peer_number, real_pk, temp_pk);

            break;
        }

        default:
            return;
    }
}

/* Find index of friend in the connections list.
 *
 * return index on success
 * return -1 on failure.
 */
static int friend_in_connections(const Group_c *g, int friendcon_id)
{
    for (unsigned int i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_NONE) {
            continue;
        }

        if (g->connections[i].number == (uint32_t)friendcon_id) {
            return i;
        }
    }

    return -1;
}

/* return number of connections.
 */
static unsigned int count_connected(const Group_c *g)
{
    unsigned int count = 0;

    for (unsigned int i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_ONLINE) {
            ++count;
        }
    }

    return count;
}

static int send_packet_online(Friend_Connections *fr_c, int friendcon_id, uint16_t group_num, uint8_t type,
                              const uint8_t *id)
{
    uint8_t packet[1 + ONLINE_PACKET_DATA_SIZE];
    group_num = net_htons(group_num);
    packet[0] = PACKET_ID_ONLINE_PACKET;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    packet[1 + sizeof(uint16_t)] = type;
    memcpy(packet + 1 + sizeof(uint16_t) + 1, id, GROUP_ID_LENGTH);
    return write_cryptpacket(friendconn_net_crypto(fr_c), friend_connection_crypt_connection_id(fr_c, friendcon_id), packet,
                             sizeof(packet), 0) != -1;
}

static bool ping_groupchat(Group_Chats *g_c, uint32_t groupnumber);

static int handle_packet_online(Group_Chats *g_c, int friendcon_id, const uint8_t *data, uint16_t length)
{
    if (length != ONLINE_PACKET_DATA_SIZE) {
        return -1;
    }

    const int groupnumber = get_group_num(g_c, data[sizeof(uint16_t)], data + sizeof(uint16_t) + 1);

    if (groupnumber == -1) {
        return -1;
    }

    uint16_t other_groupnum;
    memcpy(&other_groupnum, data, sizeof(uint16_t));
    other_groupnum = net_ntohs(other_groupnum);

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    const int index = friend_in_connections(g, friendcon_id);

    if (index == -1) {
        return -1;
    }

    if (g->connections[index].type == GROUPCHAT_CONNECTION_ONLINE) {
        return -1;
    }

    if (count_connected(g) == 0 || (g->connections[index].reasons & GROUPCHAT_CONNECTION_REASON_INTRODUCER)) {
        send_peer_query(g_c, friendcon_id, other_groupnum);
    }

    g->connections[index].group_number = other_groupnum;
    g->connections[index].type = GROUPCHAT_CONNECTION_ONLINE;
    send_packet_online(g_c->fr_c, friendcon_id, groupnumber, g->type, g->id);

    if (g->connections[index].reasons & GROUPCHAT_CONNECTION_REASON_INTRODUCING) {
        uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
        uint8_t temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
        get_friendcon_public_keys(real_pk, temp_pk, g_c->fr_c, friendcon_id);

        const int peer_index = peer_in_group(g, real_pk);

        if (peer_index != -1) {
            group_new_peer_send(g_c, groupnumber, g->group[peer_index].peer_number, real_pk, temp_pk);
        }

        g->need_send_name = true;
    }

    ping_groupchat(g_c, groupnumber);

    return 0;
}

static int handle_packet_rejoin(Group_Chats *g_c, int friendcon_id, const uint8_t *data, uint16_t length,
                                void *userdata)
{
    if (length < 1 + GROUP_ID_LENGTH) {
        return -1;
    }

    const int32_t groupnum = get_group_num(g_c, *data, data + 1);

    Group_c *g = get_group_c(g_c, groupnum);

    if (!g) {
        return -1;
    }

    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
    get_friendcon_public_keys(real_pk, temp_pk, g_c->fr_c, friendcon_id);

    uint16_t peer_number;

    if (!get_peer_number(g, real_pk, &peer_number)) {
        return -1;
    }

    addpeer(g_c, groupnum, real_pk, temp_pk, peer_number, userdata, true, true);
    const int connection_index = add_conn_to_groupchat(g_c, friendcon_id, g,
                                 GROUPCHAT_CONNECTION_REASON_INTRODUCING, 1);

    if (connection_index != -1) {
        send_packet_online(g_c->fr_c, friendcon_id, groupnum, g->type, g->id);
    }

    return 0;
}


// we could send title with invite, but then if it changes between sending and accepting inv, joinee won't see it

/* return 1 on success.
 * return 0 on failure
 */
static unsigned int send_peer_introduced(Group_Chats *g_c, int friendcon_id, uint16_t group_num)
{
    uint8_t packet[1];
    packet[0] = PEER_INTRODUCED_ID;
    return send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_CONFERENCE, group_num, packet, sizeof(packet));
}


/* return 1 on success.
 * return 0 on failure
 */
static unsigned int send_peer_query(Group_Chats *g_c, int friendcon_id, uint16_t group_num)
{
    uint8_t packet[1];
    packet[0] = PEER_QUERY_ID;
    return send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_CONFERENCE, group_num, packet, sizeof(packet));
}

/* return number of peers sent on success.
 * return 0 on failure.
 */
static unsigned int send_peers(Group_Chats *g_c, const Group_c *g, int friendcon_id, uint16_t group_num)
{
    uint8_t response_packet[MAX_CRYPTO_DATA_SIZE - (1 + sizeof(uint16_t))];
    response_packet[0] = PEER_RESPONSE_ID;
    uint8_t *p = response_packet + 1;

    uint16_t sent = 0;

    for (uint32_t i = 0;; ++i) {
        if (i == g->numpeers
                || (p - response_packet) + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE * 2 + 1 + g->group[i].nick_len >
                sizeof(response_packet)) {
            if (send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_CONFERENCE, group_num, response_packet,
                                       (p - response_packet))) {
                sent = i;
            } else {
                return sent;
            }

            if (i == g->numpeers) {
                break;
            }

            p = response_packet + 1;
        }

        const uint16_t peer_num = net_htons(g->group[i].peer_number);
        memcpy(p, &peer_num, sizeof(peer_num));
        p += sizeof(peer_num);
        memcpy(p, g->group[i].real_pk, CRYPTO_PUBLIC_KEY_SIZE);
        p += CRYPTO_PUBLIC_KEY_SIZE;
        memcpy(p, g->group[i].temp_pk, CRYPTO_PUBLIC_KEY_SIZE);
        p += CRYPTO_PUBLIC_KEY_SIZE;
        *p = g->group[i].nick_len;
        p += 1;
        memcpy(p, g->group[i].nick, g->group[i].nick_len);
        p += g->group[i].nick_len;
    }

    if (g->title_len) {
        VLA(uint8_t, title_packet, 1 + g->title_len);
        title_packet[0] = PEER_TITLE_ID;
        memcpy(title_packet + 1, g->title, g->title_len);
        send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_CONFERENCE, group_num, title_packet,
                               SIZEOF_VLA(title_packet));
    }

    return sent;
}

static int handle_send_peers(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length,
                             void *userdata)
{
    if (length == 0) {
        return -1;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    const uint8_t *d = data;

    while ((unsigned int)(length - (d - data)) >= sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE * 2 + 1) {
        uint16_t peer_num;
        memcpy(&peer_num, d, sizeof(peer_num));
        peer_num = net_ntohs(peer_num);
        d += sizeof(uint16_t);

        if (g->status == GROUPCHAT_STATUS_VALID
                && public_key_cmp(d, nc_get_self_public_key(g_c->m->net_crypto)) == 0) {
            g->peer_number = peer_num;
            g->status = GROUPCHAT_STATUS_CONNECTED;

            if (g_c->connected_callback) {
                g_c->connected_callback(g_c->m, groupnumber, userdata);
            }

            g->need_send_name = true;
        }

        const int peer_index = addpeer(g_c, groupnumber, d, d + CRYPTO_PUBLIC_KEY_SIZE, peer_num, userdata, false, true);

        if (peer_index == -1) {
            return -1;
        }

        d += CRYPTO_PUBLIC_KEY_SIZE * 2;
        const uint8_t name_length = *d;
        d += 1;

        if (name_length > (length - (d - data)) || name_length > MAX_NAME_LENGTH) {
            return -1;
        }

        if (!g->group[peer_index].nick_updated) {
            setnick(g_c, groupnumber, peer_index, d, name_length, userdata, true);
        }

        d += name_length;
    }

    return 0;
}

static void handle_direct_packet(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length,
                                 int connection_index, void *userdata)
{
    if (length == 0) {
        return;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return;
    }

    switch (data[0]) {
        case PEER_INTRODUCED_ID: {
            remove_connection_reason(g_c, g, connection_index, GROUPCHAT_CONNECTION_REASON_INTRODUCING);
        }

        break;

        case PEER_QUERY_ID: {
            if (g->connections[connection_index].type != GROUPCHAT_CONNECTION_ONLINE) {
                return;
            }

            send_peers(g_c, g, g->connections[connection_index].number, g->connections[connection_index].group_number);
        }

        break;

        case PEER_RESPONSE_ID: {
            handle_send_peers(g_c, groupnumber, data + 1, length - 1, userdata);
        }

        break;

        case PEER_TITLE_ID: {
            if (!g->title_fresh) {
                settitle(g_c, groupnumber, -1, data + 1, length - 1, userdata);
            }
        }

        break;
    }
}

/* Send message to all connections except receiver (if receiver isn't -1)
 * NOTE: this function appends the group chat number to the data passed to it.
 *
 * return number of messages sent.
 */
static unsigned int send_message_all_connections(const Group_Chats *g_c, const Group_c *g, const uint8_t *data,
        uint16_t length, int receiver)
{
    uint16_t sent = 0;

    for (uint16_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type != GROUPCHAT_CONNECTION_ONLINE) {
            continue;
        }

        if ((int)i == receiver) {
            continue;
        }

        if (send_packet_group_peer(g_c->fr_c, g->connections[i].number, PACKET_ID_MESSAGE_CONFERENCE,
                                   g->connections[i].group_number, data, length)) {
            ++sent;
        }
    }

    return sent;
}

/* Send lossy message to all connections except receiver (if receiver isn't -1)
 * NOTE: this function appends the group chat number to the data passed to it.
 *
 * return number of messages sent.
 */
static unsigned int send_lossy_all_connections(const Group_Chats *g_c, const Group_c *g, const uint8_t *data,
        uint16_t length,
        int receiver)
{
    unsigned int sent = 0;
    unsigned int num_connected_closest = 0;
    unsigned int connected_closest[DESIRED_CLOSEST];

    for (unsigned int i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type != GROUPCHAT_CONNECTION_ONLINE) {
            continue;
        }

        if ((int)i == receiver) {
            continue;
        }

        if (g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_CLOSEST) {
            connected_closest[num_connected_closest] = i;
            ++num_connected_closest;
            continue;
        }

        if (send_lossy_group_peer(g_c->fr_c, g->connections[i].number, PACKET_ID_LOSSY_CONFERENCE,
                                  g->connections[i].group_number, data, length)) {
            ++sent;
        }
    }

    if (!num_connected_closest) {
        return sent;
    }

    unsigned int to_send[2] = {0, 0};
    uint64_t comp_val_old[2] = {(uint64_t) -1, (uint64_t) -1};

    for (unsigned int i = 0; i < num_connected_closest; ++i) {
        uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE] = {0};
        get_friendcon_public_keys(real_pk, nullptr, g_c->fr_c, g->connections[connected_closest[i]].number);
        const uint64_t comp_val = calculate_comp_value(g->real_pk, real_pk);

        for (uint8_t j = 0; j < 2; ++j) {
            if (j ? (comp_val > comp_val_old[j]) : (comp_val < comp_val_old[j])) {
                to_send[j] = connected_closest[i];
                comp_val_old[j] = comp_val;
            }
        }
    }

    for (uint8_t j = 0; j < 2; ++j) {
        if (j && to_send[1] == to_send[0]) {
            break;
        }

        if (send_lossy_group_peer(g_c->fr_c, g->connections[to_send[j]].number, PACKET_ID_LOSSY_CONFERENCE,
                                  g->connections[to_send[j]].group_number, data, length)) {
            ++sent;
        }
    }

    return sent;
}

/* Send data of len with message_id to groupnumber.
 *
 * return number of peers it was sent to on success.
 * return -1 if groupnumber is invalid.
 * return -2 if message is too long.
 * return -3 if we are not connected to the group.
 * return -4 if message failed to send.
 */
static int send_message_group(const Group_Chats *g_c, uint32_t groupnumber, uint8_t message_id, const uint8_t *data,
                              uint16_t len)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    if (len > MAX_GROUP_MESSAGE_DATA_LEN) {
        return -2;
    }

    if (g->status != GROUPCHAT_STATUS_CONNECTED || count_connected(g) == 0) {
        return -3;
    }

    VLA(uint8_t, packet, sizeof(uint16_t) + sizeof(uint32_t) + 1 + len);
    const uint16_t peer_num = net_htons(g->peer_number);
    memcpy(packet, &peer_num, sizeof(peer_num));

    ++g->message_number;

    if (!g->message_number) {
        ++g->message_number;
    }

    const uint32_t message_num = net_htonl(g->message_number);
    memcpy(packet + sizeof(uint16_t), &message_num, sizeof(message_num));

    packet[sizeof(uint16_t) + sizeof(uint32_t)] = message_id;

    if (len) {
        memcpy(packet + sizeof(uint16_t) + sizeof(uint32_t) + 1, data, len);
    }

    unsigned int ret = send_message_all_connections(g_c, g, packet, SIZEOF_VLA(packet), -1);

    if (ret == 0) {
        return -4;
    }

    return ret;
}

/* send a group message
 * return 0 on success
 * see: send_message_group() for error codes.
 */
int group_message_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *message, uint16_t length)
{
    const int ret = send_message_group(g_c, groupnumber, PACKET_ID_MESSAGE, message, length);

    if (ret > 0) {
        return 0;
    }

    return ret;
}

/* send a group action
 * return 0 on success
 * see: send_message_group() for error codes.
 */
int group_action_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *action, uint16_t length)
{
    const int ret = send_message_group(g_c, groupnumber, PACKET_ID_ACTION, action, length);

    if (ret > 0) {
        return 0;
    }

    return ret;
}

/* High level function to send custom lossy packets.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_group_lossy_packet(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length)
{
    // TODO(irungentoo): length check here?
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    VLA(uint8_t, packet, sizeof(uint16_t) * 2 + length);
    const uint16_t peer_number = net_htons(g->peer_number);
    memcpy(packet, &peer_number, sizeof(uint16_t));
    const uint16_t message_num = net_htons(g->lossy_message_number);
    memcpy(packet + sizeof(uint16_t), &message_num, sizeof(uint16_t));
    memcpy(packet + sizeof(uint16_t) * 2, data, length);

    if (send_lossy_all_connections(g_c, g, packet, SIZEOF_VLA(packet), -1) == 0) {
        return -1;
    }

    ++g->lossy_message_number;
    return 0;
}

static Message_Info *find_message_slot_or_reject(uint32_t message_number, uint8_t message_id, Group_Peer *peer)
{
    const bool ignore_older = (message_id == GROUP_MESSAGE_NAME_ID || message_id == GROUP_MESSAGE_TITLE_ID);

    Message_Info *i;

    for (i = peer->last_message_infos; i < peer->last_message_infos + peer->num_last_message_infos; ++i) {
        if (message_number - (i->message_number + 1) <= ((uint32_t)1 << 31)) {
            break;
        }

        if (message_number == i->message_number) {
            return nullptr;
        }

        if (ignore_older && message_id == i->message_id) {
            return nullptr;
        }
    }

    return i;
}

/* Stores message info in peer->last_message_infos.
 *
 * return true if message should be processed.
 * return false otherwise.
 */
static bool check_message_info(uint32_t message_number, uint8_t message_id, Group_Peer *peer)
{
    Message_Info *const i = find_message_slot_or_reject(message_number, message_id, peer);

    if (i == nullptr) {
        return false;
    }

    if (i == peer->last_message_infos + MAX_LAST_MESSAGE_INFOS) {
        return false;
    }

    if (peer->num_last_message_infos < MAX_LAST_MESSAGE_INFOS) {
        ++peer->num_last_message_infos;
    }

    memmove(i + 1, i, ((peer->last_message_infos + peer->num_last_message_infos - 1) - i) * sizeof(Message_Info));

    i->message_number = message_number;
    i->message_id = message_id;

    return true;
}

static void handle_message_packet_group(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length,
                                        int connection_index, void *userdata)
{
    if (length < sizeof(uint16_t) + sizeof(uint32_t) + 1) {
        return;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return;
    }

    uint16_t peer_number;
    memcpy(&peer_number, data, sizeof(uint16_t));
    peer_number = net_ntohs(peer_number);

    uint32_t message_number;
    memcpy(&message_number, data + sizeof(uint16_t), sizeof(message_number));
    message_number = net_ntohl(message_number);

    const uint8_t message_id = data[sizeof(uint16_t) + sizeof(message_number)];
    const uint8_t *msg_data = data + sizeof(uint16_t) + sizeof(message_number) + 1;
    const uint16_t msg_data_len = length - (sizeof(uint16_t) + sizeof(message_number) + 1);

    const bool ignore_frozen = message_id == GROUP_MESSAGE_FREEZE_PEER_ID;

    const int index = ignore_frozen ? get_peer_index(g, peer_number)
                      : note_peer_active(g_c, groupnumber, peer_number, userdata);

    if (index == -1) {
        if (ignore_frozen) {
            return;
        }

        if (g->connections[connection_index].type != GROUPCHAT_CONNECTION_ONLINE) {
            return;
        }

        /* If we don't know the peer this packet came from, then we query the
         * list of peers from the relaying peer.
         * (They wouldn't have relayed it if they didn't know the peer.) */
        send_peer_query(g_c, g->connections[connection_index].number, g->connections[connection_index].group_number);
        return;
    }

    if (g->num_introducer_connections > 0 && count_connected(g) > DESIRED_CLOSEST) {
        for (uint32_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
            if (g->connections[i].type == GROUPCHAT_CONNECTION_NONE
                    || !(g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_INTRODUCER)
                    || i == connection_index) {
                continue;
            }

            uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
            get_friendcon_public_keys(real_pk, nullptr, g_c->fr_c, g->connections[i].number);

            if (id_equal(g->group[index].real_pk, real_pk)) {
                /* Received message from peer relayed via another peer, so
                 * the introduction was successful */
                remove_connection_reason(g_c, g, i, GROUPCHAT_CONNECTION_REASON_INTRODUCER);
            }
        }
    }

    if (!check_message_info(message_number, message_id, &g->group[index])) {
        return;
    }

    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    get_friendcon_public_keys(real_pk, nullptr, g_c->fr_c, g->connections[connection_index].number);
    const bool direct_from_sender = id_equal(g->group[index].real_pk, real_pk);

    switch (message_id) {
        case GROUP_MESSAGE_PING_ID:
            break;

        case GROUP_MESSAGE_NEW_PEER_ID: {
            if (msg_data_len != GROUP_MESSAGE_NEW_PEER_LENGTH) {
                return;
            }

            uint16_t new_peer_number;
            memcpy(&new_peer_number, msg_data, sizeof(uint16_t));
            new_peer_number = net_ntohs(new_peer_number);
            addpeer(g_c, groupnumber, msg_data + sizeof(uint16_t), msg_data + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE,
                    new_peer_number, userdata, true, true);
        }
        break;

        case GROUP_MESSAGE_KILL_PEER_ID:
        case GROUP_MESSAGE_FREEZE_PEER_ID: {
            if (msg_data_len != GROUP_MESSAGE_KILL_PEER_LENGTH) {
                return;
            }

            uint16_t kill_peer_number;
            memcpy(&kill_peer_number, msg_data, sizeof(uint16_t));
            kill_peer_number = net_ntohs(kill_peer_number);

            if (peer_number == kill_peer_number) {
                if (message_id == GROUP_MESSAGE_KILL_PEER_ID) {
                    delpeer(g_c, groupnumber, index, userdata);
                } else {
                    freeze_peer(g_c, groupnumber, index, userdata);
                }
            } else {
                return;
                // TODO(irungentoo):
            }
        }
        break;

        case GROUP_MESSAGE_NAME_ID: {
            if (!setnick(g_c, groupnumber, index, msg_data, msg_data_len, userdata, true)) {
                return;
            }
        }
        break;

        case GROUP_MESSAGE_TITLE_ID: {
            if (!settitle(g_c, groupnumber, index, msg_data, msg_data_len, userdata)) {
                return;
            }
        }
        break;

        case PACKET_ID_MESSAGE: {
            if (msg_data_len == 0) {
                return;
            }

            VLA(uint8_t, newmsg, msg_data_len + 1);
            memcpy(newmsg, msg_data, msg_data_len);
            newmsg[msg_data_len] = 0;

            // TODO(irungentoo):
            if (g_c->message_callback) {
                g_c->message_callback(g_c->m, groupnumber, index, 0, newmsg, msg_data_len, userdata);
            }

            break;
        }

        case PACKET_ID_ACTION: {
            if (msg_data_len == 0) {
                return;
            }

            VLA(uint8_t, newmsg, msg_data_len + 1);
            memcpy(newmsg, msg_data, msg_data_len);
            newmsg[msg_data_len] = 0;

            // TODO(irungentoo):
            if (g_c->message_callback) {
                g_c->message_callback(g_c->m, groupnumber, index, 1, newmsg, msg_data_len, userdata);
            }

            break;
        }

        default:
            return;
    }

    /* If the packet was received from the peer who sent the message, relay it
     * back. When the sender only has one group connection (e.g. because there
     * are only two peers in the group), this is the only way for them to
     * receive their own message. */
    send_message_all_connections(g_c, g, data, length, direct_from_sender ? -1 : connection_index);
}

static int g_handle_packet(void *object, int friendcon_id, const uint8_t *data, uint16_t length, void *userdata)
{
    Group_Chats *g_c = (Group_Chats *)object;

    if (length < 1 + sizeof(uint16_t) + 1) {
        return -1;
    }

    if (data[0] == PACKET_ID_ONLINE_PACKET) {
        return handle_packet_online(g_c, friendcon_id, data + 1, length - 1);
    }

    if (data[0] == PACKET_ID_REJOIN_CONFERENCE) {
        return handle_packet_rejoin(g_c, friendcon_id, data + 1, length - 1, userdata);
    }

    uint16_t groupnumber;
    memcpy(&groupnumber, data + 1, sizeof(uint16_t));
    groupnumber = net_ntohs(groupnumber);
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    const int index = friend_in_connections(g, friendcon_id);

    if (index == -1) {
        return -1;
    }

    if (data[0] == PACKET_ID_DIRECT_CONFERENCE) {
        handle_direct_packet(g_c, groupnumber, data + 1 + sizeof(uint16_t),
                             length - (1 + sizeof(uint16_t)), index, userdata);
        return 0;
    }

    if (data[0] == PACKET_ID_MESSAGE_CONFERENCE) {
        handle_message_packet_group(g_c, groupnumber, data + 1 + sizeof(uint16_t),
                                    length - (1 + sizeof(uint16_t)), index, userdata);
        return 0;
    }

    return -1;
}

/* Did we already receive the lossy packet or not.
 *
 * return -1 on failure.
 * return 0 if packet was not received.
 * return 1 if packet was received.
 *
 * TODO(irungentoo): test this
 */
static int lossy_packet_not_received(const Group_c *g, int peer_index, uint16_t message_number)
{
    if (peer_index == -1) {
        return -1;
    }

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

    if ((uint16_t)(message_number - g->group[peer_index].bottom_lossy_number) > (1 << 15)) {
        return -1;
    }

    const uint16_t top_distance = message_number - g->group[peer_index].top_lossy_number;

    if (top_distance >= MAX_LOSSY_COUNT) {
        crypto_memzero(g->group[peer_index].recv_lossy, sizeof(g->group[peer_index].recv_lossy));
    } else {  // top_distance < MAX_LOSSY_COUNT
        for (unsigned int i = g->group[peer_index].bottom_lossy_number;
                i != g->group[peer_index].bottom_lossy_number + top_distance;
                ++i) {
            g->group[peer_index].recv_lossy[i % MAX_LOSSY_COUNT] = 0;
        }
    }

    g->group[peer_index].top_lossy_number = message_number;
    g->group[peer_index].bottom_lossy_number = (message_number - MAX_LOSSY_COUNT) + 1;
    g->group[peer_index].recv_lossy[message_number % MAX_LOSSY_COUNT] = 1;

    return 0;

}

/* Does this group type make use of lossy packets? */
static bool type_uses_lossy(uint8_t type)
{
    return (type == GROUPCHAT_TYPE_AV);
}

static int handle_lossy(void *object, int friendcon_id, const uint8_t *data, uint16_t length, void *userdata)
{
    Group_Chats *g_c = (Group_Chats *)object;

    if (data[0] != PACKET_ID_LOSSY_CONFERENCE) {
        return -1;
    }

    if (length < 1 + sizeof(uint16_t) * 3 + 1) {
        return -1;
    }

    uint16_t groupnumber;
    uint16_t peer_number;
    uint16_t message_number;
    memcpy(&groupnumber, data + 1, sizeof(uint16_t));
    memcpy(&peer_number, data + 1 + sizeof(uint16_t), sizeof(uint16_t));
    memcpy(&message_number, data + 1 + sizeof(uint16_t) * 2, sizeof(uint16_t));
    groupnumber = net_ntohs(groupnumber);
    peer_number = net_ntohs(peer_number);
    message_number = net_ntohs(message_number);

    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    if (!type_uses_lossy(g->type)) {
        return -1;
    }

    const int index = friend_in_connections(g, friendcon_id);

    if (index == -1) {
        return -1;
    }

    if (peer_number == g->peer_number) {
        return -1;
    }

    const int peer_index = get_peer_index(g, peer_number);

    if (peer_index == -1) {
        return -1;
    }

    if (lossy_packet_not_received(g, peer_index, message_number) != 0) {
        return -1;
    }

    const uint8_t *lossy_data = data + 1 + sizeof(uint16_t) * 3;
    uint16_t lossy_length = length - (1 + sizeof(uint16_t) * 3);
    const uint8_t message_id = lossy_data[0];
    ++lossy_data;
    --lossy_length;

    send_lossy_all_connections(g_c, g, data + 1 + sizeof(uint16_t), length - (1 + sizeof(uint16_t)), index);

    if (!g_c->lossy_packethandlers[message_id].function) {
        return -1;
    }

    if (g_c->lossy_packethandlers[message_id].function(g->object, groupnumber, peer_index, g->group[peer_index].object,
            lossy_data, lossy_length) == -1) {
        return -1;
    }

    return 0;
}

/* Set the object that is tied to the group chat.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_set_object(const Group_Chats *g_c, uint32_t groupnumber, void *object)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    g->object = object;
    return 0;
}

/* Set the object that is tied to the group peer.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_peer_set_object(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, void *object)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return -1;
    }

    if (peernumber >= g->numpeers) {
        return -1;
    }

    g->group[peernumber].object = object;
    return 0;
}

/* Return the object tied to the group chat previously set by group_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_get_object(const Group_Chats *g_c, uint32_t groupnumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return nullptr;
    }

    return g->object;
}

/* Return the object tied to the group chat peer previously set by group_peer_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_peer_get_object(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return nullptr;
    }

    if (peernumber >= g->numpeers) {
        return nullptr;
    }

    return g->group[peernumber].object;
}

/* Interval in seconds to send ping messages */
#define GROUP_PING_INTERVAL 20

static bool ping_groupchat(Group_Chats *g_c, uint32_t groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return false;
    }

    if (mono_time_is_timeout(g_c->mono_time, g->last_sent_ping, GROUP_PING_INTERVAL)) {
        if (group_ping_send(g_c, groupnumber)) {
            g->last_sent_ping = mono_time_get(g_c->mono_time);
        }
    }

    return true;
}

/* Seconds of inactivity after which to freeze a peer */
#define FREEZE_TIMEOUT (GROUP_PING_INTERVAL * 3)

static bool groupchat_freeze_timedout(Group_Chats *g_c, uint32_t groupnumber, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (!g) {
        return false;
    }

    for (uint32_t i = 0; i < g->numpeers; ++i) {
        if (g->group[i].peer_number == g->peer_number) {
            continue;
        }

        if (mono_time_is_timeout(g_c->mono_time, g->group[i].last_active, FREEZE_TIMEOUT)) {
            freeze_peer(g_c, groupnumber, i, userdata);
        }
    }

    if (g->numpeers <= 1) {
        g->title_fresh = false;
    }

    return true;
}

/* Push non-empty slots to start. */
static void squash_connections(Group_c *g)
{
    uint16_t i = 0;

    for (uint16_t j = 0; j < MAX_GROUP_CONNECTIONS; ++j) {
        if (g->connections[j].type != GROUPCHAT_CONNECTION_NONE) {
            g->connections[i] = g->connections[j];
            ++i;
        }
    }

    for (; i < MAX_GROUP_CONNECTIONS; ++i) {
        g->connections[i].type = GROUPCHAT_CONNECTION_NONE;
    }
}

#define MIN_EMPTY_CONNECTIONS (1 + MAX_GROUP_CONNECTIONS / 10)

/* Remove old connections as necessary to ensure we have space for new
 * connections. This invalidates connections array indices (which is
 * why we do this periodically rather than on adding a connection).
 */
static void clean_connections(Group_Chats *g_c, Group_c *g)
{
    uint16_t to_clear = MIN_EMPTY_CONNECTIONS;

    for (uint16_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_NONE) {
            --to_clear;

            if (to_clear == 0) {
                break;
            }
        }
    }

    for (; to_clear > 0; --to_clear) {
        // Remove a connection. Prefer non-closest connections, and given
        // that prefer non-online connections, and given that prefer earlier
        // slots.
        uint16_t i = 0;

        while (i < MAX_GROUP_CONNECTIONS
                && (g->connections[i].type != GROUPCHAT_CONNECTION_CONNECTING
                    || (g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_CLOSEST))) {
            ++i;
        }

        if (i == MAX_GROUP_CONNECTIONS) {
            i = 0;

            while (i < MAX_GROUP_CONNECTIONS - to_clear
                    && (g->connections[i].type != GROUPCHAT_CONNECTION_ONLINE
                        || (g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_CLOSEST))) {
                ++i;
            }
        }

        if (g->connections[i].type != GROUPCHAT_CONNECTION_NONE) {
            remove_connection(g_c, g, i);
        }
    }

    squash_connections(g);
}

/* Send current name (set in messenger) to all online groups.
 */
void send_name_all_groups(Group_Chats *g_c)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        Group_c *g = get_group_c(g_c, i);

        if (!g) {
            continue;
        }

        if (g->status == GROUPCHAT_STATUS_CONNECTED) {
            group_name_send(g_c, i, g_c->m->name, g_c->m->name_length);
            g->need_send_name = false;
        }
    }
}

#define SAVED_PEER_SIZE_CONSTANT (2 * CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint16_t) + sizeof(uint64_t) + 1)

static uint32_t saved_peer_size(const Group_Peer *peer)
{
    return SAVED_PEER_SIZE_CONSTANT + peer->nick_len;
}

static uint8_t *save_peer(const Group_Peer *peer, uint8_t *data)
{
    memcpy(data, peer->real_pk, CRYPTO_PUBLIC_KEY_SIZE);
    data += CRYPTO_PUBLIC_KEY_SIZE;

    memcpy(data, peer->temp_pk, CRYPTO_PUBLIC_KEY_SIZE);
    data += CRYPTO_PUBLIC_KEY_SIZE;

    host_to_lendian_bytes16(data, peer->peer_number);
    data += sizeof(uint16_t);

    host_to_lendian_bytes64(data, peer->last_active);
    data += sizeof(uint64_t);

    *data = peer->nick_len;
    ++data;

    memcpy(data, peer->nick, peer->nick_len);
    data += peer->nick_len;

    return data;
}

#define SAVED_CONF_SIZE_CONSTANT (1 + GROUP_ID_LENGTH + sizeof(uint32_t) \
      + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + 1)

static uint32_t saved_conf_size(const Group_c *g)
{
    uint32_t len = SAVED_CONF_SIZE_CONSTANT + g->title_len;

    for (uint32_t j = 0; j < g->numpeers + g->numfrozen; ++j) {
        const Group_Peer *peer = (j < g->numpeers) ? &g->group[j] : &g->frozen[j - g->numpeers];

        if (id_equal(peer->real_pk, g->real_pk)) {
            continue;
        }

        len += saved_peer_size(peer);
    }

    return len;
}

/* Save a future message number. The save will remain valid until we have sent
 * this many more messages. */
#define SAVE_OFFSET_MESSAGE_NUMBER (1 << 16)
#define SAVE_OFFSET_LOSSY_MESSAGE_NUMBER (1 << 13)

static uint8_t *save_conf(const Group_c *g, uint8_t *data)
{
    *data = g->type;
    ++data;

    memcpy(data, g->id, GROUP_ID_LENGTH);
    data += GROUP_ID_LENGTH;

    host_to_lendian_bytes32(data, g->message_number + SAVE_OFFSET_MESSAGE_NUMBER);
    data += sizeof(uint32_t);

    host_to_lendian_bytes16(data, g->lossy_message_number + SAVE_OFFSET_LOSSY_MESSAGE_NUMBER);
    data += sizeof(uint16_t);

    host_to_lendian_bytes16(data, g->peer_number);
    data += sizeof(uint16_t);

    uint8_t *const numsaved_location = data;
    data += sizeof(uint32_t);

    *data = g->title_len;
    ++data;

    memcpy(data, g->title, g->title_len);
    data += g->title_len;

    uint32_t numsaved = 0;

    for (uint32_t j = 0; j < g->numpeers + g->numfrozen; ++j) {
        const Group_Peer *peer = (j < g->numpeers) ? &g->group[j] : &g->frozen[j - g->numpeers];

        if (id_equal(peer->real_pk, g->real_pk)) {
            continue;
        }

        data = save_peer(peer, data);
        ++numsaved;
    }

    host_to_lendian_bytes32(numsaved_location, numsaved);

    return data;
}

static uint32_t conferences_section_size(const Group_Chats *g_c)
{
    uint32_t len = 0;

    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        const Group_c *g = get_group_c(g_c, i);

        if (!g || g->status != GROUPCHAT_STATUS_CONNECTED) {
            continue;
        }

        len += saved_conf_size(g);
    }

    return len;
}

uint32_t conferences_size(const Group_Chats *g_c)
{
    return 2 * sizeof(uint32_t) + conferences_section_size(g_c);
}

uint8_t *conferences_save(const Group_Chats *g_c, uint8_t *data)
{
    const uint32_t len = conferences_section_size(g_c);
    data = state_write_section_header(data, STATE_COOKIE_TYPE, len, STATE_TYPE_CONFERENCES);

    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        const Group_c *g = get_group_c(g_c, i);

        if (!g || g->status != GROUPCHAT_STATUS_CONNECTED) {
            continue;
        }

        data = save_conf(g, data);
    }

    return data;
}

static State_Load_Status load_conferences(Group_Chats *g_c, const uint8_t *data, uint32_t length)
{
    const uint8_t *init_data = data;

    while (length >= (uint32_t)(data - init_data) + SAVED_CONF_SIZE_CONSTANT) {
        const int groupnumber = create_group_chat(g_c);

        if (groupnumber == -1) {
            return STATE_LOAD_STATUS_ERROR;
        }

        Group_c *g = &g_c->chats[groupnumber];

        g->type = *data;
        ++data;

        memcpy(g->id, data, GROUP_ID_LENGTH);
        data += GROUP_ID_LENGTH;

        lendian_bytes_to_host32(&g->message_number, data);
        data += sizeof(uint32_t);

        lendian_bytes_to_host16(&g->lossy_message_number, data);
        data += sizeof(uint16_t);

        lendian_bytes_to_host16(&g->peer_number, data);
        data += sizeof(uint16_t);

        lendian_bytes_to_host32(&g->numfrozen, data);
        data += sizeof(uint32_t);

        if (g->numfrozen > 0) {
            g->frozen = (Group_Peer *)malloc(sizeof(Group_Peer) * g->numfrozen);

            if (g->frozen == nullptr) {
                return STATE_LOAD_STATUS_ERROR;
            }
        }

        g->title_len = *data;

        if (g->title_len > MAX_NAME_LENGTH) {
            return STATE_LOAD_STATUS_ERROR;
        }

        ++data;

        if (length < (uint32_t)(data - init_data) + g->title_len) {
            return STATE_LOAD_STATUS_ERROR;
        }

        memcpy(g->title, data, g->title_len);
        data += g->title_len;

        for (uint32_t j = 0; j < g->numfrozen; ++j) {
            if (length < (uint32_t)(data - init_data) + SAVED_PEER_SIZE_CONSTANT) {
                return STATE_LOAD_STATUS_ERROR;
            }

            Group_Peer *peer = &g->frozen[j];
            memset(peer, 0, sizeof(Group_Peer));

            id_copy(peer->real_pk, data);
            data += CRYPTO_PUBLIC_KEY_SIZE;
            id_copy(peer->temp_pk, data);
            data += CRYPTO_PUBLIC_KEY_SIZE;

            lendian_bytes_to_host16(&peer->peer_number, data);
            data += sizeof(uint16_t);

            lendian_bytes_to_host64(&peer->last_active, data);
            data += sizeof(uint64_t);

            peer->nick_len = *data;

            if (peer->nick_len > MAX_NAME_LENGTH) {
                return STATE_LOAD_STATUS_ERROR;
            }

            ++data;

            if (length < (uint32_t)(data - init_data) + peer->nick_len) {
                return STATE_LOAD_STATUS_ERROR;
            }

            memcpy(peer->nick, data, peer->nick_len);
            data += peer->nick_len;

            // NOTE: this relies on friends being loaded before conferences.
            peer->is_friend = (getfriend_id(g_c->m, peer->real_pk) != -1);
        }

        if (g->numfrozen > g->maxfrozen) {
            g->maxfrozen = g->numfrozen;
        }

        g->status = GROUPCHAT_STATUS_CONNECTED;
        memcpy(g->real_pk, nc_get_self_public_key(g_c->m->net_crypto), CRYPTO_PUBLIC_KEY_SIZE);
        const int peer_index = addpeer(g_c, groupnumber, g->real_pk, dht_get_self_public_key(g_c->m->dht), g->peer_number,
                                       nullptr, true, false);

        if (peer_index == -1) {
            return STATE_LOAD_STATUS_ERROR;
        }

        setnick(g_c, groupnumber, peer_index, g_c->m->name, g_c->m->name_length, nullptr, false);
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

bool conferences_load_state_section(Group_Chats *g_c, const uint8_t *data, uint32_t length, uint16_t type,
                                    State_Load_Status *status)
{
    if (type != STATE_TYPE_CONFERENCES) {
        return false;
    }

    *status = load_conferences(g_c, data, length);
    return true;
}


/* Create new groupchat instance. */
Group_Chats *new_groupchats(Mono_Time *mono_time, Messenger *m)
{
    if (!m) {
        return nullptr;
    }

    Group_Chats *temp = (Group_Chats *)calloc(1, sizeof(Group_Chats));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->mono_time = mono_time;
    temp->m = m;
    temp->fr_c = m->fr_c;
    m->conferences_object = temp;
    m_callback_conference_invite(m, &handle_friend_invite_packet);

    set_global_status_callback(m->fr_c, &g_handle_any_status, temp);

    return temp;
}

/* main groupchats loop. */
void do_groupchats(Group_Chats *g_c, void *userdata)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        Group_c *g = get_group_c(g_c, i);

        if (!g) {
            continue;
        }

        if (g->status == GROUPCHAT_STATUS_CONNECTED) {
            connect_to_closest(g_c, i, userdata);
            ping_groupchat(g_c, i);
            groupchat_freeze_timedout(g_c, i, userdata);
            clean_connections(g_c, g);

            if (g->need_send_name) {
                group_name_send(g_c, i, g_c->m->name, g_c->m->name_length);
                g->need_send_name = false;
            }
        }
    }

    // TODO(irungentoo):
}

/* Free everything related with group chats. */
void kill_groupchats(Group_Chats *g_c)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        del_groupchat(g_c, i, false);
    }

    m_callback_conference_invite(g_c->m, nullptr);
    set_global_status_callback(g_c->m->fr_c, nullptr, nullptr);
    g_c->m->conferences_object = nullptr;
    free(g_c);
}

/* Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist.
 */
uint32_t count_chatlist(const Group_Chats *g_c)
{
    uint32_t ret = 0;

    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        if (g_c->chats[i].status != GROUPCHAT_STATUS_NONE) {
            ++ret;
        }
    }

    return ret;
}

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_chatlist(const Group_Chats *g_c, uint32_t *out_list, uint32_t list_size)
{
    if (!out_list) {
        return 0;
    }

    if (g_c->num_chats == 0) {
        return 0;
    }

    uint32_t ret = 0;

    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        if (ret >= list_size) {
            break;  /* Abandon ship */
        }

        if (g_c->chats[i].status > GROUPCHAT_STATUS_NONE) {
            out_list[ret] = i;
            ++ret;
        }
    }

    return ret;
}
