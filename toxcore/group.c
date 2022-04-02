/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Slightly better groupchats implementation.
 */
#include "group.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "mono_time.h"
#include "state.h"
#include "util.h"

enum {
    /** Connection is to one of the closest DESIRED_CLOSEST peers */
    GROUPCHAT_CONNECTION_REASON_CLOSEST     = 1 << 0,

    /** Connection is to a peer we are introducing to the conference */
    GROUPCHAT_CONNECTION_REASON_INTRODUCING = 1 << 1,

    /** Connection is to a peer who is introducing us to the conference */
    GROUPCHAT_CONNECTION_REASON_INTRODUCER  = 1 << 2,
};

typedef enum Groupchat_Connection_Type {
    GROUPCHAT_CONNECTION_NONE,
    GROUPCHAT_CONNECTION_CONNECTING,
    GROUPCHAT_CONNECTION_ONLINE,
} Groupchat_Connection_Type;

typedef enum Groupchat_Status {
    GROUPCHAT_STATUS_NONE,
    GROUPCHAT_STATUS_VALID,
    GROUPCHAT_STATUS_CONNECTED,
} Groupchat_Status;

#define GROUP_ID_LENGTH CRYPTO_SYMMETRIC_KEY_SIZE

#define DESIRED_CLOSEST 4
#define MAX_GROUP_CONNECTIONS 16
#define MAX_LAST_MESSAGE_INFOS 8
#define MAX_LOSSY_COUNT 256

/** Maximum number of frozen peers to store; `group_set_max_frozen()` overrides. */
#define MAX_FROZEN_DEFAULT 128

typedef struct Message_Info {
    uint32_t message_number;
    uint8_t  message_id;
} Message_Info;

typedef struct Group_Peer {
    uint8_t     real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t     temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
    bool        temp_pk_updated;
    bool        is_friend;

    uint64_t    last_active;

    Message_Info
    last_message_infos[MAX_LAST_MESSAGE_INFOS]; /* received messages, strictly decreasing in message_number */
    uint8_t     num_last_message_infos;

    uint8_t     nick[MAX_NAME_LENGTH];
    uint8_t     nick_len;
    bool        nick_updated;

    uint16_t peer_number;

    uint8_t  recv_lossy[MAX_LOSSY_COUNT];
    uint16_t bottom_lossy_number;
    uint16_t top_lossy_number;

    void *object;
} Group_Peer;

typedef struct Groupchat_Connection {
    uint8_t type; /* `GROUPCHAT_CONNECTION_*` */
    uint8_t reasons; /* bit field with flags `GROUPCHAT_CONNECTION_REASON_*` */
    uint32_t number;
    uint16_t group_number;
} Groupchat_Connection;

typedef struct Groupchat_Closest {
    /**
     * Whether this peer is active in the closest_peers array.
     */
    bool active;
    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
} Groupchat_Closest;

typedef struct Group_c {
    uint8_t status;

    bool need_send_name;
    bool title_fresh;

    Group_Peer *group;
    uint32_t numpeers;

    Group_Peer *frozen;
    uint32_t numfrozen;

    uint32_t maxfrozen;

    Groupchat_Connection connections[MAX_GROUP_CONNECTIONS];

    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    Groupchat_Closest closest_peers[DESIRED_CLOSEST];
    uint8_t changed;

    uint8_t type;
    uint8_t id[GROUP_ID_LENGTH];

    uint8_t title[MAX_NAME_LENGTH];
    uint8_t title_len;

    uint32_t message_number;
    uint16_t lossy_message_number;
    uint16_t peer_number;

    uint64_t last_sent_ping;

    uint32_t num_introducer_connections;

    void *object;

    peer_on_join_cb *peer_on_join;
    peer_on_leave_cb *peer_on_leave;
    group_on_delete_cb *group_on_delete;
} Group_c;

struct Group_Chats {
    const Mono_Time *mono_time;

    Messenger *m;
    Friend_Connections *fr_c;

    Group_c *chats;
    uint16_t num_chats;

    g_conference_invite_cb *invite_callback;
    g_conference_connected_cb *connected_callback;
    g_conference_message_cb *message_callback;
    peer_name_cb *peer_name_callback;
    peer_list_changed_cb *peer_list_changed_callback;
    title_cb *title_callback;

    lossy_packet_cb *lossy_packethandlers[256];
};

static const Group_c empty_group_c = {0};
static const Group_Peer empty_group_peer = {{0}};

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

static_assert(GROUP_ID_LENGTH == CRYPTO_PUBLIC_KEY_SIZE,
              "GROUP_ID_LENGTH should be equal to CRYPTO_PUBLIC_KEY_SIZE");

const Mono_Time *g_mono_time(const Group_Chats *g_c)
{
    return g_c->mono_time;
}

non_null()
static bool group_id_eq(const uint8_t *a, const uint8_t *b)
{
    return pk_equal(a, b);
}

non_null()
static bool g_title_eq(Group_c *g, const uint8_t *title, uint8_t title_len)
{
    return memeq(g->title, g->title_len, title, title_len);
}

non_null()
static bool g_peer_nick_eq(Group_Peer *peer, const uint8_t *nick, uint8_t nick_len)
{
    return memeq(peer->nick, peer->nick_len, nick, nick_len);
}

/**
 * @retval false if the groupnumber is not valid.
 * @retval true if the groupnumber is valid.
 */
non_null()
static bool is_groupnumber_valid(const Group_Chats *g_c, uint32_t groupnumber)
{
    return groupnumber < g_c->num_chats
           && g_c->chats != nullptr
           && g_c->chats[groupnumber].status != GROUPCHAT_STATUS_NONE;
}


/** @brief Set the size of the groupchat list to num.
 *
 * @retval false if realloc fails.
 * @retval true if it succeeds.
 */
non_null()
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

non_null()
static void setup_conference(Group_c *g)
{
    *g = empty_group_c;
    g->maxfrozen = MAX_FROZEN_DEFAULT;
}

/** @brief Create a new empty groupchat connection.
 *
 * @retval -1 on failure.
 * @return groupnumber on success.
 */
non_null()
static int32_t create_group_chat(Group_Chats *g_c)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        if (g_c->chats[i].status == GROUPCHAT_STATUS_NONE) {
            return i;
        }
    }

    if (realloc_conferences(g_c, g_c->num_chats + 1)) {
        const uint16_t id = g_c->num_chats;
        ++g_c->num_chats;
        setup_conference(&g_c->chats[id]);
        return id;
    }

    return -1;
}

non_null()
static void wipe_group_c(Group_c *g)
{
    free(g->frozen);
    free(g->group);
    crypto_memzero(g, sizeof(Group_c));
}

/** @brief Wipe a groupchat.
 *
 * @retval true on success.
 */
non_null()
static bool wipe_group_chat(Group_Chats *g_c, uint32_t groupnumber)
{
    if (groupnumber >= g_c->num_chats || g_c->chats == nullptr) {
        return false;
    }

    wipe_group_c(&g_c->chats[groupnumber]);

    uint16_t i;

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

non_null()
static Group_c *get_group_c(const Group_Chats *g_c, uint32_t groupnumber)
{
    if (!is_groupnumber_valid(g_c, groupnumber)) {
        return nullptr;
    }

    return &g_c->chats[groupnumber];
}

/**
 * check if peer with real_pk is in peer array.
 *
 * @return peer index if peer is in group.
 * @retval -1 if peer is not in group.
 *
 * TODO(irungentoo): make this more efficient.
 */
non_null()
static int peer_in_group(const Group_c *g, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < g->numpeers; ++i) {
        if (pk_equal(g->group[i].real_pk, real_pk)) {
            return i;
        }
    }

    return -1;
}

non_null()
static int frozen_in_group(const Group_c *g, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < g->numfrozen; ++i) {
        if (pk_equal(g->frozen[i].real_pk, real_pk)) {
            return i;
        }
    }

    return -1;
}

/**
 * check if group with the given type and id is in group array.
 *
 * @return group number if peer is in list.
 * @retval -1 if group is not in list.
 *
 * TODO(irungentoo): make this more efficient and maybe use constant time comparisons?
 */
non_null()
static int32_t get_group_num(const Group_Chats *g_c, const uint8_t type, const uint8_t *id)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        if (g_c->chats[i].type == type && group_id_eq(g_c->chats[i].id, id)) {
            return i;
        }
    }

    return -1;
}

int32_t conference_by_id(const Group_Chats *g_c, const uint8_t *id)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        if (group_id_eq(g_c->chats[i].id, id)) {
            return i;
        }
    }

    return -1;
}

/**
 * check if peer with peer_number is in peer array.
 *
 * @return peer index if peer is in chat.
 * @retval -1 if peer is not in chat.
 *
 * TODO(irungentoo): make this more efficient.
 */
non_null()
static int get_peer_index(const Group_c *g, uint16_t peer_number)
{
    for (uint32_t i = 0; i < g->numpeers; ++i) {
        if (g->group[i].peer_number == peer_number) {
            return i;
        }
    }

    return -1;
}


non_null()
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

non_null()
static bool add_to_closest(Group_c *g, const uint8_t *real_pk, const uint8_t *temp_pk)
{
    if (pk_equal(g->real_pk, real_pk)) {
        return false;
    }

    unsigned int index = DESIRED_CLOSEST;

    for (unsigned int i = 0; i < DESIRED_CLOSEST; ++i) {
        if (g->closest_peers[i].active && pk_equal(real_pk, g->closest_peers[i].real_pk)) {
            return true;
        }
    }

    for (unsigned int i = 0; i < DESIRED_CLOSEST; ++i) {
        if (!g->closest_peers[i].active) {
            index = i;
            break;
        }
    }

    if (index == DESIRED_CLOSEST) {
        uint64_t comp_val = calculate_comp_value(g->real_pk, real_pk);
        uint64_t comp_d = 0;

        for (unsigned int i = 0; i < (DESIRED_CLOSEST / 2); ++i) {
            const uint64_t comp = calculate_comp_value(g->real_pk, g->closest_peers[i].real_pk);

            if (comp > comp_val && comp > comp_d) {
                index = i;
                comp_d = comp;
            }
        }

        comp_val = calculate_comp_value(real_pk, g->real_pk);

        for (unsigned int i = DESIRED_CLOSEST / 2; i < DESIRED_CLOSEST; ++i) {
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
    bool old = false;

    if (g->closest_peers[index].active) {
        memcpy(old_real_pk, g->closest_peers[index].real_pk, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(old_temp_pk, g->closest_peers[index].temp_pk, CRYPTO_PUBLIC_KEY_SIZE);
        old = true;
    }

    g->closest_peers[index].active = true;
    memcpy(g->closest_peers[index].real_pk, real_pk, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(g->closest_peers[index].temp_pk, temp_pk, CRYPTO_PUBLIC_KEY_SIZE);

    if (old) {
        add_to_closest(g, old_real_pk, old_temp_pk);
    }

    if (g->changed == GROUPCHAT_CLOSEST_CHANGE_NONE) {
        g->changed = GROUPCHAT_CLOSEST_CHANGE_ADDED;
    }

    return true;
}

non_null()
static bool pk_in_closest_peers(const Group_c *g, const uint8_t *real_pk)
{
    for (unsigned int i = 0; i < DESIRED_CLOSEST; ++i) {
        if (!g->closest_peers[i].active) {
            continue;
        }

        if (pk_equal(g->closest_peers[i].real_pk, real_pk)) {
            return true;
        }
    }

    return false;
}

non_null()
static void remove_connection_reason(Group_Chats *g_c, Group_c *g, uint16_t i, uint8_t reason);

non_null()
static void purge_closest(Group_Chats *g_c, uint32_t groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_NONE) {
            continue;
        }

        if ((g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_CLOSEST) == 0) {
            continue;
        }

        uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
        get_friendcon_public_keys(real_pk, nullptr, g_c->fr_c, g->connections[i].number);

        if (!pk_in_closest_peers(g, real_pk)) {
            remove_connection_reason(g_c, g, i, GROUPCHAT_CONNECTION_REASON_CLOSEST);
        }
    }
}

non_null()
static bool send_packet_online(const Friend_Connections *fr_c, int friendcon_id, uint16_t group_num,
                               uint8_t type, const uint8_t *id);

non_null()
static int add_conn_to_groupchat(Group_Chats *g_c, int friendcon_id, Group_c *g, uint8_t reason,
                                 bool lock);

non_null(1) nullable(3)
static void add_closest_connections(Group_Chats *g_c, uint32_t groupnumber, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < DESIRED_CLOSEST; ++i) {
        if (!g->closest_peers[i].active) {
            continue;
        }

        int friendcon_id = getfriend_conn_id_pk(g_c->fr_c, g->closest_peers[i].real_pk);

        bool fresh = false;

        if (friendcon_id == -1) {
            friendcon_id = new_friend_connection(g_c->fr_c, g->closest_peers[i].real_pk);
            fresh = true;

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

non_null(1) nullable(3)
static bool connect_to_closest(Group_Chats *g_c, uint32_t groupnumber, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return false;
    }

    if (g->changed == GROUPCHAT_CLOSEST_CHANGE_NONE) {
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

non_null()
static int get_frozen_index(const Group_c *g, uint16_t peer_number)
{
    for (uint32_t i = 0; i < g->numfrozen; ++i) {
        if (g->frozen[i].peer_number == peer_number) {
            return i;
        }
    }

    return -1;
}

non_null()
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

        Group_Peer *const frozen_temp = (Group_Peer *)realloc(g->frozen, sizeof(Group_Peer) * g->numfrozen);

        if (frozen_temp == nullptr) {
            return false;
        }

        g->frozen = frozen_temp;
    }

    return true;
}

/** @brief Update last_active timestamp on peer, and thaw the peer if it is frozen.
 *
 * @return peer index if peer is in the conference.
 * @retval -1 otherwise, and on error.
 */
non_null(1) nullable(4)
static int note_peer_active(Group_Chats *g_c, uint32_t groupnumber, uint16_t peer_number, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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

    if (g_c->peer_list_changed_callback != nullptr) {
        g_c->peer_list_changed_callback(g_c->m, groupnumber, userdata);
    }

    if (g->peer_on_join != nullptr) {
        g->peer_on_join(g->object, groupnumber, thawed_index);
    }

    g->need_send_name = true;

    return thawed_index;
}

non_null(1) nullable(4)
static bool delpeer(Group_Chats *g_c, uint32_t groupnumber, int peer_index, void *userdata);

non_null(1, 3) nullable(4)
static void delete_any_peer_with_pk(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *real_pk, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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

/** @brief Add a peer to the group chat, or update an existing peer.
 *
 * fresh indicates whether we should consider this information on the peer to
 * be current, and so should update temp_pk and consider the peer active.
 *
 * do_gc_callback indicates whether we want to trigger callbacks set by the client
 * via the public API. This should be set to false if this function is called
 * from outside of the `tox_iterate()` loop.
 *
 * @return peer_index if success or peer already in chat.
 * @retval -1 if error.
 */
non_null(1, 3, 4) nullable(6)
static int addpeer(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *real_pk, const uint8_t *temp_pk,
                   uint16_t peer_number, void *userdata, bool fresh, bool do_gc_callback)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    const int peer_index = fresh ?
                           note_peer_active(g_c, groupnumber, peer_number, userdata) :
                           get_peer_index(g, peer_number);

    if (peer_index != -1) {
        if (!pk_equal(g->group[peer_index].real_pk, real_pk)) {
            return -1;
        }

        if (fresh || !g->group[peer_index].temp_pk_updated) {
            pk_copy(g->group[peer_index].temp_pk, temp_pk);
            g->group[peer_index].temp_pk_updated = true;
        }

        return peer_index;
    }

    if (!fresh) {
        const int frozen_index = get_frozen_index(g, peer_number);

        if (frozen_index != -1) {
            if (!pk_equal(g->frozen[frozen_index].real_pk, real_pk)) {
                return -1;
            }

            pk_copy(g->frozen[frozen_index].temp_pk, temp_pk);

            return -1;
        }
    }

    delete_any_peer_with_pk(g_c, groupnumber, real_pk, userdata);

    Group_Peer *temp = (Group_Peer *)realloc(g->group, sizeof(Group_Peer) * (g->numpeers + 1));

    if (temp == nullptr) {
        return -1;
    }

    temp[g->numpeers] = empty_group_peer;
    g->group = temp;

    const uint32_t new_index = g->numpeers;

    pk_copy(g->group[new_index].real_pk, real_pk);
    pk_copy(g->group[new_index].temp_pk, temp_pk);
    g->group[new_index].temp_pk_updated = true;
    g->group[new_index].peer_number = peer_number;
    g->group[new_index].last_active = mono_time_get(g_c->mono_time);
    g->group[new_index].is_friend = getfriend_id(g_c->m, real_pk) != -1;
    ++g->numpeers;

    add_to_closest(g, real_pk, temp_pk);

    if (do_gc_callback && g_c->peer_list_changed_callback != nullptr) {
        g_c->peer_list_changed_callback(g_c->m, groupnumber, userdata);
    }

    if (g->peer_on_join != nullptr) {
        g->peer_on_join(g->object, groupnumber, new_index);
    }

    return new_index;
}

non_null()
static void remove_connection(Group_Chats *g_c, Group_c *g, uint16_t i)
{
    if ((g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_INTRODUCER) != 0) {
        --g->num_introducer_connections;
    }

    kill_friend_connection(g_c->fr_c, g->connections[i].number);
    g->connections[i].type = GROUPCHAT_CONNECTION_NONE;
}

non_null()
static void remove_from_closest(Group_c *g, int peer_index)
{
    for (uint32_t i = 0; i < DESIRED_CLOSEST; ++i) {
        if (g->closest_peers[i].active
                && pk_equal(g->closest_peers[i].real_pk, g->group[peer_index].real_pk)) {
            g->closest_peers[i].active = false;
            g->changed = GROUPCHAT_CLOSEST_CHANGE_REMOVED;
            break;
        }
    }
}

/**
 * Delete a peer from the group chat.
 *
 * return true on success
 */
static bool delpeer(Group_Chats *g_c, uint32_t groupnumber, int peer_index, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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

        Group_Peer *temp = (Group_Peer *)realloc(g->group, sizeof(Group_Peer) * g->numpeers);

        if (temp == nullptr) {
            return false;
        }

        g->group = temp;
    }

    if (g_c->peer_list_changed_callback != nullptr) {
        g_c->peer_list_changed_callback(g_c->m, groupnumber, userdata);
    }

    if (g->peer_on_leave != nullptr) {
        g->peer_on_leave(g->object, groupnumber, peer_object);
    }

    return true;
}

static int cmp_u64(uint64_t a, uint64_t b)
{
    return (a > b ? 1 : 0) - (a < b ? 1 : 0);
}

/** Order peers with friends first and with more recently active earlier */
non_null()
static int cmp_frozen(const void *a, const void *b)
{
    const Group_Peer *pa = (const Group_Peer *)a;
    const Group_Peer *pb = (const Group_Peer *)b;

    if (pa->is_friend ^ pb->is_friend) {
        return pa->is_friend ? -1 : 1;
    }

    return cmp_u64(pb->last_active, pa->last_active);
}

/** @brief Delete frozen peers as necessary to ensure at most `g->maxfrozen` remain.
 *
 * @retval true if any frozen peers are removed.
 */
non_null()
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

non_null()
static bool try_send_rejoin(Group_Chats *g_c, Group_c *g, const uint8_t *real_pk);

non_null(1) nullable(4)
static bool freeze_peer(Group_Chats *g_c, uint32_t groupnumber, int peer_index, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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


/** @brief Set the nick for a peer.
 *
 * do_gc_callback indicates whether we want to trigger callbacks set by the client
 * via the public API. This should be set to false if this function is called
 * from outside of the `tox_iterate()` loop.
 *
 * @retval true on success.
 */
non_null(1, 4) nullable(6)
static bool setnick(Group_Chats *g_c, uint32_t groupnumber, int peer_index, const uint8_t *nick, uint16_t nick_len,
                    void *userdata, bool do_gc_callback)
{
    if (nick_len > MAX_NAME_LENGTH) {
        return false;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return false;
    }

    g->group[peer_index].nick_updated = true;

    if (g_peer_nick_eq(&g->group[peer_index], nick, nick_len)) {
        /* same name as already stored */
        return true;
    }

    if (nick_len > 0) {
        memcpy(g->group[peer_index].nick, nick, nick_len);
    }

    g->group[peer_index].nick_len = nick_len;

    if (do_gc_callback && g_c->peer_name_callback != nullptr) {
        g_c->peer_name_callback(g_c->m, groupnumber, peer_index, nick, nick_len, userdata);
    }

    return true;
}

/** @brief Set the title for a group.
 *
 * @retval true on success.
 */
non_null(1, 4) nullable(6)
static bool settitle(Group_Chats *g_c, uint32_t groupnumber, int peer_index, const uint8_t *title, uint8_t title_len,
                     void *userdata)
{
    if (title_len > MAX_NAME_LENGTH || title_len == 0) {
        return false;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return false;
    }

    if (g_title_eq(g, title, title_len)) {
        /* same title as already set */
        return true;
    }

    memcpy(g->title, title, title_len);
    g->title_len = title_len;

    g->title_fresh = true;

    if (g_c->title_callback != nullptr) {
        g_c->title_callback(g_c->m, groupnumber, peer_index, title, title_len, userdata);
    }

    return true;
}

/** Check if the group has no online connection, and freeze all peers if so */
non_null(1) nullable(3)
static void check_disconnected(Group_Chats *g_c, uint32_t groupnumber, void *userdata)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type == GROUPCHAT_CONNECTION_ONLINE) {
            return;
        }
    }

    for (uint32_t i = 0; i < g->numpeers; ++i) {
        while (i < g->numpeers && !pk_equal(g->group[i].real_pk, g->real_pk)) {
            freeze_peer(g_c, groupnumber, i, userdata);
        }
    }
}

non_null(1) nullable(5)
static void set_conns_type_connections(Group_Chats *g_c, uint32_t groupnumber, int friendcon_id, uint8_t type,
                                       void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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

/** Set the type for all connections with friendcon_id */
non_null(1) nullable(4)
static void set_conns_status_groups(Group_Chats *g_c, int friendcon_id, uint8_t type, void *userdata)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        set_conns_type_connections(g_c, i, friendcon_id, type, userdata);
    }
}

non_null()
static void rejoin_frozen_friend(Group_Chats *g_c, int friendcon_id)
{
    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    get_friendcon_public_keys(real_pk, nullptr, g_c->fr_c, friendcon_id);

    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        Group_c *g = get_group_c(g_c, i);

        if (g == nullptr) {
            continue;
        }

        for (uint32_t j = 0; j < g->numfrozen; ++j) {
            if (pk_equal(g->frozen[j].real_pk, real_pk)) {
                try_send_rejoin(g_c, g, real_pk);
                break;
            }
        }
    }
}

non_null(1) nullable(4)
static int g_handle_any_status(void *object, int friendcon_id, bool status, void *userdata)
{
    Group_Chats *g_c = (Group_Chats *)object;

    if (status) {
        rejoin_frozen_friend(g_c, friendcon_id);
    }

    return 0;
}

non_null(1) nullable(4)
static int g_handle_status(void *object, int friendcon_id, bool status, void *userdata)
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

non_null(1, 3) nullable(5)
static int g_handle_packet(void *object, int friendcon_id, const uint8_t *data, uint16_t length, void *userdata);
non_null(1, 3) nullable(5)
static int handle_lossy(void *object, int friendcon_id, const uint8_t *data, uint16_t length, void *userdata);

/** @brief Add friend to group chat.
 *
 * @return connections index on success
 * @retval -1 on failure.
 */
static int add_conn_to_groupchat(Group_Chats *g_c, int friendcon_id, Group_c *g, uint8_t reason,
                                 bool lock)
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

    if ((g->connections[ind].reasons & reason) == 0) {
        g->connections[ind].reasons |= reason;

        if (reason == GROUPCHAT_CONNECTION_REASON_INTRODUCER) {
            ++g->num_introducer_connections;
        }
    }

    return ind;
}

non_null()
static bool send_peer_introduced(const Group_Chats *g_c, int friendcon_id, uint16_t group_num);

/** @brief Removes reason for keeping connection.
 *
 * Kills connection if this was the last reason.
 */
static void remove_connection_reason(Group_Chats *g_c, Group_c *g, uint16_t i, uint8_t reason)
{
    if ((g->connections[i].reasons & reason) == 0) {
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

/** @brief Creates a new groupchat and puts it in the chats array.
 *
 * @param rng Random number generator used for generating the group ID.
 * @param type is one of `GROUPCHAT_TYPE_*`
 *
 * @return group number on success.
 * @retval -1 on failure.
 */
int add_groupchat(Group_Chats *g_c, const Random *rng, uint8_t type)
{
    const int32_t groupnumber = create_group_chat(g_c);

    if (groupnumber == -1) {
        return -1;
    }

    Group_c *g = &g_c->chats[groupnumber];

    g->status = GROUPCHAT_STATUS_CONNECTED;
    g->type = type;
    new_symmetric_key(rng, g->id);
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

non_null()
static bool group_leave(const Group_Chats *g_c, uint32_t groupnumber, bool permanent);

/** @brief Delete a groupchat from the chats array, informing the group first as
 * appropriate.
 *
 * @retval true on success.
 * @retval false if groupnumber is invalid.
 */
bool del_groupchat(Group_Chats *g_c, uint32_t groupnumber, bool leave_permanently)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return false;
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
        if (g->peer_on_leave != nullptr) {
            g->peer_on_leave(g->object, groupnumber, g->group[i].object);
        }
    }

    if (g->group_on_delete != nullptr) {
        g->group_on_delete(g->object, groupnumber);
    }

    return wipe_group_chat(g_c, groupnumber);
}

non_null()
static const Group_Peer *peer_in_list(const Group_c *g, uint32_t peernumber, bool frozen)
{
    const Group_Peer *list = frozen ? g->frozen : g->group;
    const uint32_t num = frozen ? g->numfrozen : g->numpeers;

    if (peernumber >= num) {
        return nullptr;
    }

    return &list[peernumber];
}


/**
 * @brief Copy the public key of (frozen, if frozen is true) peernumber who is in
 *   groupnumber to pk.
 *
 * @param pk must be CRYPTO_PUBLIC_KEY_SIZE long.
 *
 * @retval 0 on success
 * @retval -1 if groupnumber is invalid.
 * @retval -2 if peernumber is invalid.
 */
int group_peer_pubkey(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, uint8_t *pk, bool frozen)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    const Group_Peer *peer = peer_in_list(g, peernumber, frozen);

    if (peer == nullptr) {
        return -2;
    }

    memcpy(pk, peer->real_pk, CRYPTO_PUBLIC_KEY_SIZE);
    return 0;
}

/**
 * @brief Return the size of (frozen, if frozen is true) peernumber's name.
 *
 * @retval -1 if groupnumber is invalid.
 * @retval -2 if peernumber is invalid.
 */
int group_peername_size(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, bool frozen)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    const Group_Peer *peer = peer_in_list(g, peernumber, frozen);

    if (peer == nullptr) {
        return -2;
    }

    return peer->nick_len;
}

/**
 * @brief Copy the name of (frozen, if frozen is true) peernumber who is in
 *   groupnumber to name.
 *
 * @param  name must be at least MAX_NAME_LENGTH long.
 *
 * @return length of name if success
 * @retval -1 if groupnumber is invalid.
 * @retval -2 if peernumber is invalid.
 */
int group_peername(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, uint8_t *name, bool frozen)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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

/**
 * @brief Copy last active timestamp of frozen peernumber who is in groupnumber to
 *   last_active.
 *
 * @retval 0 on success.
 * @retval -1 if groupnumber is invalid.
 * @retval -2 if peernumber is invalid.
 */
int group_frozen_last_active(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber,
                             uint64_t *last_active)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    if (peernumber >= g->numfrozen) {
        return -2;
    }

    *last_active = g->frozen[peernumber].last_active;
    return 0;
}

/** @brief Set maximum number of frozen peers.
 *
 * @retval 0 on success.
 * @retval -1 if groupnumber is invalid.
 */
int group_set_max_frozen(const Group_Chats *g_c, uint32_t groupnumber, uint32_t maxfrozen)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    g->maxfrozen = maxfrozen;
    delete_old_frozen(g);
    return 0;
}

/**
 * @return the number of (frozen, if frozen is true) peers in the group chat on success.
 * @retval -1 if groupnumber is invalid.
 */
int group_number_peers(const Group_Chats *g_c, uint32_t groupnumber, bool frozen)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    return frozen ? g->numfrozen : g->numpeers;
}

/**
 * @retval 1 if the peernumber corresponds to ours.
 * @retval 0 if the peernumber is not ours.
 * @retval -1 if groupnumber is invalid.
 * @retval -2 if peernumber is invalid.
 * @retval -3 if we are not connected to the group chat.
 */
int group_peernumber_is_ours(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    if (peernumber >= g->numpeers) {
        return -2;
    }

    if (g->status != GROUPCHAT_STATUS_CONNECTED) {
        return -3;
    }

    return (g->peer_number == g->group[peernumber].peer_number) ? 1 : 0;
}

/** @brief return the type of groupchat (GROUPCHAT_TYPE_) that groupnumber is.
 *
 * @retval -1 on failure.
 * @return type on success.
 */
int group_get_type(const Group_Chats *g_c, uint32_t groupnumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    return g->type;
}

/** @brief Copies the unique id of `group_chat[groupnumber]` into `id`.
 *
 * @retval false on failure.
 * @retval true on success.
 */
bool conference_get_id(const Group_Chats *g_c, uint32_t groupnumber, uint8_t *id)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return false;
    }

    if (id != nullptr) {
        memcpy(id, g->id, sizeof(g->id));
    }

    return true;
}

/** @brief Send a group packet to friendcon_id.
 *
 * @retval true on success
 * @retval false on failure
 */
non_null()
static bool send_packet_group_peer(const Friend_Connections *fr_c, int friendcon_id, uint8_t packet_id,
                                   uint16_t group_num, const uint8_t *data, uint16_t length)
{
    if (1 + sizeof(uint16_t) + length > MAX_CRYPTO_DATA_SIZE) {
        return false;
    }

    group_num = net_htons(group_num);
    VLA(uint8_t, packet, 1 + sizeof(uint16_t) + length);
    packet[0] = packet_id;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    memcpy(packet + 1 + sizeof(uint16_t), data, length);
    return write_cryptpacket(friendconn_net_crypto(fr_c), friend_connection_crypt_connection_id(fr_c, friendcon_id), packet,
                             SIZEOF_VLA(packet), false) != -1;
}

/** @brief Send a group lossy packet to friendcon_id.
 *
 * @retval true on success
 * @retval false on failure
 */
non_null()
static bool send_lossy_group_peer(const Friend_Connections *fr_c, int friendcon_id, uint8_t packet_id,
                                  uint16_t group_num, const uint8_t *data, uint16_t length)
{
    if (1 + sizeof(uint16_t) + length > MAX_CRYPTO_DATA_SIZE) {
        return false;
    }

    group_num = net_htons(group_num);
    VLA(uint8_t, packet, 1 + sizeof(uint16_t) + length);
    packet[0] = packet_id;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    memcpy(packet + 1 + sizeof(uint16_t), data, length);
    return send_lossy_cryptpacket(friendconn_net_crypto(fr_c), friend_connection_crypt_connection_id(fr_c, friendcon_id),
                                  packet, SIZEOF_VLA(packet)) != -1;
}

/** @brief invite friendnumber to groupnumber.
 *
 * @retval 0 on success.
 * @retval -1 if groupnumber is invalid.
 * @retval -2 if invite packet failed to send.
 * @retval -3 if we are not connected to the group chat.
 */
int invite_friend(const Group_Chats *g_c, uint32_t friendnumber, uint32_t groupnumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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

/** @brief Send a rejoin packet to a peer if we have a friend connection to the peer.
 * @retval true if a packet was sent.
 * @retval false otherwise.
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
                          packet, sizeof(packet), false) == -1) {
        return false;
    }

    add_conn_to_groupchat(g_c, friendcon_id, g, GROUPCHAT_CONNECTION_REASON_INTRODUCER, true);

    return true;
}

non_null()
static bool send_peer_query(const Group_Chats *g_c, int friendcon_id, uint16_t group_num);

non_null()
static bool send_invite_response(Group_Chats *g_c, int groupnumber, uint32_t friendnumber, const uint8_t *data,
                                 uint16_t length);

/** @brief Join a group (we need to have been invited first).
 *
 * @param expected_type is the groupchat type we expect the chat we are joining
 *   to have.
 *
 * @return group number on success.
 * @retval -1 if data length is invalid.
 * @retval -2 if group is not the expected type.
 * @retval -3 if friendnumber is invalid.
 * @retval -4 if client is already in this group.
 * @retval -5 if group instance failed to initialize.
 * @retval -6 if join packet fails to send.
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

    const bool member = g->status == GROUPCHAT_STATUS_CONNECTED;

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

    const int connection_index = add_conn_to_groupchat(g_c, friendcon_id, g, GROUPCHAT_CONNECTION_REASON_INTRODUCER, true);

    if (member) {
        add_conn_to_groupchat(g_c, friendcon_id, g, GROUPCHAT_CONNECTION_REASON_INTRODUCING, false);
    }

    if (connection_index != -1) {
        g->connections[connection_index].group_number = other_groupnum;
        g->connections[connection_index].type = GROUPCHAT_CONNECTION_ONLINE;
    }

    send_peer_query(g_c, friendcon_id, other_groupnum);

    return true;
}

/** Set handlers for custom lossy packets. */
void group_lossy_packet_registerhandler(Group_Chats *g_c, uint8_t byte, lossy_packet_cb *function)
{
    g_c->lossy_packethandlers[byte] = function;
}

/** Set the callback for group invites. */
void g_callback_group_invite(Group_Chats *g_c, g_conference_invite_cb *function)
{
    g_c->invite_callback = function;
}

/** Set the callback for group connection. */
void g_callback_group_connected(Group_Chats *g_c, g_conference_connected_cb *function)
{
    g_c->connected_callback = function;
}

/** Set the callback for group messages. */
void g_callback_group_message(Group_Chats *g_c, g_conference_message_cb *function)
{
    g_c->message_callback = function;
}

/** @brief Set callback function for peer nickname changes.
 *
 * It gets called every time a peer changes their nickname.
 */
void g_callback_peer_name(Group_Chats *g_c, peer_name_cb *function)
{
    g_c->peer_name_callback = function;
}

/** @brief Set callback function for peer list changes.
 *
 * It gets called every time the name list changes(new peer, deleted peer)
 */
void g_callback_peer_list_changed(Group_Chats *g_c, peer_list_changed_cb *function)
{
    g_c->peer_list_changed_callback = function;
}

/** Set callback function for title changes. */
void g_callback_group_title(Group_Chats *g_c, title_cb *function)
{
    g_c->title_callback = function;
}

/** @brief Set a function to be called when a new peer joins a group chat.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int callback_groupchat_peer_new(const Group_Chats *g_c, uint32_t groupnumber, peer_on_join_cb *function)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    g->peer_on_join = function;
    return 0;
}

/** @brief Set a function to be called when a peer leaves a group chat.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int callback_groupchat_peer_delete(const Group_Chats *g_c, uint32_t groupnumber, peer_on_leave_cb *function)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    g->peer_on_leave = function;
    return 0;
}

/** @brief Set a function to be called when the group chat is deleted.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int callback_groupchat_delete(const Group_Chats *g_c, uint32_t groupnumber, group_on_delete_cb *function)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    g->group_on_delete = function;
    return 0;
}

non_null(1) nullable(4)
static int send_message_group(const Group_Chats *g_c, uint32_t groupnumber, uint8_t message_id, const uint8_t *data,
                              uint16_t len);

/** @brief send a ping message
 * return true on success
 */
non_null()
static bool group_ping_send(const Group_Chats *g_c, uint32_t groupnumber)
{
    return send_message_group(g_c, groupnumber, GROUP_MESSAGE_PING_ID, nullptr, 0) > 0;
}

/** @brief send a new_peer message
 * return true on success
 */
non_null()
static bool group_new_peer_send(const Group_Chats *g_c, uint32_t groupnumber, uint16_t peer_num, const uint8_t *real_pk,
                                const uint8_t *temp_pk)
{
    uint8_t packet[GROUP_MESSAGE_NEW_PEER_LENGTH];

    peer_num = net_htons(peer_num);
    memcpy(packet, &peer_num, sizeof(uint16_t));
    memcpy(packet + sizeof(uint16_t), real_pk, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(packet + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE, temp_pk, CRYPTO_PUBLIC_KEY_SIZE);

    return send_message_group(g_c, groupnumber, GROUP_MESSAGE_NEW_PEER_ID, packet, sizeof(packet)) > 0;
}

/** @brief send a kill_peer message
 * return true on success
 */
non_null()
static bool group_kill_peer_send(const Group_Chats *g_c, uint32_t groupnumber, uint16_t peer_num)
{
    uint8_t packet[GROUP_MESSAGE_KILL_PEER_LENGTH];

    peer_num = net_htons(peer_num);
    memcpy(packet, &peer_num, sizeof(uint16_t));

    return send_message_group(g_c, groupnumber, GROUP_MESSAGE_KILL_PEER_ID, packet, sizeof(packet)) > 0;
}

/** @brief send a freeze_peer message
 * return true on success
 */
non_null()
static bool group_freeze_peer_send(const Group_Chats *g_c, uint32_t groupnumber, uint16_t peer_num)
{
    uint8_t packet[GROUP_MESSAGE_KILL_PEER_LENGTH];

    peer_num = net_htons(peer_num);
    memcpy(packet, &peer_num, sizeof(uint16_t));

    return send_message_group(g_c, groupnumber, GROUP_MESSAGE_FREEZE_PEER_ID, packet, sizeof(packet)) > 0;
}

/** @brief send a name message
 * return true on success
 */
non_null()
static bool group_name_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *nick, uint16_t nick_len)
{
    if (nick_len > MAX_NAME_LENGTH) {
        return false;
    }

    return send_message_group(g_c, groupnumber, GROUP_MESSAGE_NAME_ID, nick, nick_len) > 0;
}

/** @brief send message to announce leaving group
 * return true on success
 */
static bool group_leave(const Group_Chats *g_c, uint32_t groupnumber, bool permanent)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return false;
    }

    if (permanent) {
        return group_kill_peer_send(g_c, groupnumber, g->peer_number);
    } else {
        return group_freeze_peer_send(g_c, groupnumber, g->peer_number);
    }
}


/** @brief set the group's title, limited to MAX_NAME_LENGTH.
 * @retval 0 on success
 * @retval -1 if groupnumber is invalid.
 * @retval -2 if title is too long or empty.
 * @retval -3 if packet fails to send.
 */
int group_title_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *title, uint8_t title_len)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    if (title_len > MAX_NAME_LENGTH || title_len == 0) {
        return -2;
    }

    /* same as already set? */
    if (g_title_eq(g, title, title_len)) {
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

/** @brief return the group's title size.
 * @retval -1 of groupnumber is invalid.
 * @retval -2 if title is too long or empty.
 */
int group_title_get_size(const Group_Chats *g_c, uint32_t groupnumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    if (g->title_len > MAX_NAME_LENGTH || g->title_len == 0) {
        return -2;
    }

    return g->title_len;
}

/** @brief Get group title from groupnumber and put it in title.
 *
 * Title needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 * @return length of copied title if success.
 * @retval -1 if groupnumber is invalid.
 * @retval -2 if title is too long or empty.
 */
int group_title_get(const Group_Chats *g_c, uint32_t groupnumber, uint8_t *title)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    if (g->title_len > MAX_NAME_LENGTH || g->title_len == 0) {
        return -2;
    }

    memcpy(title, g->title, g->title_len);
    return g->title_len;
}

non_null()
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

non_null(1, 3) nullable(5)
static void handle_friend_invite_packet(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length,
                                        void *userdata)
{
    Group_Chats *g_c = m->conferences_object;

    if (length <= 1) {
        return;
    }

    switch (data[0]) {
        case INVITE_ID: {
            if (length != INVITE_PACKET_SIZE) {
                return;
            }

            const int groupnumber = get_group_num(g_c, data[1 + sizeof(uint16_t)], data + 1 + sizeof(uint16_t) + 1);

            const uint8_t *invite_data = data + 1;
            const uint16_t invite_length = length - 1;

            if (groupnumber == -1) {
                if (g_c->invite_callback != nullptr) {
                    g_c->invite_callback(m, friendnumber, invite_data[sizeof(uint16_t)], invite_data, invite_length, userdata);
                }

                return;
            } else {
                const Group_c *g = get_group_c(g_c, groupnumber);

                if (g != nullptr && g->status == GROUPCHAT_STATUS_CONNECTED) {
                    send_invite_response(g_c, groupnumber, friendnumber, invite_data, invite_length);
                }
            }

            break;
        }

        case INVITE_ACCEPT_ID:
        case INVITE_MEMBER_ID: {
            const bool member = data[0] == INVITE_MEMBER_ID;

            if (length != (member ? INVITE_MEMBER_PACKET_SIZE : INVITE_ACCEPT_PACKET_SIZE)) {
                return;
            }

            uint16_t other_groupnum;
            uint16_t groupnum;
            net_unpack_u16(data + 1, &other_groupnum);
            net_unpack_u16(data + 1 + sizeof(uint16_t), &groupnum);

            Group_c *g = get_group_c(g_c, groupnum);

            if (g == nullptr) {
                return;
            }

            if (data[1 + sizeof(uint16_t) * 2] != g->type) {
                return;
            }

            if (!group_id_eq(data + 1 + sizeof(uint16_t) * 2 + 1, g->id)) {
                return;
            }

            uint16_t peer_number;

            if (member) {
                net_unpack_u16(data + 1 + sizeof(uint16_t) * 2 + 1 + GROUP_ID_LENGTH, &peer_number);
            } else {
                /* TODO(irungentoo): what if two people enter the group at the
                 * same time and are given the same peer_number by different
                 * nodes? */
                peer_number = random_u16(m->rng);

                unsigned int tries = 0;

                while (get_peer_index(g, peer_number) != -1 || get_frozen_index(g, peer_number) != -1) {
                    peer_number = random_u16(m->rng);
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
                                         GROUPCHAT_CONNECTION_REASON_INTRODUCING, true);

            if (member) {
                add_conn_to_groupchat(g_c, friendcon_id, g, GROUPCHAT_CONNECTION_REASON_INTRODUCER, false);
                send_peer_query(g_c, friendcon_id, other_groupnum);
            }

            if (connection_index != -1) {
                g->connections[connection_index].group_number = other_groupnum;
                g->connections[connection_index].type = GROUPCHAT_CONNECTION_ONLINE;
            }

            group_new_peer_send(g_c, groupnum, peer_number, real_pk, temp_pk);

            break;
        }

        default: {
            return;
        }
    }
}

/** @brief Find index of friend in the connections list.
 *
 * return index on success
 * return -1 on failure.
 */
non_null()
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

/** return number of connections. */
non_null()
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

static bool send_packet_online(const Friend_Connections *fr_c, int friendcon_id, uint16_t group_num,
                               uint8_t type, const uint8_t *id)
{
    uint8_t packet[1 + ONLINE_PACKET_DATA_SIZE];
    group_num = net_htons(group_num);
    packet[0] = PACKET_ID_ONLINE_PACKET;
    memcpy(packet + 1, &group_num, sizeof(uint16_t));
    packet[1 + sizeof(uint16_t)] = type;
    memcpy(packet + 1 + sizeof(uint16_t) + 1, id, GROUP_ID_LENGTH);
    return write_cryptpacket(friendconn_net_crypto(fr_c), friend_connection_crypt_connection_id(fr_c, friendcon_id), packet,
                             sizeof(packet), false) != -1;
}

non_null()
static bool ping_groupchat(const Group_Chats *g_c, uint32_t groupnumber);

non_null()
static int handle_packet_online(const Group_Chats *g_c, int friendcon_id, const uint8_t *data, uint16_t length)
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

    if (g == nullptr) {
        return -1;
    }

    const int index = friend_in_connections(g, friendcon_id);

    if (index == -1) {
        return -1;
    }

    if (g->connections[index].type == GROUPCHAT_CONNECTION_ONLINE) {
        return -1;
    }

    if (count_connected(g) == 0 || (g->connections[index].reasons & GROUPCHAT_CONNECTION_REASON_INTRODUCER) != 0) {
        send_peer_query(g_c, friendcon_id, other_groupnum);
    }

    g->connections[index].group_number = other_groupnum;
    g->connections[index].type = GROUPCHAT_CONNECTION_ONLINE;
    send_packet_online(g_c->fr_c, friendcon_id, groupnumber, g->type, g->id);

    if ((g->connections[index].reasons & GROUPCHAT_CONNECTION_REASON_INTRODUCING) != 0) {
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

non_null(1, 3) nullable(5)
static int handle_packet_rejoin(Group_Chats *g_c, int friendcon_id, const uint8_t *data, uint16_t length,
                                void *userdata)
{
    if (length < 1 + GROUP_ID_LENGTH) {
        return -1;
    }

    const int32_t groupnum = get_group_num(g_c, *data, data + 1);

    Group_c *g = get_group_c(g_c, groupnum);

    if (g == nullptr) {
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
                                 GROUPCHAT_CONNECTION_REASON_INTRODUCING, true);

    if (connection_index != -1) {
        send_packet_online(g_c->fr_c, friendcon_id, groupnum, g->type, g->id);
    }

    return 0;
}


// we could send title with invite, but then if it changes between sending and accepting inv, joinee won't see it

/**
 * @retval true on success.
 * @retval false on failure
 */
static bool send_peer_introduced(const Group_Chats *g_c, int friendcon_id, uint16_t group_num)
{
    uint8_t packet[1];
    packet[0] = PEER_INTRODUCED_ID;
    return send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_CONFERENCE, group_num, packet, sizeof(packet));
}


/**
 * @retval true on success.
 * @retval false on failure
 */
static bool send_peer_query(const Group_Chats *g_c, int friendcon_id, uint16_t group_num)
{
    uint8_t packet[1];
    packet[0] = PEER_QUERY_ID;
    return send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_CONFERENCE, group_num, packet, sizeof(packet));
}

/**
 * @return number of peers sent on success.
 * @retval 0 on failure.
 */
non_null()
static unsigned int send_peers(const Group_Chats *g_c, const Group_c *g, int friendcon_id, uint16_t group_num)
{
    uint8_t response_packet[MAX_CRYPTO_DATA_SIZE - (1 + sizeof(uint16_t))];
    response_packet[0] = PEER_RESPONSE_ID;
    uint8_t *p = response_packet + 1;

    uint16_t sent = 0;

    for (uint32_t i = 0; i <= g->numpeers; ++i) {
        if (i == g->numpeers
                || (p - response_packet) + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE * 2 + 1 + g->group[i].nick_len >
                sizeof(response_packet)) {
            if (send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_CONFERENCE, group_num, response_packet,
                                       p - response_packet)) {
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

    if (g->title_len > 0) {
        VLA(uint8_t, title_packet, 1 + g->title_len);
        title_packet[0] = PEER_TITLE_ID;
        memcpy(title_packet + 1, g->title, g->title_len);
        send_packet_group_peer(g_c->fr_c, friendcon_id, PACKET_ID_DIRECT_CONFERENCE, group_num, title_packet,
                               SIZEOF_VLA(title_packet));
    }

    return sent;
}

non_null(1, 3) nullable(5)
static int handle_send_peers(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length,
                             void *userdata)
{
    if (length == 0) {
        return -1;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    const uint8_t *d = data;

    while ((unsigned int)(length - (d - data)) >= sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE * 2 + 1) {
        uint16_t peer_num;
        memcpy(&peer_num, d, sizeof(peer_num));
        peer_num = net_ntohs(peer_num);
        d += sizeof(uint16_t);

        if (g->status == GROUPCHAT_STATUS_VALID
                && pk_equal(d, nc_get_self_public_key(g_c->m->net_crypto))) {
            g->peer_number = peer_num;
            g->status = GROUPCHAT_STATUS_CONNECTED;

            if (g_c->connected_callback != nullptr) {
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

non_null(1, 3) nullable(6)
static void handle_direct_packet(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length,
                                 int connection_index, void *userdata)
{
    if (length == 0) {
        return;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return;
    }

    switch (data[0]) {
        case PEER_INTRODUCED_ID: {
            remove_connection_reason(g_c, g, connection_index, GROUPCHAT_CONNECTION_REASON_INTRODUCING);
            break;
        }

        case PEER_QUERY_ID: {
            if (g->connections[connection_index].type != GROUPCHAT_CONNECTION_ONLINE) {
                return;
            }

            send_peers(g_c, g, g->connections[connection_index].number, g->connections[connection_index].group_number);
            break;
        }


        case PEER_RESPONSE_ID: {
            handle_send_peers(g_c, groupnumber, data + 1, length - 1, userdata);
            break;
        }


        case PEER_TITLE_ID: {
            if (!g->title_fresh) {
                settitle(g_c, groupnumber, -1, data + 1, length - 1, userdata);
            }

            break;
        }
    }
}

/** @brief Send message to all connections except receiver (if receiver isn't -1)
 *
 * NOTE: this function appends the group chat number to the data passed to it.
 *
 * @return number of messages sent.
 */
non_null()
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

/** @brief Send lossy message to all connections except receiver (if receiver isn't -1)
 *
 * NOTE: this function appends the group chat number to the data passed to it.
 *
 * @return number of messages sent.
 */
non_null()
static unsigned int send_lossy_all_connections(const Group_Chats *g_c, const Group_c *g, const uint8_t *data,
        uint16_t length, int receiver)
{
    unsigned int sent = 0;
    unsigned int num_connected_closest = 0;
    unsigned int connected_closest[DESIRED_CLOSEST] = {0};

    for (unsigned int i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type != GROUPCHAT_CONNECTION_ONLINE) {
            continue;
        }

        if ((int)i == receiver) {
            continue;
        }

        if ((g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_CLOSEST) != 0) {
            connected_closest[num_connected_closest] = i;
            ++num_connected_closest;
            continue;
        }

        if (send_lossy_group_peer(g_c->fr_c, g->connections[i].number, PACKET_ID_LOSSY_CONFERENCE,
                                  g->connections[i].group_number, data, length)) {
            ++sent;
        }
    }

    if (num_connected_closest == 0) {
        return sent;
    }

    unsigned int to_send[2] = {0, 0};
    uint64_t comp_val_old[2] = {(uint64_t) -1, (uint64_t) -1};

    for (unsigned int i = 0; i < num_connected_closest; ++i) {
        uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE] = {0};
        get_friendcon_public_keys(real_pk, nullptr, g_c->fr_c, g->connections[connected_closest[i]].number);
        const uint64_t comp_val = calculate_comp_value(g->real_pk, real_pk);

        for (uint8_t j = 0; j < 2; ++j) {
            if (j > 0 ? (comp_val > comp_val_old[j]) : (comp_val < comp_val_old[j])) {
                to_send[j] = connected_closest[i];
                comp_val_old[j] = comp_val;
            }
        }
    }

    for (uint8_t j = 0; j < 2; ++j) {
        if (j > 0 && to_send[1] == to_send[0]) {
            break;
        }

        if (send_lossy_group_peer(g_c->fr_c, g->connections[to_send[j]].number, PACKET_ID_LOSSY_CONFERENCE,
                                  g->connections[to_send[j]].group_number, data, length)) {
            ++sent;
        }
    }

    return sent;
}

/** @brief Send data of len with message_id to groupnumber.
 *
 * @return number of peers it was sent to on success.
 * @retval -1 if groupnumber is invalid.
 * @retval -2 if message is too long.
 * @retval -3 if we are not connected to the group.
 * @retval -4 if message failed to send.
 */
static int send_message_group(const Group_Chats *g_c, uint32_t groupnumber, uint8_t message_id, const uint8_t *data,
                              uint16_t len)
{
    assert(len == 0 || data != nullptr);
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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

    if (g->message_number == 0) {
        ++g->message_number;
    }

    const uint32_t message_num = net_htonl(g->message_number);
    memcpy(packet + sizeof(uint16_t), &message_num, sizeof(message_num));

    packet[sizeof(uint16_t) + sizeof(uint32_t)] = message_id;

    if (len != 0) {
        memcpy(packet + sizeof(uint16_t) + sizeof(uint32_t) + 1, data, len);
    }

    const unsigned int ret = send_message_all_connections(g_c, g, packet, SIZEOF_VLA(packet), -1);

    if (ret == 0) {
        return -4;
    }

    return ret;
}

/** @brief send a group message
 * @retval 0 on success
 * @see send_message_group for error codes.
 */
int group_message_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *message, uint16_t length)
{
    const int ret = send_message_group(g_c, groupnumber, PACKET_ID_MESSAGE, message, length);

    if (ret > 0) {
        return 0;
    }

    return ret;
}

/** @brief send a group action
 * @retval 0 on success
 * @see send_message_group for error codes.
 */
int group_action_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *action, uint16_t length)
{
    const int ret = send_message_group(g_c, groupnumber, PACKET_ID_ACTION, action, length);

    if (ret > 0) {
        return 0;
    }

    return ret;
}

/** @brief High level function to send custom lossy packets.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
int send_group_lossy_packet(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length)
{
    // TODO(irungentoo): length check here?
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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

non_null()
static Message_Info *find_message_slot_or_reject(uint32_t message_number, uint8_t message_id, Group_Peer *peer)
{
    const bool ignore_older = message_id == GROUP_MESSAGE_NAME_ID || message_id == GROUP_MESSAGE_TITLE_ID;

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

/** @brief Stores message info in `peer->last_message_infos`.
 *
 * @retval true if message should be processed.
 * @retval false otherwise.
 */
non_null()
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

    memmove(i + 1, i, (&peer->last_message_infos[peer->num_last_message_infos - 1] - i) * sizeof(Message_Info));

    i->message_number = message_number;
    i->message_id = message_id;

    return true;
}

non_null(1, 3) nullable(6)
static void handle_message_packet_group(Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length,
                                        int connection_index, void *userdata)
{
    if (length < sizeof(uint16_t) + sizeof(uint32_t) + 1) {
        return;
    }

    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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
                    || (g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_INTRODUCER) == 0
                    || i == connection_index) {
                continue;
            }

            uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
            get_friendcon_public_keys(real_pk, nullptr, g_c->fr_c, g->connections[i].number);

            if (pk_equal(g->group[index].real_pk, real_pk)) {
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
    const bool direct_from_sender = pk_equal(g->group[index].real_pk, real_pk);

    switch (message_id) {
        case GROUP_MESSAGE_PING_ID: {
            break;
        }

        case GROUP_MESSAGE_NEW_PEER_ID: {
            if (msg_data_len != GROUP_MESSAGE_NEW_PEER_LENGTH) {
                return;
            }

            uint16_t new_peer_number;
            memcpy(&new_peer_number, msg_data, sizeof(uint16_t));
            new_peer_number = net_ntohs(new_peer_number);
            addpeer(g_c, groupnumber, msg_data + sizeof(uint16_t), msg_data + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE,
                    new_peer_number, userdata, true, true);
            break;
        }

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

            break;
        }

        case GROUP_MESSAGE_NAME_ID: {
            if (!setnick(g_c, groupnumber, index, msg_data, msg_data_len, userdata, true)) {
                return;
            }

            break;
        }

        case GROUP_MESSAGE_TITLE_ID: {
            if (!settitle(g_c, groupnumber, index, msg_data, msg_data_len, userdata)) {
                return;
            }

            break;
        }

        case PACKET_ID_MESSAGE: {
            if (msg_data_len == 0) {
                return;
            }

            VLA(uint8_t, newmsg, msg_data_len + 1);
            memcpy(newmsg, msg_data, msg_data_len);
            newmsg[msg_data_len] = 0;

            // TODO(irungentoo):
            if (g_c->message_callback != nullptr) {
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
            if (g_c->message_callback != nullptr) {
                g_c->message_callback(g_c->m, groupnumber, index, 1, newmsg, msg_data_len, userdata);
            }

            break;
        }

        default: {
            return;
        }
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

    if (g == nullptr) {
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

/** @brief Did we already receive the lossy packet or not.
 *
 * @retval -1 on failure.
 * @retval 0 if packet was not received.
 * @retval 1 if packet was received.
 *
 * TODO(irungentoo): test this
 */
non_null()
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
        if (g->group[peer_index].recv_lossy[message_number % MAX_LOSSY_COUNT] != 0) {
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

/** Does this group type make use of lossy packets? */
static bool type_uses_lossy(uint8_t type)
{
    return type == GROUPCHAT_TYPE_AV;
}

static int handle_lossy(void *object, int friendcon_id, const uint8_t *data, uint16_t length, void *userdata)
{
    const Group_Chats *g_c = (const Group_Chats *)object;

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

    if (g == nullptr) {
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

    if (g_c->lossy_packethandlers[message_id] == nullptr) {
        return -1;
    }

    if (g_c->lossy_packethandlers[message_id](g->object, groupnumber, peer_index, g->group[peer_index].object,
            lossy_data, lossy_length) == -1) {
        return -1;
    }

    return 0;
}

/** @brief Set the object that is tied to the group chat.
 *
 * @retval 0 on success.
 * @retval -1 on failure
 */
int group_set_object(const Group_Chats *g_c, uint32_t groupnumber, void *object)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    g->object = object;
    return 0;
}

/** @brief Set the object that is tied to the group peer.
 *
 * @retval 0 on success.
 * @retval -1 on failure
 */
int group_peer_set_object(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, void *object)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return -1;
    }

    if (peernumber >= g->numpeers) {
        return -1;
    }

    g->group[peernumber].object = object;
    return 0;
}

/** @brief Return the object tied to the group chat previously set by group_set_object.
 *
 * @retval NULL on failure.
 * @return object on success.
 */
void *group_get_object(const Group_Chats *g_c, uint32_t groupnumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return nullptr;
    }

    return g->object;
}

/** @brief Return the object tied to the group chat peer previously set by group_peer_set_object.
 *
 * @retval NULL on failure.
 * @return object on success.
 */
void *group_peer_get_object(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber)
{
    const Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return nullptr;
    }

    if (peernumber >= g->numpeers) {
        return nullptr;
    }

    return g->group[peernumber].object;
}

/** Interval in seconds to send ping messages */
#define GROUP_PING_INTERVAL 20

static bool ping_groupchat(const Group_Chats *g_c, uint32_t groupnumber)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
        return false;
    }

    if (mono_time_is_timeout(g_c->mono_time, g->last_sent_ping, GROUP_PING_INTERVAL)) {
        if (group_ping_send(g_c, groupnumber)) {
            g->last_sent_ping = mono_time_get(g_c->mono_time);
        }
    }

    return true;
}

/** Seconds of inactivity after which to freeze a peer */
#define FREEZE_TIMEOUT (GROUP_PING_INTERVAL * 3)

non_null(1) nullable(3)
static bool groupchat_freeze_timedout(Group_Chats *g_c, uint32_t groupnumber, void *userdata)
{
    Group_c *g = get_group_c(g_c, groupnumber);

    if (g == nullptr) {
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

/** Push non-empty slots to start. */
non_null()
static void squash_connections(Group_c *g)
{
    uint16_t num_connected = 0;

    for (uint16_t i = 0; i < MAX_GROUP_CONNECTIONS; ++i) {
        if (g->connections[i].type != GROUPCHAT_CONNECTION_NONE) {
            g->connections[num_connected] = g->connections[i];
            ++num_connected;
        }
    }

    for (uint16_t i = num_connected; i < MAX_GROUP_CONNECTIONS; ++i) {
        g->connections[i].type = GROUPCHAT_CONNECTION_NONE;
    }
}

#define MIN_EMPTY_CONNECTIONS (1 + MAX_GROUP_CONNECTIONS / 10)

non_null()
static uint16_t empty_connection_count(const Group_c *g)
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

    return to_clear;
}

/**
 * @brief Remove old connections as necessary to ensure we have space for new
 *   connections.
 *
 * This invalidates connections array indices (which is
 * why we do this periodically rather than on adding a connection).
 */
non_null()
static void clean_connections(Group_Chats *g_c, Group_c *g)
{
    for (uint16_t to_clear = empty_connection_count(g); to_clear > 0; --to_clear) {
        // Remove a connection. Prefer non-closest connections, and given
        // that prefer non-online connections, and given that prefer earlier
        // slots.
        uint16_t i = 0;

        while (i < MAX_GROUP_CONNECTIONS
                && (g->connections[i].type != GROUPCHAT_CONNECTION_CONNECTING
                    || (g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_CLOSEST) != 0)) {
            ++i;
        }

        if (i == MAX_GROUP_CONNECTIONS) {
            i = 0;

            while (i < MAX_GROUP_CONNECTIONS - to_clear
                    && (g->connections[i].type != GROUPCHAT_CONNECTION_ONLINE
                        || (g->connections[i].reasons & GROUPCHAT_CONNECTION_REASON_CLOSEST) != 0)) {
                ++i;
            }
        }

        if (g->connections[i].type != GROUPCHAT_CONNECTION_NONE) {
            remove_connection(g_c, g, i);
        }
    }

    squash_connections(g);
}

/** Send current name (set in messenger) to all online groups. */
void send_name_all_groups(const Group_Chats *g_c)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        Group_c *g = get_group_c(g_c, i);

        if (g == nullptr) {
            continue;
        }

        if (g->status == GROUPCHAT_STATUS_CONNECTED) {
            group_name_send(g_c, i, g_c->m->name, g_c->m->name_length);
            g->need_send_name = false;
        }
    }
}

#define SAVED_PEER_SIZE_CONSTANT (2 * CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint16_t) + sizeof(uint64_t) + 1)

non_null()
static uint32_t saved_peer_size(const Group_Peer *peer)
{
    return SAVED_PEER_SIZE_CONSTANT + peer->nick_len;
}

non_null()
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

    // TODO(iphydf): This looks broken: nick_len can be > 255.
    *data = peer->nick_len;
    ++data;

    memcpy(data, peer->nick, peer->nick_len);
    data += peer->nick_len;

    return data;
}

#define SAVED_CONF_SIZE_CONSTANT (1 + GROUP_ID_LENGTH + sizeof(uint32_t) \
      + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + 1)

non_null()
static uint32_t saved_conf_size(const Group_c *g)
{
    uint32_t len = SAVED_CONF_SIZE_CONSTANT + g->title_len;

    for (uint32_t j = 0; j < g->numpeers + g->numfrozen; ++j) {
        const Group_Peer *peer = (j < g->numpeers) ? &g->group[j] : &g->frozen[j - g->numpeers];

        if (pk_equal(peer->real_pk, g->real_pk)) {
            continue;
        }

        len += saved_peer_size(peer);
    }

    return len;
}

/**
 * Save a future message number. The save will remain valid until we have sent
 * this many more messages.
 */
#define SAVE_OFFSET_MESSAGE_NUMBER (1 << 16)
#define SAVE_OFFSET_LOSSY_MESSAGE_NUMBER (1 << 13)

non_null()
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

        if (pk_equal(peer->real_pk, g->real_pk)) {
            continue;
        }

        data = save_peer(peer, data);
        ++numsaved;
    }

    host_to_lendian_bytes32(numsaved_location, numsaved);

    return data;
}

non_null()
static uint32_t conferences_section_size(const Group_Chats *g_c)
{
    uint32_t len = 0;

    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        const Group_c *g = get_group_c(g_c, i);

        if (g == nullptr || g->status != GROUPCHAT_STATUS_CONNECTED) {
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

        if (g == nullptr || g->status != GROUPCHAT_STATUS_CONNECTED) {
            continue;
        }

        data = save_conf(g, data);
    }

    return data;
}

/**
 * @brief load_group Load a Group section from a save file
 * @param g Group to load
 * @param g_c Reference to all groupchats, need for utility functions
 * @param data Start of the data to deserialze
 * @param length Length of data
 * @return 0 on error, number of consumed bytes otherwise
 */
non_null()
static uint32_t load_group(Group_c *g, const Group_Chats *g_c, const uint8_t *data, uint32_t length)
{
    const uint8_t *init_data = data;

    // Initialize to default values so we can unconditionally free in case of an error
    setup_conference(g);

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

    g->title_len = *data;

    if (g->title_len > MAX_NAME_LENGTH) {
        return 0;
    }

    ++data;

    assert((data - init_data) < UINT32_MAX);

    if (length < (uint32_t)(data - init_data) + g->title_len) {
        return 0;
    }

    memcpy(g->title, data, g->title_len);
    data += g->title_len;

    for (uint32_t j = 0; j < g->numfrozen; ++j) {

        assert((data - init_data) < UINT32_MAX);

        if (length < (uint32_t)(data - init_data) + SAVED_PEER_SIZE_CONSTANT) {
            return 0;
        }

        // This is inefficient, but allows us to check data consistency before allocating memory
        Group_Peer *tmp_frozen = (Group_Peer *)realloc(g->frozen, (j + 1) * sizeof(Group_Peer));

        if (tmp_frozen == nullptr) {
            // Memory allocation failure
            return 0;
        }

        g->frozen = tmp_frozen;

        Group_Peer *peer = &g->frozen[j];
        *peer = empty_group_peer;

        pk_copy(peer->real_pk, data);
        data += CRYPTO_PUBLIC_KEY_SIZE;
        pk_copy(peer->temp_pk, data);
        data += CRYPTO_PUBLIC_KEY_SIZE;

        lendian_bytes_to_host16(&peer->peer_number, data);
        data += sizeof(uint16_t);

        lendian_bytes_to_host64(&peer->last_active, data);
        data += sizeof(uint64_t);

        peer->nick_len = *data;

        if (peer->nick_len > MAX_NAME_LENGTH) {
            return 0;
        }

        ++data;
        assert((data - init_data) < UINT32_MAX);

        if (length < (uint32_t)(data - init_data) + peer->nick_len) {
            return 0;
        }

        memcpy(peer->nick, data, peer->nick_len);
        data += peer->nick_len;

        // NOTE: this relies on friends being loaded before conferences.
        peer->is_friend = getfriend_id(g_c->m, peer->real_pk) != -1;
    }

    if (g->numfrozen > g->maxfrozen) {
        g->maxfrozen = g->numfrozen;
    }

    g->status = GROUPCHAT_STATUS_CONNECTED;

    pk_copy(g->real_pk, nc_get_self_public_key(g_c->m->net_crypto));

    assert((data - init_data) < UINT32_MAX);

    return (uint32_t)(data - init_data);
}

non_null()
static State_Load_Status load_conferences_helper(Group_Chats *g_c, const uint8_t *data, uint32_t length)
{
    const uint8_t *init_data = data;

    while (length >= (uint32_t)(data - init_data) + SAVED_CONF_SIZE_CONSTANT) {
        const int groupnumber = create_group_chat(g_c);

        // Helpful for testing
        assert(groupnumber != -1);

        if (groupnumber == -1) {
            // If this fails there's a serious problem, don't bother with cleanup
            return STATE_LOAD_STATUS_ERROR;
        }

        Group_c *g = &g_c->chats[groupnumber];

        const uint32_t consumed = load_group(g, g_c, data, length - (uint32_t)(data - init_data));

        if (consumed == 0) {
            // remove partially loaded stuff, wipe_group_chat must be able to wipe a partially loaded group
            const bool ret = wipe_group_chat(g_c, groupnumber);

            // HACK: suppress unused variable warning
            if (!ret) {
                // wipe_group_chat(...) must be able to wipe partially allocated groups
                assert(ret);
            }

            return STATE_LOAD_STATUS_ERROR;
        }

        data += consumed;

        const int peer_index = addpeer(g_c, groupnumber, g->real_pk, dht_get_self_public_key(g_c->m->dht), g->peer_number,
                                       nullptr, true, false);

        if (peer_index == -1) {
            return STATE_LOAD_STATUS_ERROR;
        }

        setnick(g_c, groupnumber, peer_index, g_c->m->name, g_c->m->name_length, nullptr, false);
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

non_null()
static State_Load_Status load_conferences(Group_Chats *g_c, const uint8_t *data, uint32_t length)
{
    const State_Load_Status res = load_conferences_helper(g_c, data, length);

    if (res == STATE_LOAD_STATUS_CONTINUE) {
        return res;
    }

    // Loading failed, cleanup all Group_c

    // save locally, because wipe_group_chat(...) modifies it
    const uint16_t num_groups = g_c->num_chats;

    for (uint16_t i = 0; i < num_groups; ++i) {
        wipe_group_chat(g_c, i);
    }

    return res;
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


/** Create new groupchat instance. */
Group_Chats *new_groupchats(const Mono_Time *mono_time, Messenger *m)
{
    if (m == nullptr) {
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

/** main groupchats loop. */
void do_groupchats(Group_Chats *g_c, void *userdata)
{
    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        Group_c *g = get_group_c(g_c, i);

        if (g == nullptr) {
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

/** Free everything related with group chats. */
void kill_groupchats(Group_Chats *g_c)
{
    if (g_c == nullptr) {
        return;
    }

    for (uint16_t i = 0; i < g_c->num_chats; ++i) {
        del_groupchat(g_c, i, false);
    }

    m_callback_conference_invite(g_c->m, nullptr);
    set_global_status_callback(g_c->m->fr_c, nullptr, nullptr);
    g_c->m->conferences_object = nullptr;
    free(g_c);
}

/**
 * @brief Return the number of chats in the instance m.
 *
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

/** @brief Copy a list of valid chat IDs into the array out_list.
 *
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size.
 */
uint32_t copy_chatlist(const Group_Chats *g_c, uint32_t *out_list, uint32_t list_size)
{
    if (out_list == nullptr) {
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
