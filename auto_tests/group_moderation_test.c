/*
 * Tests group moderation functionality.
 *
 * Note that making the peer count too high will break things. This test should not be relied on
 * for general group/syncing functionality.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "auto_test_support.h"
#include "check_compat.h"

#include "../toxcore/tox.h"

#define NUM_GROUP_TOXES 5
#define GROUP_NAME "NASA Headquarters"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

typedef struct Peer {
    char name[TOX_MAX_NAME_LENGTH];
    size_t name_length;
    uint32_t peer_id;
} Peer;

typedef struct State {
    char self_name[TOX_MAX_NAME_LENGTH];
    size_t self_name_length;

    uint32_t group_number;

    uint32_t num_peers;
    Peer peers[NUM_GROUP_TOXES - 1];

    bool mod_check;
    size_t mod_event_count;
    char mod_name1[TOX_MAX_NAME_LENGTH];
    char mod_name2[TOX_MAX_NAME_LENGTH];


    bool observer_check;
    size_t observer_event_count;
    char observer_name1[TOX_MAX_NAME_LENGTH];
    char observer_name2[TOX_MAX_NAME_LENGTH];

    bool user_check;
    size_t user_event_count;

    bool kick_check;  // mod gets kicked
} State;

static bool all_peers_connected(AutoTox *autotoxes)
{
    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        State *state = (State *)autotoxes[i].state;

        if (state->num_peers != NUM_GROUP_TOXES - 1) {
            return false;
        }

        if (!tox_group_is_connected(autotoxes[i].tox, state->group_number, nullptr)) {
            return false;
        }
    }

    return true;
}

/*
 * Waits for all peers to receive the mod event.
 */
static void check_mod_event(AutoTox *autotoxes, size_t num_peers, Tox_Group_Mod_Event event)
{
    uint32_t peers_recv_changes = 0;

    do {
        peers_recv_changes = 0;

        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

        for (size_t i = 0; i < num_peers; ++i) {
            State *state = (State *)autotoxes[i].state;
            bool check = false;

            switch (event) {
                case TOX_GROUP_MOD_EVENT_MODERATOR: {
                    if (state->mod_check) {
                        check = true;
                        state->mod_check = false;
                    }

                    break;
                }

                case TOX_GROUP_MOD_EVENT_OBSERVER: {
                    if (state->observer_check) {
                        check = true;
                        state->observer_check = false;
                    }

                    break;
                }

                case TOX_GROUP_MOD_EVENT_USER: {
                    if (state->user_check) {
                        check = true;
                        state->user_check = false;
                    }

                    break;
                }

                case TOX_GROUP_MOD_EVENT_KICK: {
                    check = state->kick_check;
                    break;
                }

                default: {
                    ck_assert(0);
                }
            }

            if (check) {
                ++peers_recv_changes;
            }
        }
    } while (peers_recv_changes < num_peers - 1);
}

static uint32_t get_peer_id_by_nick(const Peer *peers, uint32_t num_peers, const char *name)
{
    ck_assert(name != nullptr);

    for (uint32_t i = 0; i < num_peers; ++i) {
        if (memcmp(peers[i].name, name, peers[i].name_length) == 0) {
            return peers[i].peer_id;
        }
    }

    ck_assert_msg(0, "Failed to find peer id");
}

static size_t get_state_index_by_nick(const AutoTox *autotoxes, size_t num_peers, const char *name, size_t name_length)
{
    ck_assert(name != nullptr && name_length <= TOX_MAX_NAME_LENGTH);

    for (size_t i = 0; i < num_peers; ++i) {
        State *state = (State *)autotoxes[i].state;

        if (memcmp(state->self_name, name, name_length) == 0) {
            return i;
        }
    }

    ck_assert_msg(0, "Failed to find index");
}

static void group_join_fail_handler(Tox *tox, uint32_t group_number, Tox_Group_Join_Fail fail_type, void *user_data)
{
    fprintf(stderr, "Failed to join group: %d", fail_type);
}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    ck_assert(state->group_number == group_number);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];

    Tox_Err_Group_Peer_Query q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(tox, group_number, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    tox_group_peer_get_name(tox, group_number, peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;
    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    Peer *peer = &state->peers[state->num_peers];

    peer->peer_id = peer_id;
    memcpy(peer->name, peer_name, peer_name_len);
    peer->name_length = peer_name_len;

    ++state->num_peers;

    ck_assert(state->num_peers < NUM_GROUP_TOXES);
}

static void handle_mod(State *state, const char *peer_name, size_t peer_name_len, Tox_Group_Role role)
{
    if (state->mod_event_count == 0) {
        ck_assert(memcmp(peer_name, state->mod_name1, peer_name_len) == 0);
    } else if (state->mod_event_count == 1) {
        ck_assert(memcmp(peer_name, state->mod_name2, peer_name_len) == 0);
    } else {
        ck_assert(false);
    }

    ++state->mod_event_count;
    state->mod_check = true;
    ck_assert(role == TOX_GROUP_ROLE_MODERATOR);
}

static void handle_observer(State *state, const char *peer_name, size_t peer_name_len, Tox_Group_Role role)
{
    if (state->observer_event_count == 0) {
        ck_assert(memcmp(peer_name, state->observer_name1, peer_name_len) == 0);
    } else if (state->observer_event_count == 1) {
        ck_assert(memcmp(peer_name, state->observer_name2, peer_name_len) == 0);
    } else {
        ck_assert(false);
    }

    ++state->observer_event_count;
    state->observer_check = true;
    ck_assert(role == TOX_GROUP_ROLE_OBSERVER);
}

static void handle_user(State *state, const char *peer_name, size_t peer_name_len, Tox_Group_Role role)
{
    // event 1: observer1 gets promoted back to user
    // event 2: observer2 gets promoted to moderator
    // event 3: moderator 1 gets kicked
    // event 4: moderator 2 gets demoted to moderator
    if (state->user_event_count == 0) {
        ck_assert(memcmp(peer_name, state->observer_name1, peer_name_len) == 0);
    } else if (state->user_event_count == 1) {
        ck_assert(memcmp(peer_name, state->observer_name2, peer_name_len) == 0);
    } else if (state->user_event_count == 2) {
        ck_assert(memcmp(peer_name, state->mod_name1, peer_name_len) == 0);
    } else if (state->user_event_count == 3) {
        ck_assert(memcmp(peer_name, state->mod_name2, peer_name_len) == 0);
    } else {
        ck_assert(false);
    }

    ++state->user_event_count;
    state->user_check = true;
    ck_assert(role == TOX_GROUP_ROLE_USER);
}

static void group_mod_event_handler(Tox *tox, uint32_t group_number, uint32_t source_peer_id, uint32_t target_peer_id,
                                    Tox_Group_Mod_Event event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    ck_assert(state->group_number == group_number);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];

    Tox_Err_Group_Peer_Query q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(tox, group_number, target_peer_id, &q_err);

    if (q_err == TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND) {  // may occurr on sync attempts
        return;
    }

    ck_assert_msg(q_err == TOX_ERR_GROUP_PEER_QUERY_OK, "error %d", q_err);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    tox_group_peer_get_name(tox, group_number, target_peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;
    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    Tox_Group_Role role = tox_group_peer_get_role(tox, group_number, target_peer_id, &q_err);
    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    switch (event) {
        case TOX_GROUP_MOD_EVENT_MODERATOR: {
            handle_mod(state, peer_name, peer_name_len, role);
            break;
        }

        case TOX_GROUP_MOD_EVENT_OBSERVER: {
            handle_observer(state, peer_name, peer_name_len, role);
            break;
        }

        case TOX_GROUP_MOD_EVENT_USER: {
            handle_user(state, peer_name, peer_name_len, role);
            break;
        }

        case TOX_GROUP_MOD_EVENT_KICK: {
            ck_assert(memcmp(peer_name, state->mod_name1, peer_name_len) == 0);
            state->kick_check = true;
            break;
        }

        default: {
            ck_assert_msg(0, "Got invalid moderator event %d", event);
            return;
        }
    }
}

/* Checks that `peer_id` sees itself with the role `role`. */
static void check_self_role(AutoTox *autotoxes, uint32_t peer_id, Tox_Group_Role role)
{
    Tox_Err_Group_Self_Query sq_err;

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        State *state = (State *)autotoxes[i].state;

        uint32_t self_peer_id = tox_group_self_get_peer_id(autotoxes[i].tox, state->group_number, &sq_err);
        ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

        if (self_peer_id == peer_id) {
            Tox_Group_Role self_role = tox_group_self_get_role(autotoxes[i].tox, state->group_number, &sq_err);
            ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
            ck_assert(self_role == role);
            return;
        }
    }
}

/* Makes sure that a peer's role respects the voice state  */
static void voice_state_message_test(AutoTox *autotox, Tox_Group_Voice_State voice_state)
{
    const State *state = (State *)autotox->state;

    Tox_Err_Group_Self_Query sq_err;
    Tox_Group_Role self_role = tox_group_self_get_role(autotox->tox, state->group_number, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    Tox_Err_Group_Send_Message msg_err;
    tox_group_send_message(autotox->tox, state->group_number, TOX_MESSAGE_TYPE_NORMAL,
                           (const uint8_t *)"test", 4, &msg_err);

    switch (self_role) {
        case TOX_GROUP_ROLE_OBSERVER: {
            ck_assert(msg_err == TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS);
            break;
        }

        case TOX_GROUP_ROLE_USER: {
            if (voice_state != TOX_GROUP_VOICE_STATE_ALL) {
                ck_assert_msg(msg_err == TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS,
                              "%d", msg_err);
            } else {
                ck_assert(msg_err == TOX_ERR_GROUP_SEND_MESSAGE_OK);
            }

            break;
        }

        case TOX_GROUP_ROLE_MODERATOR: {
            if (voice_state != TOX_GROUP_VOICE_STATE_FOUNDER) {
                ck_assert(msg_err == TOX_ERR_GROUP_SEND_MESSAGE_OK);
            } else {
                ck_assert(msg_err == TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS);
            }

            break;
        }

        case TOX_GROUP_ROLE_FOUNDER: {
            ck_assert(msg_err == TOX_ERR_GROUP_SEND_MESSAGE_OK);
            break;
        }
    }
}

static bool all_peers_got_voice_state_change(AutoTox *autotoxes, uint32_t num_toxes,
        Tox_Group_Voice_State expected_voice_state)
{
    Tox_Err_Group_State_Queries query_err;

    for (uint32_t i = 0; i < num_toxes; ++i) {
        const State *state = (State *)autotoxes[i].state;

        Tox_Group_Voice_State voice_state = tox_group_get_voice_state(autotoxes[i].tox, state->group_number, &query_err);
        ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

        if (voice_state != expected_voice_state) {
            return false;
        }
    }

    return true;
}

static void check_voice_state(AutoTox *autotoxes, uint32_t num_toxes)
{
    // founder sets voice state to Moderator
    const State *state = (State *)autotoxes[0].state;
    Tox_Err_Group_Founder_Set_Voice_State voice_set_err;
    tox_group_founder_set_voice_state(autotoxes[0].tox, state->group_number, TOX_GROUP_VOICE_STATE_MODERATOR,
                                      &voice_set_err);
    ck_assert(voice_set_err == TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_OK);

    for (uint32_t i = 0; i < num_toxes; ++i) {
        do {
            iterate_all_wait(autotoxes, num_toxes, ITERATION_INTERVAL);
        } while (!all_peers_got_voice_state_change(autotoxes, num_toxes, TOX_GROUP_VOICE_STATE_MODERATOR));

        voice_state_message_test(&autotoxes[i], TOX_GROUP_VOICE_STATE_MODERATOR);
    }

    tox_group_founder_set_voice_state(autotoxes[0].tox, state->group_number, TOX_GROUP_VOICE_STATE_FOUNDER, &voice_set_err);
    ck_assert(voice_set_err == TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_OK);

    for (uint32_t i = 0; i < num_toxes; ++i) {
        do {
            iterate_all_wait(autotoxes, num_toxes, ITERATION_INTERVAL);
        } while (!all_peers_got_voice_state_change(autotoxes, num_toxes, TOX_GROUP_VOICE_STATE_FOUNDER));

        voice_state_message_test(&autotoxes[i], TOX_GROUP_VOICE_STATE_FOUNDER);
    }

    tox_group_founder_set_voice_state(autotoxes[0].tox, state->group_number, TOX_GROUP_VOICE_STATE_ALL, &voice_set_err);
    ck_assert(voice_set_err == TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_OK);

    for (uint32_t i = 0; i < num_toxes; ++i) {
        do {
            iterate_all_wait(autotoxes, num_toxes, ITERATION_INTERVAL);
        } while (!all_peers_got_voice_state_change(autotoxes, num_toxes, TOX_GROUP_VOICE_STATE_ALL));

        voice_state_message_test(&autotoxes[i], TOX_GROUP_VOICE_STATE_ALL);
    }
}

static void group_moderation_test(AutoTox *autotoxes)
{
    ck_assert_msg(NUM_GROUP_TOXES >= 4, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);
    ck_assert_msg(NUM_GROUP_TOXES < 10, "NUM_GROUP_TOXES is too big: %d", NUM_GROUP_TOXES);

    uint16_t name_length = 6;

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        State *state = (State *)autotoxes[i].state;
        state->self_name_length = name_length;
        snprintf(state->self_name, sizeof(state->self_name), "peer_%zu", i);
        state->self_name[name_length] = 0;

        tox_callback_group_join_fail(autotoxes[i].tox, group_join_fail_handler);
        tox_callback_group_peer_join(autotoxes[i].tox, group_peer_join_handler);
        tox_callback_group_moderation(autotoxes[i].tox, group_mod_event_handler);
    }

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    fprintf(stderr, "Creating new group\n");

    /* Founder makes new group */
    State *state0 = (State *)autotoxes[0].state;
    Tox *tox0 = autotoxes[0].tox;

    Tox_Err_Group_New err_new;
    state0->group_number = tox_group_new(tox0, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME,
                                         GROUP_NAME_LEN, (const uint8_t *)state0->self_name, state0->self_name_length,
                                         &err_new);

    ck_assert_msg(err_new == TOX_ERR_GROUP_NEW_OK, "Failed to create group. error: %d\n", err_new);

    /* Founder gets chat ID */
    Tox_Err_Group_State_Queries id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(tox0, state0->group_number, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get chat ID. error: %d", id_err);

    fprintf(stderr, "Peers attemping to join DHT group via the chat ID\n");

    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

        State *state = (State *)autotoxes[i].state;
        Tox_Err_Group_Join join_err;
        state->group_number = tox_group_join(autotoxes[i].tox, chat_id, (const uint8_t *)state->self_name,
                                             state->self_name_length,
                                             nullptr, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "Peer %s (%zu) failed to join group. error %d",
                      state->self_name, i, join_err);

        c_sleep(100);
    }

    // make sure every peer sees every other peer before we continue
    do {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    } while (!all_peers_connected(autotoxes));

    /* manually tell the other peers the names of the peers that will be assigned new roles */
    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        State *state = (State *)autotoxes[i].state;
        memcpy(state->mod_name1, state0->peers[0].name, sizeof(state->mod_name1));
        memcpy(state->mod_name2, state0->peers[2].name, sizeof(state->mod_name2));
        memcpy(state->observer_name1, state0->peers[1].name, sizeof(state->observer_name1));
        memcpy(state->observer_name2, state0->peers[2].name, sizeof(state->observer_name2));
    }

    /* founder checks his own role */
    Tox_Err_Group_Self_Query sq_err;
    Tox_Group_Role self_role = tox_group_self_get_role(tox0, state0->group_number, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_role == TOX_GROUP_ROLE_FOUNDER);

    /* all peers should be user role except founder */
    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        State *state = (State *)autotoxes[i].state;
        self_role = tox_group_self_get_role(autotoxes[i].tox, state->group_number, &sq_err);
        ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
        ck_assert(self_role == TOX_GROUP_ROLE_USER);
    }

    /* founder sets first peer to moderator */
    fprintf(stderr, "Founder setting %s to moderator\n", state0->peers[0].name);

    Tox_Err_Group_Mod_Set_Role role_err;
    tox_group_mod_set_role(tox0, state0->group_number, state0->peers[0].peer_id, TOX_GROUP_ROLE_MODERATOR, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set moderator. error: %d", role_err);

    // manually flag the role setter because they don't get a callback
    state0->mod_check = true;
    ++state0->mod_event_count;
    check_mod_event(autotoxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_MODERATOR);

    check_self_role(autotoxes, state0->peers[0].peer_id, TOX_GROUP_ROLE_MODERATOR);

    fprintf(stderr, "All peers successfully received mod event\n");

    /* founder sets second and third peer to observer */
    fprintf(stderr, "Founder setting %s to observer\n", state0->peers[1].name);

    tox_group_mod_set_role(tox0, state0->group_number, state0->peers[1].peer_id, TOX_GROUP_ROLE_OBSERVER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set observer. error: %d", role_err);

    state0->observer_check = true;
    ++state0->observer_event_count;
    check_mod_event(autotoxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_OBSERVER);

    fprintf(stderr, "All peers successfully received observer event 1\n");

    fprintf(stderr, "Founder setting %s to observer\n", state0->peers[2].name);

    tox_group_mod_set_role(tox0, state0->group_number, state0->peers[2].peer_id, TOX_GROUP_ROLE_OBSERVER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set observer. error: %d", role_err);

    state0->observer_check = true;
    ++state0->observer_event_count;
    check_mod_event(autotoxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_OBSERVER);

    check_self_role(autotoxes, state0->peers[1].peer_id, TOX_GROUP_ROLE_OBSERVER);

    fprintf(stderr, "All peers successfully received observer event 2\n");

    /* do voice state test here since we have at least one peer of each role */
    check_voice_state(autotoxes, NUM_GROUP_TOXES);

    fprintf(stderr, "Voice state respected by all peers\n");

    /* New moderator promotes second peer back to user */
    const uint32_t idx = get_state_index_by_nick(autotoxes, NUM_GROUP_TOXES, state0->peers[0].name,
                         state0->peers[0].name_length);
    State *state1 = (State *)autotoxes[idx].state;
    Tox *tox1 = autotoxes[idx].tox;

    const uint32_t obs_peer_id = get_peer_id_by_nick(state1->peers, NUM_GROUP_TOXES - 1, state1->observer_name1);

    fprintf(stderr, "%s is promoting %s back to user\n", state1->self_name, state0->peers[1].name);

    tox_group_mod_set_role(tox1, state1->group_number, obs_peer_id, TOX_GROUP_ROLE_USER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to promote observer back to user. error: %d",
                  role_err);

    state1->user_check = true;
    ++state1->user_event_count;
    check_mod_event(autotoxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_USER);

    fprintf(stderr, "All peers successfully received user event\n");

    /* founder assigns third peer to moderator (this triggers two events: user and moderator) */
    fprintf(stderr, "Founder setting %s to moderator\n", state0->peers[2].name);

    tox_group_mod_set_role(tox0, state0->group_number, state0->peers[2].peer_id, TOX_GROUP_ROLE_MODERATOR, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set moderator. error: %d", role_err);

    state0->mod_check = true;
    ++state0->mod_event_count;
    check_mod_event(autotoxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_MODERATOR);

    check_self_role(autotoxes, state0->peers[2].peer_id, TOX_GROUP_ROLE_MODERATOR);

    fprintf(stderr, "All peers successfully received moderator event\n");

    /* moderator attempts to demote and kick founder */
    uint32_t founder_peer_id = get_peer_id_by_nick(state1->peers, NUM_GROUP_TOXES - 1, state0->self_name);
    tox_group_mod_set_role(tox1, state1->group_number, founder_peer_id, TOX_GROUP_ROLE_OBSERVER, &role_err);
    ck_assert_msg(role_err != TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Mod set founder to observer");

    Tox_Err_Group_Mod_Kick_Peer k_err;
    tox_group_mod_kick_peer(tox1, state1->group_number, founder_peer_id, &k_err);
    ck_assert_msg(k_err != TOX_ERR_GROUP_MOD_KICK_PEER_OK, "Mod kicked founder");

    /* founder kicks moderator (this triggers two events: user and kick) */
    fprintf(stderr, "Founder is kicking %s\n", state0->peers[0].name);

    tox_group_mod_kick_peer(tox0, state0->group_number, state0->peers[0].peer_id, &k_err);
    ck_assert_msg(k_err == TOX_ERR_GROUP_MOD_KICK_PEER_OK, "Failed to kick peer. error: %d", k_err);

    state0->kick_check = true;
    check_mod_event(autotoxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_KICK);

    fprintf(stderr, "All peers successfully received kick event\n");

    fprintf(stderr, "Founder is demoting moderator to user\n");

    tox_group_mod_set_role(tox0, state0->group_number, state0->peers[2].peer_id, TOX_GROUP_ROLE_USER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to demote peer 3 to User. error: %d", role_err);

    state0->user_check = true;
    ++state0->user_event_count;

    check_mod_event(autotoxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_USER);
    check_self_role(autotoxes, state0->peers[2].peer_id, TOX_GROUP_ROLE_USER);

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        const State *state = (const State *)autotoxes[i].state;
        Tox_Err_Group_Leave err_exit;
        tox_group_leave(autotoxes[i].tox, state->group_number, nullptr, 0, &err_exit);
        ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
    }

    fprintf(stderr, "All tests passed!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_COMPLETE;

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_moderation_test, sizeof(State), &options);
    return 0;
}

#undef NUM_GROUP_TOXES
#undef GROUP_NAME
#undef GROUP_NAME_LEN
