/*
 * Tests that we can connect to a public group chat through the DHT and make basic queries
 * about the group, other peers, and ourselves. We also make sure we can disconnect and
 * reconnect to a group while retaining our credentials.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "auto_test_support.h"
#include "../toxcore/tox_private.h"

typedef struct State {
    size_t   peer_joined_count;
    size_t   self_joined_count;
    size_t   peer_exit_count;
    bool     peer_nick;
    bool     peer_status;
    uint32_t peer_id;
    bool     is_founder;
} State;

#define NUM_GROUP_TOXES 2

#define GROUP_NAME "NASA Headquarters"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

#define TOPIC "Funny topic here"
#define TOPIC_LEN (sizeof(TOPIC) - 1)

#define PEER0_NICK "Lois"
#define PEER0_NICK_LEN (sizeof(PEER0_NICK) - 1)

#define PEER0_NICK2 "Terry Davis"
#define PEER0_NICK2_LEN (sizeof(PEER0_NICK2) - 1)

#define PEER1_NICK "Bran"
#define PEER1_NICK_LEN (sizeof(PEER1_NICK) - 1)

#define EXIT_MESSAGE "Goodbye world"
#define EXIT_MESSAGE_LEN (sizeof(EXIT_MESSAGE) - 1)

#define PEER_LIMIT 20

static void print_ip(const Tox *tox, uint32_t groupnumber, uint32_t peer_id)
{
    Tox_Err_Group_Peer_Query err;
    size_t length = tox_group_peer_get_ip_address_size(tox, groupnumber, peer_id, &err);

    ck_assert_msg(err == TOX_ERR_GROUP_PEER_QUERY_OK, "failed to get ip address size: error %d", err);

    uint8_t ip_str[TOX_GROUP_PEER_IP_STRING_MAX_LENGTH];
    tox_group_peer_get_ip_address(tox, groupnumber, peer_id, ip_str, &err);
    ip_str[length] = '\0';

    ck_assert_msg(err == TOX_ERR_GROUP_PEER_QUERY_OK, "failed to get ip address: error %d", err);

    fprintf(stderr, "%s\n", ip_str);
}

static bool all_group_peers_connected(AutoTox *autotoxes, uint32_t tox_count, uint32_t groupnumber, size_t name_length)
{
    for (size_t i = 0; i < tox_count; ++i) {
        // make sure we got an invite response
        if (tox_group_get_name_size(autotoxes[i].tox, groupnumber, nullptr) != name_length) {
            return false;
        }

        // make sure we got a sync response
        if (tox_group_get_peer_limit(autotoxes[i].tox, groupnumber, nullptr) != PEER_LIMIT) {
            return false;
        }

        // make sure we're actually connected
        if (!tox_group_is_connected(autotoxes[i].tox, groupnumber, nullptr)) {
            return false;
        }
    }

    return true;
}

static void group_peer_join_handler(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint32_t groupnumber = tox_event_group_peer_join_get_group_number(event);
    const uint32_t peer_id = tox_event_group_peer_join_get_peer_id(event);

    // we do a connection test here for fun
    Tox_Err_Group_Peer_Query pq_err;
    Tox_Connection connection_status = tox_group_peer_get_connection_status(autotox->tox, groupnumber, peer_id, &pq_err);
    ck_assert(pq_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(connection_status != TOX_CONNECTION_NONE);

    Tox_Group_Role role = tox_group_peer_get_role(autotox->tox, groupnumber, peer_id, &pq_err);
    ck_assert_msg(pq_err == TOX_ERR_GROUP_PEER_QUERY_OK, "%d", pq_err);

    Tox_User_Status status = tox_group_peer_get_status(autotox->tox, groupnumber, peer_id, &pq_err);
    ck_assert_msg(pq_err == TOX_ERR_GROUP_PEER_QUERY_OK, "%d", pq_err);

    size_t peer_name_len = tox_group_peer_get_name_size(autotox->tox, groupnumber, peer_id, &pq_err);
    char peer_name[TOX_MAX_NAME_LENGTH + 1];

    ck_assert(pq_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    tox_group_peer_get_name(autotox->tox, groupnumber, peer_id, (uint8_t *)peer_name, &pq_err);
    ck_assert(pq_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    peer_name[peer_name_len] = 0;

    // make sure we see the correct peer state on join
    if (!state->is_founder) {
        ck_assert_msg(role == TOX_GROUP_ROLE_FOUNDER, "wrong role: %d", role);

        if (state->peer_joined_count == 0) {
            ck_assert_msg(status == TOX_USER_STATUS_NONE, "wrong status: %d", status);
            ck_assert_msg(peer_name_len == PEER0_NICK_LEN, "wrong nick: %s", peer_name);
            ck_assert(memcmp(peer_name, PEER0_NICK, peer_name_len) == 0);
        } else {
            ck_assert_msg(status == TOX_USER_STATUS_BUSY, "wrong status: %d", status);
            ck_assert(peer_name_len == PEER0_NICK2_LEN);
            ck_assert(memcmp(peer_name, PEER0_NICK2, peer_name_len) == 0);
        }
    } else {
        ck_assert_msg(role == TOX_GROUP_ROLE_USER, "wrong role: %d", role);
        ck_assert(peer_name_len == PEER1_NICK_LEN);
        ck_assert(memcmp(peer_name, PEER1_NICK, peer_name_len) == 0);

        if (state->peer_joined_count == 0) {
            ck_assert_msg(status == TOX_USER_STATUS_NONE, "wrong status: %d", status);
        } else {
            ck_assert_msg(status == TOX_USER_STATUS_AWAY, "wrong status: %d", status);
        }
    }

    fprintf(stderr, "%s joined with IP: ", peer_name);
    print_ip(autotox->tox, groupnumber, peer_id);

    state->peer_id = peer_id;
    ++state->peer_joined_count;
}

static void group_peer_self_join_handler(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint32_t groupnumber = tox_event_group_self_join_get_group_number(event);

    // make sure we see our own correct peer state on join callback

    Tox_Err_Group_Self_Query sq_err;
    size_t self_length = tox_group_self_get_name_size(autotox->tox, groupnumber, &sq_err);

    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    uint8_t self_name[TOX_MAX_NAME_LENGTH];
    tox_group_self_get_name(autotox->tox, groupnumber, self_name, &sq_err);

    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    Tox_User_Status self_status = tox_group_self_get_status(autotox->tox, groupnumber, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    Tox_Group_Role self_role = tox_group_self_get_role(autotox->tox, groupnumber, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    if (state->is_founder) {
        // founder doesn't get a self join callback on initial creation of group
        ck_assert(self_length == PEER0_NICK2_LEN);
        ck_assert(memcmp(self_name, PEER0_NICK2, self_length) == 0);
        ck_assert(self_status == TOX_USER_STATUS_BUSY);
        ck_assert(self_role == TOX_GROUP_ROLE_FOUNDER);
    } else {
        ck_assert(self_length == PEER1_NICK_LEN);
        ck_assert(memcmp(self_name, PEER1_NICK, self_length) == 0);
        ck_assert(self_role == TOX_GROUP_ROLE_USER);
        ck_assert(self_status == TOX_USER_STATUS_NONE);
    }

    // make sure we see correct group state on join callback
    uint8_t group_name[GROUP_NAME_LEN];
    uint8_t topic[TOX_GROUP_MAX_TOPIC_LENGTH];

    ck_assert(tox_group_get_peer_limit(autotox->tox, groupnumber, nullptr) == PEER_LIMIT);
    ck_assert(tox_group_get_name_size(autotox->tox, groupnumber, nullptr) == GROUP_NAME_LEN);
    ck_assert(tox_group_get_topic_size(autotox->tox, groupnumber, nullptr) == TOPIC_LEN);

    Tox_Err_Group_State_Query query_err;
    tox_group_get_name(autotox->tox, groupnumber, group_name, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERY_OK, "%d", query_err);
    ck_assert(memcmp(group_name, GROUP_NAME, GROUP_NAME_LEN) == 0);

    tox_group_get_topic(autotox->tox, groupnumber, topic, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERY_OK, "%d", query_err);
    ck_assert(memcmp(topic, TOPIC, TOPIC_LEN) == 0);

    uint32_t peer_id = tox_group_self_get_peer_id(autotox->tox, groupnumber, nullptr);

    fprintf(stderr, "self joined with IP: ");
    print_ip(autotox->tox, groupnumber, peer_id);

    ++state->self_joined_count;
}

static void group_peer_exit_handler(const Tox_Event_Group_Peer_Exit *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint8_t *part_message = tox_event_group_peer_exit_get_part_message(event);
    const size_t length = tox_event_group_peer_exit_get_part_message_length(event);

    ++state->peer_exit_count;

    // first exit is a disconnect. second is a real exit with a part message
    if (state->peer_exit_count == 2) {
        ck_assert(length == EXIT_MESSAGE_LEN);
        ck_assert(memcmp(part_message, EXIT_MESSAGE, length) == 0);
    }
}

static void group_peer_name_handler(const Tox_Event_Group_Peer_Name *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint8_t *name = tox_event_group_peer_name_get_name(event);
    const size_t length = tox_event_group_peer_name_get_name_length(event);

    // note: we already test the name_get api call elsewhere

    ck_assert(length == PEER0_NICK2_LEN);
    ck_assert(memcmp(name, PEER0_NICK2, length) == 0);

    state->peer_nick = true;
}

static void group_peer_status_handler(const Tox_Event_Group_Peer_Status *event,
                                      void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint32_t groupnumber = tox_event_group_peer_status_get_group_number(event);
    const uint32_t peer_id = tox_event_group_peer_status_get_peer_id(event);
    const Tox_User_Status status = tox_event_group_peer_status_get_status(event);

    Tox_Err_Group_Peer_Query err;
    Tox_User_Status cur_status = tox_group_peer_get_status(autotox->tox, groupnumber, peer_id, &err);

    ck_assert_msg(cur_status == status, "%d, %d", cur_status, status);
    ck_assert(status == TOX_USER_STATUS_BUSY);

    state->peer_status = true;
}

static void group_announce_test(AutoTox *autotoxes)
{
    ck_assert_msg(NUM_GROUP_TOXES == 2, "NUM_GROUP_TOXES needs to be 2");

    Tox *tox0 = autotoxes[0].tox;
    Tox *tox1 = autotoxes[1].tox;
    State *state0 = (State *)autotoxes[0].state;
    const State *state1 = (const State *)autotoxes[1].state;

    tox_events_callback_group_peer_join(autotoxes[0].dispatch, group_peer_join_handler);
    tox_events_callback_group_peer_join(autotoxes[1].dispatch, group_peer_join_handler);
    tox_events_callback_group_self_join(autotoxes[0].dispatch, group_peer_self_join_handler);
    tox_events_callback_group_self_join(autotoxes[1].dispatch, group_peer_self_join_handler);
    tox_events_callback_group_peer_name(autotoxes[1].dispatch, group_peer_name_handler);
    tox_events_callback_group_peer_status(autotoxes[1].dispatch, group_peer_status_handler);
    tox_events_callback_group_peer_exit(autotoxes[1].dispatch, group_peer_exit_handler);

    // tox0 makes new group.
    Tox_Err_Group_New err_new;
    uint32_t groupnumber = tox_group_new(tox0, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *) GROUP_NAME,
                                         GROUP_NAME_LEN, (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN,
                                         &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    state0->is_founder = true;

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    // changes the state (for sync check purposes)
    Tox_Err_Group_Set_Peer_Limit limit_set_err;
    tox_group_set_peer_limit(tox0, groupnumber, PEER_LIMIT, &limit_set_err);
    ck_assert_msg(limit_set_err == TOX_ERR_GROUP_SET_PEER_LIMIT_OK, "failed to set peer limit: %d", limit_set_err);

    Tox_Err_Group_Topic_Set tp_err;
    tox_group_set_topic(tox0, groupnumber, (const uint8_t *)TOPIC, TOPIC_LEN, &tp_err);
    ck_assert(tp_err == TOX_ERR_GROUP_TOPIC_SET_OK);

    // get the chat id of the new group.
    Tox_Err_Group_State_Query err_id;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(tox0, groupnumber, chat_id, &err_id);
    ck_assert(err_id == TOX_ERR_GROUP_STATE_QUERY_OK);

    // tox1 joins it.
    Tox_Err_Group_Join err_join;
    tox_group_join(tox1, chat_id, (const uint8_t *)PEER1_NICK, PEER1_NICK_LEN, nullptr, 0, &err_join);
    ck_assert(err_join == TOX_ERR_GROUP_JOIN_OK);

    // peers see each other and themselves join
    while (!state1->peer_joined_count || !state1->self_joined_count || !state0->peer_joined_count) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    // wait for group syncing to finish
    while (!all_group_peers_connected(autotoxes, NUM_GROUP_TOXES, groupnumber, GROUP_NAME_LEN)) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    fprintf(stderr, "Peers connected to group\n");

    // tox 0 changes name
    Tox_Err_Group_Self_Name_Set n_err;
    tox_group_self_set_name(tox0, groupnumber, (const uint8_t *)PEER0_NICK2, PEER0_NICK2_LEN, &n_err);
    ck_assert(n_err == TOX_ERR_GROUP_SELF_NAME_SET_OK);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    Tox_Err_Group_Self_Query sq_err;
    size_t self_length = tox_group_self_get_name_size(tox0, groupnumber, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_length == PEER0_NICK2_LEN);

    uint8_t self_name[TOX_MAX_NAME_LENGTH];
    tox_group_self_get_name(tox0, groupnumber, self_name, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(self_name, PEER0_NICK2, self_length) == 0);

    fprintf(stderr, "Peer 0 successfully changed nick\n");

    // tox 0 changes status
    Tox_Err_Group_Self_Status_Set s_err;
    tox_group_self_set_status(tox0, groupnumber, TOX_USER_STATUS_BUSY, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_STATUS_SET_OK);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    Tox_User_Status self_status = tox_group_self_get_status(tox0, groupnumber, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_status == TOX_USER_STATUS_BUSY);

    fprintf(stderr, "Peer 0 successfully changed status to %d\n", self_status);

    while (!state1->peer_nick && !state1->peer_status) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    // tox 0 and tox 1 should see the same public key for tox 0
    uint8_t tox0_self_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    tox_group_self_get_public_key(tox0, groupnumber, tox0_self_pk, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    Tox_Err_Group_Peer_Query pq_err;
    uint8_t tox0_pk_query[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    tox_group_peer_get_public_key(tox1, groupnumber, state1->peer_id, tox0_pk_query, &pq_err);
    ck_assert(pq_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(memcmp(tox0_pk_query, tox0_self_pk, TOX_GROUP_PEER_PUBLIC_KEY_SIZE) == 0);

    fprintf(stderr, "Peer 0 disconnecting...\n");

    // tox 0 disconnects then reconnects
    Tox_Err_Group_Disconnect d_err;
    tox_group_disconnect(tox0, groupnumber, &d_err);
    ck_assert(d_err == TOX_ERR_GROUP_DISCONNECT_OK);

    while (state1->peer_exit_count != 1) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    // tox 1 changes status while alone in the group
    tox_group_self_set_status(tox1, groupnumber, TOX_USER_STATUS_AWAY, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_STATUS_SET_OK);

    fprintf(stderr, "Peer 0 reconnecting...\n");
    Tox_Err_Group_Reconnect r_err;
    tox_group_reconnect(tox0, groupnumber, &r_err);
    ck_assert(r_err == TOX_ERR_GROUP_RECONNECT_OK);

    while (state1->peer_joined_count != 2 && state0->self_joined_count == 2) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    for (size_t i = 0; i < 100; ++i) {  // if we don't do this the exit packet never arrives
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    while (!all_group_peers_connected(autotoxes, NUM_GROUP_TOXES, groupnumber, GROUP_NAME_LEN))  {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    // tox 0 should have the same public key and still be founder
    uint8_t tox0_self_pk2[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    tox_group_self_get_public_key(tox0, groupnumber, tox0_self_pk2, &sq_err);

    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(tox0_self_pk2, tox0_self_pk, TOX_GROUP_PEER_PUBLIC_KEY_SIZE) == 0);

    Tox_Group_Role self_role = tox_group_self_get_role(tox0, groupnumber, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    Tox_Group_Role other_role = tox_group_peer_get_role(tox1, groupnumber, state1->peer_id, &pq_err);
    ck_assert(pq_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    ck_assert(self_role == other_role && self_role == TOX_GROUP_ROLE_FOUNDER);

    uint32_t num_groups1 = tox_group_get_number_groups(tox0);
    uint32_t num_groups2 = tox_group_get_number_groups(tox1);

    ck_assert(num_groups1 == num_groups2 && num_groups2 == 1);

    fprintf(stderr, "Both peers exiting group...\n");

    Tox_Err_Group_Leave err_exit;
    tox_group_leave(tox0, groupnumber, (const uint8_t *)EXIT_MESSAGE, EXIT_MESSAGE_LEN, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);

    while (state1->peer_exit_count != 2) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    tox_group_leave(tox1, groupnumber, nullptr, 0, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);

    while (num_groups1 != 0 || num_groups2 != 0) {
        num_groups1 = tox_group_get_number_groups(tox0);
        num_groups2 = tox_group_get_number_groups(tox1);

        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    printf("All tests passed!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_announce_test, sizeof(State), &options);

    return 0;
}

#undef NUM_GROUP_TOXES
#undef PEER1_NICK
#undef PEER0_NICK
#undef PEER0_NICK_LEN
#undef PEER1_NICK_LEN
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef PEER_LIMIT
#undef TOPIC
#undef TOPIC_LEN
