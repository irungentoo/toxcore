/*
 * Does a basic functionality test for TCP connections.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "auto_test_support.h"

#define NUM_GROUP_TOXES 2
#define CODEWORD "RONALD MCDONALD"
#define CODEWORD_LEN (sizeof(CODEWORD) - 1)

typedef struct State {
    size_t   num_peers;
    bool     got_code;
    bool     got_second_code;
    uint32_t peer_id[NUM_GROUP_TOXES - 1];
} State;

static void group_invite_handler(const Tox_Event_Group_Invite *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    const uint32_t friend_number = tox_event_group_invite_get_friend_number(event);
    const uint8_t *invite_data = tox_event_group_invite_get_invite_data(event);
    const size_t length = tox_event_group_invite_get_invite_data_length(event);

    printf("Accepting friend invite\n");

    Tox_Err_Group_Invite_Accept err_accept;
    tox_group_invite_accept(autotox->tox, friend_number, invite_data, length, (const uint8_t *)"test", 4,
                            nullptr, 0, &err_accept);
    ck_assert(err_accept == TOX_ERR_GROUP_INVITE_ACCEPT_OK);
}

static void group_peer_join_handler(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint32_t peer_id = tox_event_group_peer_join_get_peer_id(event);

    fprintf(stderr, "joined: %zu, %u\n", state->num_peers, peer_id);
    ck_assert_msg(state->num_peers < NUM_GROUP_TOXES - 1, "%zu", state->num_peers);

    state->peer_id[state->num_peers++] = peer_id;
}

static void group_private_message_handler(const Tox_Event_Group_Private_Message *event, void *user_data)
{
    const uint8_t *message = tox_event_group_private_message_get_message(event);
    const size_t length = tox_event_group_private_message_get_message_length(event);

    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    ck_assert(length == CODEWORD_LEN);
    ck_assert(memcmp(CODEWORD, message, length) == 0);

    printf("Codeword: %s\n", CODEWORD);

    state->got_code = true;
}

static void group_message_handler(const Tox_Event_Group_Message *event, void *user_data)
{
    const uint8_t *message = tox_event_group_message_get_message(event);
    const size_t length = tox_event_group_message_get_message_length(event);

    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    ck_assert(length == CODEWORD_LEN);
    ck_assert(memcmp(CODEWORD, message, length) == 0);

    printf("Codeword: %s\n", CODEWORD);

    state->got_second_code = true;
}

/*
 * We need different constants to make TCP run smoothly. TODO(Jfreegman): is this because of the group
 * implementation or just an autotest quirk?
 */
#define GROUP_ITERATION_INTERVAL 100
static void iterate_group(AutoTox *autotoxes, uint32_t num_toxes, size_t interval)
{
    for (uint32_t i = 0; i < num_toxes; i++) {
        if (autotoxes[i].alive) {
            tox_iterate(autotoxes[i].tox, &autotoxes[i]);
            autotoxes[i].clock += interval;
        }
    }

    c_sleep(50);
}

static bool all_peers_connected(AutoTox *autotoxes)
{
    iterate_group(autotoxes, NUM_GROUP_TOXES, GROUP_ITERATION_INTERVAL);

    size_t count = 0;

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        const State *state = (const State *)autotoxes[i].state;

        if (state->num_peers == NUM_GROUP_TOXES - 1) {
            ++count;
        }
    }

    return count == NUM_GROUP_TOXES;
}

static bool all_peers_got_code(AutoTox *autotoxes)
{
    iterate_group(autotoxes, NUM_GROUP_TOXES, GROUP_ITERATION_INTERVAL);

    size_t count = 0;

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        const State *state = (const State *)autotoxes[i].state;

        if (state->got_code) {
            ++count;
        }
    }

    return count == NUM_GROUP_TOXES - 1;
}

static void group_tcp_test(AutoTox *autotoxes)
{
    ck_assert(NUM_GROUP_TOXES >= 2);

    State *state0 = (State *)autotoxes[0].state;
    State *state1 = (State *)autotoxes[1].state;

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_events_callback_group_peer_join(autotoxes[i].dispatch, group_peer_join_handler);
        tox_events_callback_group_private_message(autotoxes[i].dispatch, group_private_message_handler);
    }

    tox_events_callback_group_message(autotoxes[1].dispatch, group_message_handler);
    tox_events_callback_group_invite(autotoxes[1].dispatch, group_invite_handler);

    Tox_Err_Group_New new_err;
    uint32_t groupnumber = tox_group_new(autotoxes[0].tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)"test", 4,
                                         (const uint8_t *)"test", 4, &new_err);
    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    iterate_group(autotoxes, NUM_GROUP_TOXES, GROUP_ITERATION_INTERVAL);

    Tox_Err_Group_State_Query id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];

    tox_group_get_chat_id(autotoxes[0].tox, groupnumber, chat_id, &id_err);
    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERY_OK, "%d", id_err);

    printf("Tox 0 created new group...\n");

    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        Tox_Err_Group_Join jerr;
        tox_group_join(autotoxes[i].tox, chat_id, (const uint8_t *)"test", 4, nullptr, 0, &jerr);
        ck_assert_msg(jerr == TOX_ERR_GROUP_JOIN_OK, "%d", jerr);
        iterate_group(autotoxes, NUM_GROUP_TOXES, GROUP_ITERATION_INTERVAL * 10);
    }

    while (!all_peers_connected(autotoxes))
        ;

    printf("%d peers successfully joined. Waiting for code...\n", NUM_GROUP_TOXES);
    printf("Tox 0 sending secret code to all peers\n");

    for (size_t i = 0; i < NUM_GROUP_TOXES - 1; ++i) {

        Tox_Err_Group_Send_Private_Message perr;
        tox_group_send_private_message(autotoxes[0].tox, groupnumber, state0->peer_id[i],
                                       TOX_MESSAGE_TYPE_NORMAL,
                                       (const uint8_t *)CODEWORD, CODEWORD_LEN, &perr);
        ck_assert_msg(perr == TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK, "%d", perr);
    }

    while (!all_peers_got_code(autotoxes))
        ;

    Tox_Err_Group_Leave err_exit;
    tox_group_leave(autotoxes[1].tox, groupnumber, nullptr, 0, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);

    iterate_group(autotoxes, NUM_GROUP_TOXES, GROUP_ITERATION_INTERVAL);

    state0->num_peers = 0;
    state1->num_peers = 0;

    // now do a friend invite to make sure the TCP-specific logic for friend invites is okay

    printf("Tox1 leaves group and Tox0 does a friend group invite for tox1\n");

    Tox_Err_Group_Invite_Friend err_invite;
    tox_group_invite_friend(autotoxes[0].tox, groupnumber, 0, &err_invite);
    ck_assert(err_invite == TOX_ERR_GROUP_INVITE_FRIEND_OK);

    while (state0->num_peers == 0 && state1->num_peers == 0) {
        iterate_group(autotoxes, NUM_GROUP_TOXES, GROUP_ITERATION_INTERVAL);
    }

    printf("Tox 1 successfully joined. Waiting for code...\n");

    Tox_Err_Group_Send_Message merr;
    tox_group_send_message(autotoxes[0].tox, groupnumber, TOX_MESSAGE_TYPE_NORMAL,
                           (const uint8_t *)CODEWORD, CODEWORD_LEN, &merr);
    ck_assert(merr == TOX_ERR_GROUP_SEND_MESSAGE_OK);

    while (!state1->got_second_code) {
        iterate_group(autotoxes, NUM_GROUP_TOXES, GROUP_ITERATION_INTERVAL);
    }

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        tox_group_leave(autotoxes[i].tox, groupnumber, nullptr, 0, &err_exit);
        ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
    }

    printf("Test passed!\n");
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *options = tox_options_new(nullptr);
    ck_assert(options != nullptr);

    tox_options_set_udp_enabled(options, false);

    Run_Auto_Options autotest_opts = default_run_auto_options();
    autotest_opts.graph = GRAPH_COMPLETE;

    // TODO(JFreegman): Fix this test and remove the "if".
    if (argc > 2) {
        run_auto_test(options, NUM_GROUP_TOXES, group_tcp_test, sizeof(State), &autotest_opts);
    }

    tox_options_free(options);
    return 0;
}

#undef CODEWORD_LEN
#undef CODEWORD
#undef NUM_GROUP_TOXES
