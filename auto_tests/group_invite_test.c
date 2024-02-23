/*
 * Tests group invites as well as join restrictions, including password protection, privacy state,
 * and peer limits. Ensures sure that the peer being blocked from joining successfully receives
 * the invite fail packet with the correct message.
 *
 * This test also checks that many peers can successfully join the group simultaneously.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "auto_test_support.h"
#include "check_compat.h"

typedef struct State {
    uint32_t num_peers;
    bool peer_limit_fail;
    bool password_fail;
    bool connected;
    size_t messages_received;
} State;

#define NUM_GROUP_TOXES 8  // must be > 7

#define PASSWORD "dadada"
#define PASS_LEN (sizeof(PASSWORD) - 1)

#define WRONG_PASS "dadadada"
#define WRONG_PASS_LEN (sizeof(WRONG_PASS) - 1)

static bool group_has_full_graph(const AutoTox *autotoxes, uint32_t group_number, uint32_t expected_peer_count)
{
    for (size_t i = 7; i < NUM_GROUP_TOXES; ++i) {
        const State *state = (const State *)autotoxes[i].state;

        if (state->num_peers < expected_peer_count) {
            return false;
        }
    }

    const State *state0 = (const State *)autotoxes[0].state;
    const State *state1 = (const State *)autotoxes[1].state;
    const State *state5 = (const State *)autotoxes[5].state;

    if (state0->num_peers < expected_peer_count || state1->num_peers < expected_peer_count
            || state5->num_peers < expected_peer_count) {
        return false;
    }

    return true;
}

static void group_join_fail_handler(const Tox_Event_Group_Join_Fail *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const Tox_Group_Join_Fail fail_type = tox_event_group_join_fail_get_fail_type(event);

    switch (fail_type) {
        case TOX_GROUP_JOIN_FAIL_PEER_LIMIT: {
            state->peer_limit_fail = true;
            break;
        }

        case TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD: {
            state->password_fail = true;
            break;
        }

        case TOX_GROUP_JOIN_FAIL_UNKNOWN:

        // intentional fallthrough
        default: {
            ck_assert_msg(false, "Got unknown join fail");
            return;
        }
    }
}

static void group_self_join_handler(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    state->connected = true;
}

static void group_peer_join_handler(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    ++state->num_peers;
    ck_assert(state->num_peers < NUM_GROUP_TOXES);
}

static void group_invite_test(AutoTox *autotoxes)
{
    ck_assert_msg(NUM_GROUP_TOXES > 7, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_events_callback_group_peer_join(autotoxes[i].dispatch, group_peer_join_handler);
        tox_events_callback_group_join_fail(autotoxes[i].dispatch, group_join_fail_handler);
        tox_events_callback_group_self_join(autotoxes[i].dispatch, group_self_join_handler);
    }

    Tox *tox0 = autotoxes[0].tox;
    Tox *tox1 = autotoxes[1].tox;
    Tox *tox2 = autotoxes[2].tox;
    Tox *tox3 = autotoxes[3].tox;
    Tox *tox4 = autotoxes[4].tox;
    Tox *tox5 = autotoxes[5].tox;
    Tox *tox6 = autotoxes[6].tox;

    const State *state0 = (const State *)autotoxes[0].state;
    const State *state2 = (const State *)autotoxes[2].state;
    const State *state3 = (const State *)autotoxes[3].state;
    const State *state4 = (const State *)autotoxes[4].state;
    const State *state5 = (const State *)autotoxes[5].state;
    const State *state6 = (const State *)autotoxes[6].state;

    Tox_Err_Group_New new_err;
    uint32_t groupnumber = tox_group_new(tox0, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)"test", 4,
                                         (const uint8_t *)"test", 4, &new_err);
    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    Tox_Err_Group_State_Query id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];

    tox_group_get_chat_id(tox0, groupnumber, chat_id, &id_err);
    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERY_OK, "%d", id_err);

    // peer 1 joins public group with no password
    Tox_Err_Group_Join join_err;
    tox_group_join(tox1, chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (state0->num_peers < 1) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    printf("Peer 1 joined group\n");

    // founder sets a password
    Tox_Err_Group_Set_Password pass_set_err;
    tox_group_set_password(tox0, groupnumber, (const uint8_t *)PASSWORD, PASS_LEN, &pass_set_err);
    ck_assert_msg(pass_set_err == TOX_ERR_GROUP_SET_PASSWORD_OK, "%d", pass_set_err);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, 5000);

    // peer 2 attempts to join with no password
    tox_group_join(tox2, chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (!state2->password_fail) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    printf("Peer 2 successfully blocked with no password\n");

    // peer 3 attempts to join with invalid password
    tox_group_join(tox3, chat_id, (const uint8_t *)"Test", 4, (const uint8_t *)WRONG_PASS, WRONG_PASS_LEN, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (!state3->password_fail) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    printf("Peer 3 successfully blocked with invalid password\n");

    // founder sets peer limit to 1
    Tox_Err_Group_Set_Peer_Limit limit_set_err;
    tox_group_set_peer_limit(tox0, groupnumber, 1, &limit_set_err);
    ck_assert_msg(limit_set_err == TOX_ERR_GROUP_SET_PEER_LIMIT_OK, "%d", limit_set_err);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, 5000);

    // peer 4 attempts to join with correct password
    tox_group_join(tox4, chat_id, (const uint8_t *)"Test", 4, (const uint8_t *)PASSWORD, PASS_LEN, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (!state4->peer_limit_fail) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    printf("Peer 4 successfully blocked from joining full group\n");

    // founder removes password and increases peer limit to 100
    tox_group_set_password(tox0, groupnumber, nullptr, 0, &pass_set_err);
    ck_assert_msg(pass_set_err == TOX_ERR_GROUP_SET_PASSWORD_OK, "%d", pass_set_err);

    tox_group_set_peer_limit(tox0, groupnumber, 100, &limit_set_err);
    ck_assert_msg(limit_set_err == TOX_ERR_GROUP_SET_PEER_LIMIT_OK, "%d", limit_set_err);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, 5000);

    // peer 5 attempts to join group
    tox_group_join(tox5, chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (!state5->connected) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    printf("Peer 5 successfully joined the group\n");

    // founder makes group private
    Tox_Err_Group_Set_Privacy_State priv_err;
    tox_group_set_privacy_state(tox0, groupnumber, TOX_GROUP_PRIVACY_STATE_PRIVATE, &priv_err);
    ck_assert_msg(priv_err == TOX_ERR_GROUP_SET_PRIVACY_STATE_OK, "%d", priv_err);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, 5000);

    // peer 6 attempts to join group via chat ID
    tox_group_join(tox6, chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    // since we don't receive a fail packet in this case we just wait a while and check if we're in the group
    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, 20000);

    ck_assert(!state6->connected);

    printf("Peer 6 failed to join private group via chat ID\n");

    // founder makes group public again
    tox_group_set_privacy_state(tox0, groupnumber, TOX_GROUP_PRIVACY_STATE_PUBLIC, &priv_err);
    ck_assert_msg(priv_err == TOX_ERR_GROUP_SET_PRIVACY_STATE_OK, "%d", priv_err);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    const uint32_t num_new_peers = NUM_GROUP_TOXES - 7;
    printf("Connecting %u peers at the same time\n", num_new_peers);

    for (size_t i = 7; i < NUM_GROUP_TOXES; ++i) {
        tox_group_join(autotoxes[i].tox, chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);
    }

    const uint32_t expected_peer_count = num_new_peers + state0->num_peers + 1;

    while (!group_has_full_graph(autotoxes, groupnumber, expected_peer_count)) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    printf("Every peer sees every other peer\n");

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        Tox_Err_Group_Leave err_exit;
        tox_group_leave(autotoxes[i].tox, 0, nullptr, 0, &err_exit);
        ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
    }

    printf("All tests passed!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options autotest_opts = default_run_auto_options();
    autotest_opts.graph = GRAPH_COMPLETE;

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_invite_test, sizeof(State), &autotest_opts);

    return 0;
}

#undef NUM_GROUP_TOXES
#undef PASSWORD
#undef PASS_LEN
#undef WRONG_PASS
#undef WRONG_PASS_LEN
