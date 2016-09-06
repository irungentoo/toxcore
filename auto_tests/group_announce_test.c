/* Tests that we can send messages to friends.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct State {
    uint32_t index;
    uint64_t clock;
    bool peer_joined;
    bool message_sent;
    bool message_received;
} State;

#include "run_auto_test.h"

static void group_invite_handler(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 void *user_data)
{
    printf("invite arrived; accepting\n");
    TOX_ERR_GROUP_INVITE_ACCEPT err_accept;
    tox_group_invite_accept(tox, invite_data, length, nullptr, 0, &err_accept);
    ck_assert(err_accept == TOX_ERR_GROUP_INVITE_ACCEPT_OK);
}

static const char *tox_str_group_join_fail(TOX_GROUP_JOIN_FAIL v)
{
    switch (v) {
        case TOX_GROUP_JOIN_FAIL_NAME_TAKEN:
            return "NAME_TAKEN";

        case TOX_GROUP_JOIN_FAIL_PEER_LIMIT:
            return "PEER_LIMIT";

        case TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD:
            return "INVALID_PASSWORD";

        case TOX_GROUP_JOIN_FAIL_UNKNOWN:
            return "UNKNOWN";
    }

    return "<invalid>";
}

static void group_join_fail_handler(Tox *tox, uint32_t groupnumber, TOX_GROUP_JOIN_FAIL fail_type, void *user_data)
{
    printf("join failed: %s\n", tox_str_group_join_fail(fail_type));
}

static void group_peer_join_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;
    printf("peer %u joined, sending message\n", peer_id);
    state->peer_joined = true;
}

static void group_message_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_MESSAGE_TYPE type,
                                  const uint8_t *message, size_t length, void *user_data)
{
    State *state = (State *)user_data;
    printf("peer %u sent message: %s\n", peer_id, (const char *)message);
    ck_assert(memcmp(message, "hello", 6) == 0);
    state->message_received = true;
}

static void group_message_test(Tox **toxes, State *state)
{
    tox_self_set_name(toxes[0], (const uint8_t *)"a", 1, nullptr);
    tox_self_set_name(toxes[1], (const uint8_t *)"b", 1, nullptr);
    tox_self_set_name(toxes[2], (const uint8_t *)"c", 1, nullptr);

    tox_callback_group_invite(toxes[1], group_invite_handler, nullptr);
    tox_callback_group_join_fail(toxes[1], group_join_fail_handler, nullptr);
    tox_callback_group_peer_join(toxes[1], group_peer_join_handler, nullptr);
    tox_callback_group_message(toxes[0], group_message_handler, nullptr);

    // tox0 makes new group.
    TOX_ERR_GROUP_NEW err_new;
    uint32_t group_number =
        tox_group_new(
            toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC,
            (const uint8_t *)"my cool group", strlen("my cool group"), &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    // get the chat id of the new group.
    TOX_ERR_GROUP_STATE_QUERIES err_id;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[0], group_number, chat_id, &err_id);
    ck_assert(err_id == TOX_ERR_GROUP_STATE_QUERIES_OK);

    // tox1 and tox2 joins it.
    TOX_ERR_GROUP_JOIN err_join;
    tox_group_join(toxes[1], chat_id, nullptr, 0, &err_join);
    ck_assert(err_join == TOX_ERR_GROUP_JOIN_OK);

    tox_group_join(toxes[2], chat_id, nullptr, 0, &err_join);
    ck_assert(err_join == TOX_ERR_GROUP_JOIN_OK);

    while (!state[0].message_received) {
        iterate_all_wait(3, toxes, state, ITERATION_INTERVAL);

        if (state[1].peer_joined && !state[1].message_sent) {
            TOX_ERR_GROUP_SEND_MESSAGE err_send;
            tox_group_send_message(toxes[1], group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"hello", 6, &err_send);
            ck_assert(err_send == TOX_ERR_GROUP_SEND_MESSAGE_OK);
            state[1].message_sent = true;
        }

        c_sleep(ITERATION_INTERVAL);
    }

    TOX_ERR_GROUP_LEAVE err_exit;
    tox_group_leave(toxes[0], group_number, nullptr, 0, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);

    tox_group_leave(toxes[1], group_number, nullptr, 0, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);

    tox_group_leave(toxes[2], group_number, nullptr, 0, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(3, group_message_test, false);
    return 0;
}
