/* Tests that we can send messages to friends.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct State {
    bool message_received;
} State;

#include "auto_test_support.h"

#define MESSAGE_FILLER 'G'

static void message_callback(
    Tox *m, uint32_t friendnumber, Tox_Message_Type type,
    const uint8_t *string, size_t length, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    if (type != TOX_MESSAGE_TYPE_NORMAL) {
        ck_abort_msg("Bad type");
    }

    uint8_t cmp_msg[TOX_MAX_MESSAGE_LENGTH];
    memset(cmp_msg, MESSAGE_FILLER, sizeof(cmp_msg));

    if (length == TOX_MAX_MESSAGE_LENGTH && memcmp(string, cmp_msg, sizeof(cmp_msg)) == 0) {
        state->message_received = true;
    }
}

static void send_message_test(AutoTox *autotoxes)
{
    tox_callback_friend_message(autotoxes[1].tox, &message_callback);

    uint8_t msgs[TOX_MAX_MESSAGE_LENGTH + 1];
    memset(msgs, MESSAGE_FILLER, sizeof(msgs));

    Tox_Err_Friend_Send_Message errm;
    tox_friend_send_message(autotoxes[0].tox, 0, TOX_MESSAGE_TYPE_NORMAL, msgs, TOX_MAX_MESSAGE_LENGTH + 1, &errm);
    ck_assert_msg(errm == TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG, "TOX_MAX_MESSAGE_LENGTH is too small? error=%d", errm);

    tox_friend_send_message(autotoxes[0].tox, 0, TOX_MESSAGE_TYPE_NORMAL, msgs, TOX_MAX_MESSAGE_LENGTH, &errm);
    ck_assert_msg(errm == TOX_ERR_FRIEND_SEND_MESSAGE_OK, "TOX_MAX_MESSAGE_LENGTH is too big? error=%d", errm);

    do {
        iterate_all_wait(autotoxes, 2, ITERATION_INTERVAL);
    } while (!((State *)autotoxes[1].state)->message_received);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *tox_options = tox_options_new(nullptr);
    ck_assert(tox_options != nullptr);

    Run_Auto_Options options = default_run_auto_options;
    options.graph = GRAPH_LINEAR;
    tox_options_set_ipv6_enabled(tox_options, true);
    run_auto_test(tox_options, 2, send_message_test, sizeof(State), &options);

    tox_options_set_ipv6_enabled(tox_options, false);
    run_auto_test(tox_options, 2, send_message_test, sizeof(State), &options);

    tox_options_free(tox_options);

    return 0;
}
