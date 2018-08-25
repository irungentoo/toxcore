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
    bool message_received;
} State;

#include "run_auto_test.h"

#define MESSAGE_FILLER 'G'

static void message_callback(
    Tox *m, uint32_t friendnumber, TOX_MESSAGE_TYPE type,
    const uint8_t *string, size_t length, void *userdata)
{
    State *state = (State *)userdata;

    if (type != TOX_MESSAGE_TYPE_NORMAL) {
        ck_abort_msg("Bad type");
    }

    uint8_t cmp_msg[TOX_MAX_MESSAGE_LENGTH];
    memset(cmp_msg, MESSAGE_FILLER, sizeof(cmp_msg));

    if (length == TOX_MAX_MESSAGE_LENGTH && memcmp(string, cmp_msg, sizeof(cmp_msg)) == 0) {
        state->message_received = true;
    }
}

static void send_message_test(Tox **toxes, State *state)
{
    tox_callback_friend_message(toxes[1], &message_callback);

    uint8_t msgs[TOX_MAX_MESSAGE_LENGTH + 1];
    memset(msgs, MESSAGE_FILLER, sizeof(msgs));

    TOX_ERR_FRIEND_SEND_MESSAGE errm;
    tox_friend_send_message(toxes[0], 0, TOX_MESSAGE_TYPE_NORMAL, msgs, TOX_MAX_MESSAGE_LENGTH + 1, &errm);
    ck_assert_msg(errm == TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG, "TOX_MAX_MESSAGE_LENGTH is too small? error=%d", errm);

    tox_friend_send_message(toxes[0], 0, TOX_MESSAGE_TYPE_NORMAL, msgs, TOX_MAX_MESSAGE_LENGTH, &errm);
    ck_assert_msg(errm == TOX_ERR_FRIEND_SEND_MESSAGE_OK, "TOX_MAX_MESSAGE_LENGTH is too big? error=%d", errm);

    do {
        tox_iterate(toxes[0], &state[0]);
        tox_iterate(toxes[1], &state[1]);

        c_sleep(ITERATION_INTERVAL);
    } while (!state[1].message_received);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, send_message_test);
    return 0;
}
