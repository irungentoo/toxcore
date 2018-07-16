/* Try to overflow the net_crypto packet buffer.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

typedef struct State {
    uint32_t index;
} State;

#include "run_auto_test.h"

#define NUM_MSGS 40000

static void net_crypto_overflow_test(Tox **toxes, State *state)
{
    const uint8_t message[] = {0};
    bool errored = false;

    for (uint32_t i = 0; i < NUM_MSGS; i++) {
        TOX_ERR_FRIEND_SEND_MESSAGE err;
        tox_friend_send_message(toxes[0], 0, TOX_MESSAGE_TYPE_NORMAL, message, sizeof message, &err);

        if (err != TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            errored = true;
        }

        if (errored) {
            // As soon as we get the first error, we expect the same error (SENDQ)
            // every time we try to send.
            ck_assert_msg(err == TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ,
                          "expected SENDQ error on message %u, but got %d", i, err);
        } else {
            ck_assert_msg(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK,
                          "failed to send message number %u: %d", i, err);
        }
    }

    ck_assert_msg(errored, "expected SENDQ error at some point (increase NUM_MSGS?)");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, net_crypto_overflow_test);
    return 0;
}
