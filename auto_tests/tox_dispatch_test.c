/* Auto Tests: Many clients.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/tox.h"
#include "../toxcore/tox_dispatch.h"
#include "../toxcore/tox_events.h"
#include "check_compat.h"

static void handle_events_friend_message(Tox *tox, const Tox_Event_Friend_Message *event, void *user_data)
{
    bool *success = (bool *)user_data;

    ck_assert(tox_event_friend_message_get_message_length(event) == sizeof("hello"));
    const uint8_t *msg = tox_event_friend_message_get_message(event);
    ck_assert_msg(memcmp(msg, "hello", sizeof("hello")) == 0,
                  "message was not expected 'hello' but '%s'", (const char *)msg);

    *success = true;
}

static bool await_message(Tox **toxes, const Tox_Dispatch *dispatch)
{
    for (uint32_t i = 0; i < 100; ++i) {
        // Ignore events on tox 1.
        tox_events_free(tox_events_iterate(toxes[0], nullptr));
        // Check if tox 2 got the message from tox 1.
        Tox_Events *events = tox_events_iterate(toxes[1], nullptr);

        bool success = false;
        tox_dispatch_invoke(dispatch, events, toxes[1], &success);
        tox_events_free(events);

        if (success) {
            return true;
        }

        c_sleep(tox_iteration_interval(toxes[0]));
    }

    return false;
}

static void test_tox_events(void)
{
    uint8_t message[sizeof("hello")];
    memcpy(message, "hello", sizeof(message));

    Tox *toxes[2];
    uint32_t index[2];

    for (uint32_t i = 0; i < 2; ++i) {
        index[i] = i + 1;
        toxes[i] = tox_new_log(nullptr, nullptr, &index[i]);
        tox_events_init(toxes[i]);
        ck_assert_msg(toxes[i] != nullptr, "failed to create tox instances %u", i);
    }

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    ck_assert_msg(dispatch != nullptr, "failed to create event dispatcher");

    tox_events_callback_friend_message(dispatch, handle_events_friend_message);

    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(toxes[0], pk);
    tox_bootstrap(toxes[1], "localhost", tox_self_get_udp_port(toxes[0], nullptr), pk, nullptr);

    tox_self_get_public_key(toxes[0], pk);
    tox_friend_add_norequest(toxes[1], pk, nullptr);

    tox_self_get_public_key(toxes[1], pk);
    tox_friend_add_norequest(toxes[0], pk, nullptr);

    printf("bootstrapping and connecting 2 toxes\n");

    while (tox_self_get_connection_status(toxes[0]) == TOX_CONNECTION_NONE ||
            tox_self_get_connection_status(toxes[1]) == TOX_CONNECTION_NONE) {
        // Ignore connection events for now.
        tox_events_free(tox_events_iterate(toxes[0], nullptr));
        tox_events_free(tox_events_iterate(toxes[1], nullptr));

        c_sleep(tox_iteration_interval(toxes[0]));
    }

    printf("toxes online, waiting for friend connection\n");

    while (tox_friend_get_connection_status(toxes[0], 0, nullptr) == TOX_CONNECTION_NONE ||
            tox_friend_get_connection_status(toxes[1], 0, nullptr) == TOX_CONNECTION_NONE) {
        // Ignore connection events for now.
        tox_events_free(tox_events_iterate(toxes[0], nullptr));
        tox_events_free(tox_events_iterate(toxes[1], nullptr));

        c_sleep(tox_iteration_interval(toxes[0]));
    }

    printf("friends are connected via %s, now sending message\n",
           tox_friend_get_connection_status(toxes[0], 0, nullptr) == TOX_CONNECTION_TCP ? "TCP" : "UDP");

    Tox_Err_Friend_Send_Message err;
    tox_friend_send_message(toxes[0], 0, TOX_MESSAGE_TYPE_NORMAL, message, sizeof(message), &err);
    ck_assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);

    ck_assert(await_message(toxes, dispatch));

    tox_dispatch_free(dispatch);

    for (uint32_t i = 0; i < 2; ++i) {
        tox_kill(toxes[i]);
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    test_tox_events();
    return 0;
}
