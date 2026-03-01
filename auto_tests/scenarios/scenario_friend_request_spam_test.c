#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FR_MESSAGE "Gentoo"
#define FR_TOX_COUNT 33

typedef struct {
    uint32_t requests_received;
} ReceiverState;

static void on_friend_request(const Tox_Event_Friend_Request *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ReceiverState *state = (ReceiverState *)tox_node_get_script_ctx(self);

    const uint8_t *public_key = tox_event_friend_request_get_public_key(event);
    const uint8_t *data = tox_event_friend_request_get_message(event);
    const size_t length = tox_event_friend_request_get_message_length(event);

    if (length == sizeof(FR_MESSAGE) && memcmp(FR_MESSAGE, data, sizeof(FR_MESSAGE)) == 0) {
        tox_friend_add_norequest(tox_node_get_tox(self), public_key, nullptr);
        state->requests_received++;
        tox_node_log(self, "Friend request received: %u", state->requests_received);
    }
}

static void receiver_script(ToxNode *self, void *ctx)
{
    const ReceiverState *state = (const ReceiverState *)ctx;
    tox_events_callback_friend_request(tox_node_get_dispatch(self), on_friend_request);

    WAIT_UNTIL(tox_node_is_self_connected(self));

    // Wait for all requests to be received and friends connected
    WAIT_UNTIL(state->requests_received == FR_TOX_COUNT - 1);

    // Also wait until they are all connected as friends
    bool all_connected = false;
    while (!all_connected && tox_scenario_is_running(self)) {
        all_connected = true;
        for (uint32_t i = 0; i < FR_TOX_COUNT - 1; ++i) {
            if (!tox_node_is_friend_connected(self, i)) {
                all_connected = false;
                break;
            }
        }
        if (!all_connected) {
            tox_scenario_yield(self);
        }
    }

    tox_node_log(self, "All friends connected");
}

static void sender_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));

    ToxNode *receiver = (ToxNode *)ctx;
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_node_get_address(receiver, address);

    Tox_Err_Friend_Add err;
    tox_friend_add(tox_node_get_tox(self), address, (const uint8_t *)FR_MESSAGE, sizeof(FR_MESSAGE), &err);
    if (err != TOX_ERR_FRIEND_ADD_OK) {
        tox_node_log(self, "Failed to add friend: %u", err);
        return;
    }

    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Connected to receiver");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    ReceiverState receiver_state = {0};

    ToxNode *receiver = tox_scenario_add_node(s, "Receiver", receiver_script, &receiver_state, sizeof(ReceiverState));
    ToxNode *senders[FR_TOX_COUNT - 1];

    for (int i = 0; i < FR_TOX_COUNT - 1; ++i) {
        char alias[16];
        snprintf(alias, sizeof(alias), "Sender%d", i);
        senders[i] = tox_scenario_add_node(s, alias, sender_script, receiver, 0);
        tox_node_bootstrap(senders[i], receiver);
        tox_node_bootstrap(receiver, senders[i]);
    }

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef FR_MESSAGE
