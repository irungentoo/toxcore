#include "framework/framework.h"
#include <stdio.h>
#include <string.h>

#define NUM_MSGS 40000

typedef struct {
    uint32_t recv_count;
} State;

static void on_friend_message(const Tox_Event_Friend_Message *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->recv_count++;
}

static void receiver_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);
    tox_events_callback_friend_message(dispatch, on_friend_message);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);
    tox_node_wait_for_friend_connected(self, 1);

    tox_node_log(self, "Ready to receive...");
    tox_scenario_barrier_wait(self); // Barrier 1: Connected

    // Wait until we get many messages or scenario timeout.
    // We don't expect ALL 80k messages to arrive in a short time,
    // but we want to see if it survives the flood.
    uint32_t last_count = 0;
    uint32_t stable_ticks = 0;
    while (tox_scenario_is_running(self)) {
        tox_scenario_yield(self);
        if (state->recv_count == last_count && state->recv_count > 0) {
            stable_ticks++;
            if (stable_ticks > 100) {
                break;    // No new messages for 5 seconds
            }
        } else {
            stable_ticks = 0;
        }
        last_count = state->recv_count;

        if (state->recv_count >= NUM_MSGS * 2) {
            break;
        }
    }
    tox_node_log(self, "Received %u messages.", state->recv_count);
}

static void sender_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    tox_scenario_barrier_wait(self); // Barrier 1: Connected

    tox_node_log(self, "Sending messages...");
    Tox *tox = tox_node_get_tox(self);
    for (uint32_t i = 0; i < NUM_MSGS; i++) {
        uint8_t message[128] = {0};
        snprintf((char *)message, sizeof(message), "%u-%u", tox_node_get_index(self), i);

        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(tox, 0, TOX_MESSAGE_TYPE_NORMAL, message, sizeof(message), &err);

        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ) {
            // This is expected when flooding
            if (i % 1000 == 0) {
                tox_node_log(self, "Send queue full at message %u, yielding...", i);
            }
            tox_scenario_yield(self);
            i--; // Retry this message
            continue;
        }

        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED) {
            if (i % 1000 == 0) {
                tox_node_log(self, "Friend not connected at message %u, waiting...", i);
            }
            tox_node_wait_for_friend_connected(self, 0);
            i--; // Retry this message
            continue;
        }

        ck_assert_msg(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK, "send_message failed with %s",
                      tox_err_friend_send_message_to_string(err));

        if (i % 500 == 0) {
            tox_scenario_yield(self);
        }
    }
    tox_node_log(self, "Finished sending.");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 120000);
    State receiver_state = {0};

    ToxNode *receiver = tox_scenario_add_node(s, "Receiver", receiver_script, &receiver_state, sizeof(State));
    ToxNode *sender1 = tox_scenario_add_node(s, "Sender1", sender_script, nullptr, 0);
    ToxNode *sender2 = tox_scenario_add_node(s, "Sender2", sender_script, nullptr, 0);

    tox_node_bootstrap(sender1, receiver);
    tox_node_bootstrap(sender2, receiver);
    tox_node_friend_add(receiver, sender1);
    tox_node_friend_add(sender1, receiver);
    tox_node_friend_add(receiver, sender2);
    tox_node_friend_add(sender2, receiver);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE && res != TOX_SCENARIO_TIMEOUT) {
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef NUM_MSGS
