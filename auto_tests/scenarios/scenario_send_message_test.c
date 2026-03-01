#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MESSAGE_FILLER 'G'

typedef struct {
    bool message_received;
    uint32_t received_len;
} MessageState;

static void on_friend_message(const Tox_Event_Friend_Message *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    MessageState *state = (MessageState *)tox_node_get_script_ctx(self);

    state->received_len = tox_event_friend_message_get_message_length(event);
    const uint8_t *msg = tox_event_friend_message_get_message(event);

    size_t max_len = tox_max_message_length();
    bool correct = (state->received_len == max_len);
    if (correct) {
        for (size_t i = 0; i < max_len; ++i) {
            if (msg[i] != MESSAGE_FILLER) {
                correct = false;
                break;
            }
        }
    }

    if (correct) {
        state->message_received = true;
        tox_node_log(self, "Received correct long message");
    } else {
        tox_node_log(self, "Received INCORRECT message, len %u", state->received_len);
    }
}

static void sender_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    size_t max_len = tox_max_message_length();
    uint8_t *msg = (uint8_t *)malloc(max_len + 1);
    memset(msg, MESSAGE_FILLER, max_len + 1);

    Tox_Err_Friend_Send_Message err;

    // Test too long
    tox_friend_send_message(tox, 0, TOX_MESSAGE_TYPE_NORMAL, msg, max_len + 1, &err);
    ck_assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG);
    tox_node_log(self, "Correctly failed to send too long message");

    // Test max length
    tox_friend_send_message(tox, 0, TOX_MESSAGE_TYPE_NORMAL, msg, max_len, &err);
    ck_assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);
    tox_node_log(self, "Sent max length message");

    free(msg);
}

static void receiver_script(ToxNode *self, void *ctx)
{
    const MessageState *state = (const MessageState *)ctx;
    tox_events_callback_friend_message(tox_node_get_dispatch(self), on_friend_message);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    WAIT_UNTIL(state->message_received);
    tox_node_log(self, "Done");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    MessageState state_receiver = {0};

    ToxNode *sender = tox_scenario_add_node(s, "Sender", sender_script, nullptr, 0);
    ToxNode *receiver = tox_scenario_add_node(s, "Receiver", receiver_script, &state_receiver, sizeof(MessageState));

    tox_node_friend_add(sender, receiver);
    tox_node_friend_add(receiver, sender);
    tox_node_bootstrap(sender, receiver);
    tox_node_bootstrap(receiver, sender);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
