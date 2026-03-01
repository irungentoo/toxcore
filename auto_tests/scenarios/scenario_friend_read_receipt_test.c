#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t message_id;
    bool received_receipt;
} AliceState;

static void on_read_receipt(const Tox_Event_Friend_Read_Receipt *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    AliceState *state = (AliceState *)tox_node_get_script_ctx(self);

    uint32_t friend_number = tox_event_friend_read_receipt_get_friend_number(event);
    uint32_t message_id = tox_event_friend_read_receipt_get_message_id(event);

    tox_node_log(self, "Received read receipt for friend %u, message %u", friend_number, message_id);

    if (friend_number == 0 && message_id == state->message_id) {
        state->received_receipt = true;
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    AliceState *state = (AliceState *)ctx;
    tox_events_callback_friend_read_receipt(tox_node_get_dispatch(self), on_read_receipt);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    tox_node_log(self, "Sending message to Bob...");
    uint8_t msg[] = "Hello Bob!";
    Tox_Err_Friend_Send_Message err;
    state->message_id = tox_friend_send_message(tox_node_get_tox(self), 0, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), &err);
    ck_assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);
    tox_node_log(self, "Message sent with ID %u, waiting for read receipt...", state->message_id);

    WAIT_UNTIL(state->received_receipt);
    tox_node_log(self, "Read receipt received successfully!");
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    tox_node_log(self, "Waiting for message from Alice...");
    WAIT_FOR_EVENT(TOX_EVENT_FRIEND_MESSAGE);
    tox_node_log(self, "Received message! Tox will automatically send a read receipt.");

    // We stay here to allow Alice to receive the receipt
    // We wait until alice is finished
    ToxNode *alice = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    WAIT_UNTIL(tox_node_is_finished(alice));
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    AliceState alice_state = {0, false};
    tox_scenario_add_node(s, "Alice", alice_script, &alice_state, sizeof(AliceState));
    tox_scenario_add_node(s, "Bob", bob_script, nullptr, 0);

    ToxNode *alice = tox_scenario_get_node(s, 0);
    ToxNode *bob = tox_scenario_get_node(s, 1);

    tox_node_bootstrap(alice, bob);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %u\n", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
