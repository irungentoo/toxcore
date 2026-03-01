#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool cancelled;
} AliceState;

static void on_file_recv_control(const Tox_Event_File_Recv_Control *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    AliceState *state = (AliceState *)tox_node_get_script_ctx(self);

    if (tox_event_file_recv_control_get_control(event) == TOX_FILE_CONTROL_CANCEL) {
        state->cancelled = true;
        tox_node_log(self, "Bob cancelled the file transfer.");
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    const AliceState *state = (const AliceState *)ctx;
    tox_events_callback_file_recv_control(tox_node_get_dispatch(self), on_file_recv_control);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox *tox = tox_node_get_tox(self);
    tox_file_send(tox, 0, TOX_FILE_KIND_DATA, 1000, nullptr, (const uint8_t *)"test.txt", 8, nullptr);

    WAIT_UNTIL(state->cancelled);
    tox_node_log(self, "File cancellation verified from Alice side.");
}

static void on_file_recv(const Tox_Event_File_Recv *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    uint32_t friend_number = tox_event_file_recv_get_friend_number(event);
    uint32_t file_number = tox_event_file_recv_get_file_number(event);

    tox_node_log(self, "Received file request, rejecting (CANCEL)...");
    tox_file_control(tox_node_get_tox(self), friend_number, file_number, TOX_FILE_CONTROL_CANCEL, nullptr);
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_events_callback_file_recv(tox_node_get_dispatch(self), on_file_recv);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    ToxNode *alice = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    WAIT_UNTIL(tox_node_is_finished(alice));
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    AliceState alice_state = {false};

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
