#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_DATA "after"
#define FILE_SIZE (sizeof(FILE_DATA) - 1)

typedef struct {
    bool done;
} AliceState;

typedef struct {
    Tox_File_Number offered;
    uint32_t offers;
    bool accepting;
} BobState;

static void on_file_chunk_request(const Tox_Event_File_Chunk_Request *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    AliceState *state = (AliceState *)tox_node_get_script_ctx(self);

    const uint64_t position = tox_event_file_chunk_request_get_position(event);
    const size_t length = tox_event_file_chunk_request_get_length(event);

    if (length == 0) {
        state->done = true;
        return;
    }

    tox_file_send_chunk(tox_node_get_tox(self),
                        tox_event_file_chunk_request_get_friend_number(event),
                        tox_event_file_chunk_request_get_file_number(event),
                        position, (const uint8_t *)FILE_DATA + position, length, nullptr);
}

static void alice_script(ToxNode *self, void *ctx)
{
    const AliceState *state = (const AliceState *)ctx;
    tox_events_callback_file_chunk_request(tox_node_get_dispatch(self), on_file_chunk_request);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox *tox = tox_node_get_tox(self);
    const Tox_File_Number cancelled = tox_file_send(tox, 0, TOX_FILE_KIND_DATA, FILE_SIZE, nullptr,
                                      (const uint8_t *)"cancelled.txt", 13, nullptr);

    // Bob accepts the file as Alice cancels it.
    tox_scenario_barrier_wait(self);
    tox_file_control(tox, 0, cancelled, TOX_FILE_CONTROL_CANCEL, nullptr);

    // Long enough for what's left of it to reach the other end.
    const uint64_t settled = tox_scenario_get_time(tox_node_get_scenario(self)) + 1000;
    WAIT_UNTIL(tox_scenario_get_time(tox_node_get_scenario(self)) >= settled);

    // This takes the number the cancelled one had.
    tox_file_send(tox, 0, TOX_FILE_KIND_DATA, FILE_SIZE, nullptr, (const uint8_t *)"first.txt", 9, nullptr);

    WAIT_UNTIL(state->done);
    tox_node_log(self, "The file after the crossed cancel arrived.");
}

static void on_file_recv(const Tox_Event_File_Recv *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    BobState *state = (BobState *)tox_node_get_script_ctx(self);

    state->offered = tox_event_file_recv_get_file_number(event);
    ++state->offers;

    if (state->accepting) {
        tox_file_control(tox_node_get_tox(self), tox_event_file_recv_get_friend_number(event), state->offered,
                         TOX_FILE_CONTROL_RESUME, nullptr);
    }
}

static void bob_script(ToxNode *self, void *ctx)
{
    BobState *state = (BobState *)ctx;
    tox_events_callback_file_recv(tox_node_get_dispatch(self), on_file_recv);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    WAIT_UNTIL(state->offers == 1);
    tox_scenario_barrier_wait(self);
    tox_file_control(tox_node_get_tox(self), 0, state->offered, TOX_FILE_CONTROL_RESUME, nullptr);
    state->accepting = true;

    ToxNode *alice = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    WAIT_UNTIL(tox_node_is_finished(alice));
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 30000);

    AliceState alice_state = {0};
    BobState bob_state = {0};

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, &alice_state, sizeof(AliceState));
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, &bob_state, sizeof(BobState));

    tox_node_bootstrap(alice, bob);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %d\n", (int)res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef FILE_SIZE
#undef FILE_DATA
