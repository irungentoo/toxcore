#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_SIZE (1024 * 1024)
#define SEEK_POS (512 * 1024)

typedef struct {
    bool seek_happened;
    bool finished;
} SenderState;

static void on_file_chunk_request(const Tox_Event_File_Chunk_Request *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    SenderState *state = (SenderState *)tox_node_get_script_ctx(self);

    uint32_t friend_number = tox_event_file_chunk_request_get_friend_number(event);
    uint32_t file_number = tox_event_file_chunk_request_get_file_number(event);
    uint64_t position = tox_event_file_chunk_request_get_position(event);
    size_t length = tox_event_file_chunk_request_get_length(event);

    if (length == 0) {
        state->finished = true;
        return;
    }

    if (position >= SEEK_POS) {
        state->seek_happened = true;
    }

    uint8_t data[TOX_MAX_CUSTOM_PACKET_SIZE];
    memset(data, (uint8_t)(position % 256), length);
    tox_file_send_chunk(tox_node_get_tox(self), friend_number, file_number, position, data, length, nullptr);
}

static void sender_script(ToxNode *self, void *ctx)
{
    SenderState *state = (SenderState *)ctx;
    tox_events_callback_file_chunk_request(tox_node_get_dispatch(self), on_file_chunk_request);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox *tox = tox_node_get_tox(self);
    tox_file_send(tox, 0, TOX_FILE_KIND_DATA, FILE_SIZE, nullptr, (const uint8_t *)"seek_test.bin", 13, nullptr);

    WAIT_UNTIL(state->finished);
    tox_node_log(self, "Sender finished. Seek happened: %s", state->seek_happened ? "YES" : "NO");
    ck_assert(state->seek_happened);
}

typedef struct {
    uint32_t file_number;
    bool file_recv_called;
    bool finished;
} ReceiverState;

static void on_file_recv(const Tox_Event_File_Recv *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ReceiverState *state = (ReceiverState *)tox_node_get_script_ctx(self);
    state->file_number = tox_event_file_recv_get_file_number(event);
    state->file_recv_called = true;
    tox_node_log(self, "Received file request, file_number = %u", state->file_number);
}

static void on_file_recv_chunk(const Tox_Event_File_Recv_Chunk *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ReceiverState *state = (ReceiverState *)tox_node_get_script_ctx(self);
    size_t length = tox_event_file_recv_chunk_get_data_length(event);
    if (length == 0) {
        state->finished = true;
    }
}

static void receiver_script(ToxNode *self, void *ctx)
{
    ReceiverState *state = (ReceiverState *)ctx;
    tox_events_callback_file_recv(tox_node_get_dispatch(self), on_file_recv);
    tox_events_callback_file_recv_chunk(tox_node_get_dispatch(self), on_file_recv_chunk);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    WAIT_UNTIL(state->file_recv_called);

    tox_node_log(self, "Seeking to %d before resuming...", SEEK_POS);
    Tox_Err_File_Seek seek_err;
    bool seek_res = tox_file_seek(tox_node_get_tox(self), 0, state->file_number, SEEK_POS, &seek_err);
    if (!seek_res) {
        tox_node_log(self, "tox_file_seek failed: %s", tox_err_file_seek_to_string(seek_err));
    }
    ck_assert(seek_res);

    tox_node_log(self, "Resuming file %u...", state->file_number);
    Tox_Err_File_Control ctrl_err;
    bool resume_res = tox_file_control(tox_node_get_tox(self), 0, state->file_number, TOX_FILE_CONTROL_RESUME, &ctrl_err);
    ck_assert(resume_res);

    WAIT_UNTIL(state->finished);
    tox_node_log(self, "Receiver finished!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    SenderState sender_state = {false, false};
    ReceiverState receiver_state = {0, false, false};

    tox_scenario_add_node(s, "Sender", sender_script, &sender_state, sizeof(SenderState));
    tox_scenario_add_node(s, "Receiver", receiver_script, &receiver_state, sizeof(ReceiverState));

    ToxNode *sender = tox_scenario_get_node(s, 0);
    ToxNode *receiver = tox_scenario_get_node(s, 1);

    tox_node_bootstrap(sender, receiver);
    tox_node_friend_add(sender, receiver);
    tox_node_friend_add(receiver, sender);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %u\n", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef FILE_SIZE
