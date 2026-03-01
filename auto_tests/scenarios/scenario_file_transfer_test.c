#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FILE_SIZE (1024 * 1024)
#define FILENAME "Gentoo.exe"

typedef struct {
    bool file_received;
    bool file_sending_done;
    uint64_t size_recv;
    uint64_t sending_pos;
    uint8_t file_id[TOX_FILE_ID_LENGTH];
    uint32_t file_accepted;
    uint64_t file_size;
    bool sendf_ok;
    uint8_t num;
    uint8_t sending_num;
    bool m_send_reached;
} FileTransferState;

static void on_file_receive(const Tox_Event_File_Recv *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    FileTransferState *state = (FileTransferState *)tox_node_get_script_ctx(self);

    const uint32_t friend_number = tox_event_file_recv_get_friend_number(event);
    const uint32_t file_number = tox_event_file_recv_get_file_number(event);
    const uint64_t filesize = tox_event_file_recv_get_file_size(event);

    state->file_size = filesize;
    state->sending_pos = state->size_recv = 0;

    Tox_Err_File_Control error;
    tox_file_control(tox_node_get_tox(self), friend_number, file_number, TOX_FILE_CONTROL_RESUME, &error);
    state->file_accepted++;
    tox_node_log(self, "File receive: %u bytes, accepted", (uint32_t)filesize);
}

static void on_file_recv_control(const Tox_Event_File_Recv_Control *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    FileTransferState *state = (FileTransferState *)tox_node_get_script_ctx(self);
    const Tox_File_Control control = tox_event_file_recv_control_get_control(event);

    if (control == TOX_FILE_CONTROL_RESUME) {
        state->sendf_ok = true;
        tox_node_log(self, "Received RESUME control");
    }
}

static void on_file_chunk_request(const Tox_Event_File_Chunk_Request *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    FileTransferState *state = (FileTransferState *)tox_node_get_script_ctx(self);

    const uint32_t friend_number = tox_event_file_chunk_request_get_friend_number(event);
    const uint32_t file_number = tox_event_file_chunk_request_get_file_number(event);
    const uint64_t position = tox_event_file_chunk_request_get_position(event);
    size_t length = tox_event_file_chunk_request_get_length(event);

    if (length == 0) {
        state->file_sending_done = true;
        tox_node_log(self, "File sending done");
        return;
    }

    uint8_t *f_data = (uint8_t *)malloc(length);
    memset(f_data, state->sending_num, length);

    tox_file_send_chunk(tox_node_get_tox(self), friend_number, file_number, position, f_data, length, nullptr);
    free(f_data);

    state->sending_num++;
    state->sending_pos += length;
}

static void on_file_recv_chunk(const Tox_Event_File_Recv_Chunk *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    FileTransferState *state = (FileTransferState *)tox_node_get_script_ctx(self);

    const size_t length = tox_event_file_recv_chunk_get_data_length(event);

    if (length == 0) {
        state->file_received = true;
        tox_node_log(self, "File reception done");
        return;
    }

    state->num++;
    state->size_recv += length;
}

static void sender_script(ToxNode *self, void *ctx)
{
    const FileTransferState *state = (const FileTransferState *)ctx;

    tox_events_callback_file_recv_control(tox_node_get_dispatch(self), on_file_recv_control);
    tox_events_callback_file_chunk_request(tox_node_get_dispatch(self), on_file_chunk_request);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    uint32_t fnum = tox_file_send(tox_node_get_tox(self), 0, TOX_FILE_KIND_DATA, FILE_SIZE, nullptr, (const uint8_t *)FILENAME, sizeof(FILENAME), nullptr);
    tox_node_log(self, "Started sending file %u", fnum);

    Tox_File_Id file_id;
    if (!tox_file_get_file_id(tox_node_get_tox(self), 0, fnum, file_id, nullptr)) {
        tox_node_log(self, "Failed to get file id for file %u", fnum);
        abort();
    }

    Tox_Err_File_By_Id err;
    Tox_File_Number found_fnum = tox_file_by_id(tox_node_get_tox(self), 0, file_id, &err);
    if (found_fnum != fnum) {
        tox_node_log(self, "tox_file_by_id failed: expected %u, got %u, error %u", fnum, found_fnum, err);
        abort();
    }

    /* Test with invalid friend number */
    found_fnum = tox_file_by_id(tox_node_get_tox(self), 1234, file_id, &err);
    if (found_fnum != UINT32_MAX || err != TOX_ERR_FILE_BY_ID_FRIEND_NOT_FOUND) {
        tox_node_log(self, "tox_file_by_id with invalid friend failed: expected UINT32_MAX and FRIEND_NOT_FOUND, got %u and error %u", found_fnum, err);
        abort();
    }

    /* Test with invalid file id */
    Tox_File_Id invalid_id = {0};
    found_fnum = tox_file_by_id(tox_node_get_tox(self), 0, invalid_id, &err);
    if (found_fnum != UINT32_MAX || err != TOX_ERR_FILE_BY_ID_NOT_FOUND) {
        tox_node_log(self, "tox_file_by_id with invalid id failed: expected UINT32_MAX and NOT_FOUND, got %u and error %u", found_fnum, err);
        abort();
    }

    WAIT_UNTIL(state->file_sending_done);
    tox_node_log(self, "Done");
}

static void receiver_script(ToxNode *self, void *ctx)
{
    const FileTransferState *state = (const FileTransferState *)ctx;

    tox_events_callback_file_recv(tox_node_get_dispatch(self), on_file_receive);
    tox_events_callback_file_recv_chunk(tox_node_get_dispatch(self), on_file_recv_chunk);

    WAIT_UNTIL(tox_node_is_self_connected(self));

    WAIT_UNTIL(state->file_received);
    tox_node_log(self, "Done");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    FileTransferState state_sender = {0};
    FileTransferState state_receiver = {0};

    ToxNode *sender = tox_scenario_add_node(s, "Sender", sender_script, &state_sender, sizeof(FileTransferState));
    ToxNode *receiver = tox_scenario_add_node(s, "Receiver", receiver_script, &state_receiver, sizeof(FileTransferState));

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

#undef FILE_SIZE
