#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AVATAR_SIZE 100
static const uint8_t avatar_data[AVATAR_SIZE] = "This is a fake avatar image data. It should be longer but for testing this is enough.";

typedef struct {
    uint8_t avatar_hash[TOX_HASH_LENGTH];
    bool transfer_finished;
} AvatarState;

static void on_file_chunk_request(const Tox_Event_File_Chunk_Request *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    AvatarState *state = (AvatarState *)tox_node_get_script_ctx(self);

    uint32_t friend_number = tox_event_file_chunk_request_get_friend_number(event);
    uint32_t file_number = tox_event_file_chunk_request_get_file_number(event);
    uint64_t position = tox_event_file_chunk_request_get_position(event);
    size_t length = tox_event_file_chunk_request_get_length(event);

    if (length == 0) {
        state->transfer_finished = true;
        return;
    }

    if (position >= AVATAR_SIZE) {
        tox_file_send_chunk(tox_node_get_tox(self), friend_number, file_number, position, nullptr, 0, nullptr);
        state->transfer_finished = true;
        return;
    }

    size_t to_send = AVATAR_SIZE - (size_t)position;
    if (to_send > length) {
        to_send = length;
    }

    tox_file_send_chunk(tox_node_get_tox(self), friend_number, file_number, position, avatar_data + position, to_send, nullptr);
}

static void alice_script(ToxNode *self, void *ctx)
{
    AvatarState *state = (AvatarState *)ctx;
    tox_events_callback_file_chunk_request(tox_node_get_dispatch(self), on_file_chunk_request);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox *tox = tox_node_get_tox(self);
    tox_hash(state->avatar_hash, avatar_data, AVATAR_SIZE);

    tox_node_log(self, "Sending avatar request to Bob...");
    Tox_Err_File_Send err_send;
    tox_file_send(tox, 0, TOX_FILE_KIND_AVATAR, AVATAR_SIZE, state->avatar_hash, (const uint8_t *)"avatar.png", 10, &err_send);
    ck_assert(err_send == TOX_ERR_FILE_SEND_OK);

    WAIT_UNTIL(state->transfer_finished);
    tox_node_log(self, "Avatar transfer finished from Alice side.");
}

typedef struct {
    bool avatar_received;
    uint8_t received_data[AVATAR_SIZE];
    size_t received_len;
} BobState;

static void on_file_recv(const Tox_Event_File_Recv *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    uint32_t kind = tox_event_file_recv_get_kind(event);
    uint32_t friend_number = tox_event_file_recv_get_friend_number(event);
    uint32_t file_number = tox_event_file_recv_get_file_number(event);

    if (kind == TOX_FILE_KIND_AVATAR) {
        tox_node_log(self, "Receiving avatar from Alice, resuming...");
        tox_file_control(tox_node_get_tox(self), friend_number, file_number, TOX_FILE_CONTROL_RESUME, nullptr);
    }
}

static void on_file_recv_chunk(const Tox_Event_File_Recv_Chunk *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    BobState *state = (BobState *)tox_node_get_script_ctx(self);
    size_t length = tox_event_file_recv_chunk_get_data_length(event);
    uint64_t position = tox_event_file_recv_chunk_get_position(event);

    if (length == 0) {
        state->avatar_received = true;
        return;
    }

    if (position + length <= AVATAR_SIZE) {
        memcpy(state->received_data + position, tox_event_file_recv_chunk_get_data(event), length);
        state->received_len += length;
    }
}

static void bob_script(ToxNode *self, void *ctx)
{
    const BobState *state = (const BobState *)ctx;
    tox_events_callback_file_recv(tox_node_get_dispatch(self), on_file_recv);
    tox_events_callback_file_recv_chunk(tox_node_get_dispatch(self), on_file_recv_chunk);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    WAIT_UNTIL(state->avatar_received);
    tox_node_log(self, "Avatar received. Verifying data...");

    ck_assert(state->received_len == AVATAR_SIZE);
    ck_assert(memcmp(state->received_data, avatar_data, AVATAR_SIZE) == 0);

    tox_node_log(self, "Avatar verification successful!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    AvatarState alice_state = {{0}, false};
    BobState bob_state = {false, {0}, 0};

    tox_scenario_add_node(s, "Alice", alice_script, &alice_state, sizeof(AvatarState));
    tox_scenario_add_node(s, "Bob", bob_script, &bob_state, sizeof(BobState));

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

