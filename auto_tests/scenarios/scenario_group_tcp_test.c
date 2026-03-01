#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CODEWORD "RONALD MCDONALD"
#define CODEWORD_LEN (sizeof(CODEWORD) - 1)
#define RELAY_TCP_PORT 33811

typedef struct {
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    uint32_t group_number;
    uint32_t peer_id;
    bool joined;
    bool got_private_message;
    bool got_group_message;
    bool got_invite;
} State;

static void on_group_invite(const Tox_Event_Group_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);

    const uint32_t friend_number = tox_event_group_invite_get_friend_number(event);
    const uint8_t *invite_data = tox_event_group_invite_get_invite_data(event);
    const size_t length = tox_event_group_invite_get_invite_data_length(event);

    Tox_Err_Group_Invite_Accept err_accept;
    state->group_number = tox_group_invite_accept(tox_node_get_tox(self), friend_number, invite_data, length, (const uint8_t *)"test", 4,
                          nullptr, 0, &err_accept);
    if (err_accept == TOX_ERR_GROUP_INVITE_ACCEPT_OK) {
        state->got_invite = true;
    }
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->peer_id = tox_event_group_peer_join_get_peer_id(event);
    state->joined = true;
    tox_node_log(self, "Peer %u joined group", state->peer_id);
}

static void on_group_private_message(const Tox_Event_Group_Private_Message *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    const uint8_t *message = tox_event_group_private_message_get_message(event);
    const size_t length = tox_event_group_private_message_get_message_length(event);

    if (length == CODEWORD_LEN && memcmp(CODEWORD, message, length) == 0) {
        state->got_private_message = true;
    }
}

static void on_group_message(const Tox_Event_Group_Message *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    const uint8_t *message = tox_event_group_message_get_message(event);
    const size_t length = tox_event_group_message_get_message_length(event);

    if (length == CODEWORD_LEN && memcmp(CODEWORD, message, length) == 0) {
        state->got_group_message = true;
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    Tox *tox = tox_node_get_tox(self);

    tox_events_callback_group_peer_join(tox_node_get_dispatch(self), on_group_peer_join);

    Tox_Err_Group_New new_err;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)"test", 4,
                                        (const uint8_t *)"test", 4, &new_err);
    ck_assert(new_err == TOX_ERR_GROUP_NEW_OK);

    Tox_Err_Group_State_Query id_err;
    tox_group_get_chat_id(tox, state->group_number, state->chat_id, &id_err);
    ck_assert(id_err == TOX_ERR_GROUP_STATE_QUERY_OK);

    char chat_id_str[TOX_GROUP_CHAT_ID_SIZE * 2 + 1];
    for (int i = 0; i < TOX_GROUP_CHAT_ID_SIZE; ++i) {
        snprintf(chat_id_str + i * 2, sizeof(chat_id_str) - i * 2, "%02X", state->chat_id[i]);
    }
    tox_node_log(self, "Created group with chat_id: %s", chat_id_str);

    tox_scenario_barrier_wait(self); // Barrier 1: chat_id is ready for Bob

    tox_node_log(self, "Waiting for Bob to join group...");
    WAIT_UNTIL(state->joined);
    if (!state->joined) {
        return;
    }

    Tox_Err_Group_Send_Private_Message perr;
    tox_group_send_private_message(tox, state->group_number, state->peer_id,
                                   TOX_MESSAGE_TYPE_NORMAL,
                                   (const uint8_t *)CODEWORD, CODEWORD_LEN, &perr);
    ck_assert(perr == TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK);

    tox_scenario_barrier_wait(self); // Barrier 2: PM sent, Bob leaving
    tox_scenario_barrier_wait(self); // Barrier 3: Bob left
    state->joined = false;

    tox_node_log(self, "Inviting Bob back via friend invite...");
    Tox_Err_Group_Invite_Friend err_invite;
    tox_group_invite_friend(tox, state->group_number, 0, &err_invite);
    ck_assert(err_invite == TOX_ERR_GROUP_INVITE_FRIEND_OK);

    WAIT_UNTIL(state->joined);
    if (!state->joined) {
        return;
    }

    Tox_Err_Group_Send_Message merr;
    tox_group_send_message(tox, state->group_number, TOX_MESSAGE_TYPE_NORMAL,
                           (const uint8_t *)CODEWORD, CODEWORD_LEN, &merr);
    ck_assert(merr == TOX_ERR_GROUP_SEND_MESSAGE_OK);
}

static void bob_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    Tox *tox = tox_node_get_tox(self);

    tox_events_callback_group_private_message(tox_node_get_dispatch(self), on_group_private_message);
    tox_events_callback_group_message(tox_node_get_dispatch(self), on_group_message);
    tox_events_callback_group_invite(tox_node_get_dispatch(self), on_group_invite);

    tox_node_log(self, "Waiting for TCP connection...");
    WAIT_UNTIL(tox_node_get_connection_status(self) == TOX_CONNECTION_TCP);
    tox_node_log(self, "Connected. Waiting for Alice...");
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    if (!tox_node_is_friend_connected(self, 0)) {
        tox_node_log(self, "TIMEOUT waiting for Alice.");
        return;
    }
    tox_node_log(self, "Alice connected.");

    tox_scenario_barrier_wait(self); // Barrier 1: Alice has chat_id

    ToxScenario *s = tox_node_get_scenario(self);
    ToxNode *alice_node = tox_scenario_get_node(s, 0);
    State *alice_state = (State *)tox_node_get_script_ctx(alice_node);

    tox_node_log(self, "Joining group via chat_id...");
    Tox_Err_Group_Join jerr;
    state->group_number = tox_group_join(tox, alice_state->chat_id, (const uint8_t *)"test", 4, nullptr, 0, &jerr);
    ck_assert(jerr == TOX_ERR_GROUP_JOIN_OK);

    WAIT_UNTIL(state->got_private_message);
    if (!state->got_private_message) {
        return;
    }
    tox_scenario_barrier_wait(self); // Barrier 2: PM received, now leaving

    Tox_Err_Group_Leave err_exit;
    tox_group_leave(tox, state->group_number, nullptr, 0, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);

    state->got_invite = false;
    tox_scenario_barrier_wait(self); // Barrier 3: Left, waiting for invite
    WAIT_UNTIL(state->got_invite);
    WAIT_UNTIL(state->got_group_message);
}

static void relay_script(ToxNode *self, void *ctx)
{
    (void)ctx;
    tox_scenario_barrier_wait(self); // Barrier 1
    tox_scenario_barrier_wait(self); // Barrier 2
    tox_scenario_barrier_wait(self); // Barrier 3
}

int main(int argc, char **argv)
{
    ToxScenario *s = tox_scenario_new(argc, argv, 120000);

    struct Tox_Options *options_alice = tox_options_new(nullptr);
    tox_options_set_udp_enabled(options_alice, false);

    struct Tox_Options *options_bob = tox_options_new(nullptr);
    tox_options_set_udp_enabled(options_bob, false);

    struct Tox_Options *options_relay = tox_options_new(nullptr);
    tox_options_set_tcp_port(options_relay, RELAY_TCP_PORT);

    State *alice_state = (State *)calloc(1, sizeof(State));
    State *bob_state = (State *)calloc(1, sizeof(State));

    ToxNode *alice = tox_scenario_add_node_ex(s, "Alice", alice_script, alice_state, sizeof(State), options_alice);
    ToxNode *bob = tox_scenario_add_node_ex(s, "Bob", bob_script, bob_state, sizeof(State), options_bob);
    ToxNode *relay = tox_scenario_add_node_ex(s, "Relay", relay_script, nullptr, 0, options_relay);

    tox_options_free(options_alice);
    tox_options_free(options_bob);
    tox_options_free(options_relay);

    if (!alice || !bob || !relay) {
        fprintf(stderr, "Failed to create nodes\n");
        return 1;
    }

    uint8_t relay_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox_node_get_tox(relay), relay_dht_id);

    uint16_t relay_tcp_port = tox_self_get_tcp_port(tox_node_get_tox(relay), nullptr);

    Tox_Err_Bootstrap berr;

    // Both Alice and Bob use the Relay for TCP and DHT bootstrapping
    tox_add_tcp_relay(tox_node_get_tox(alice), "127.0.0.1", relay_tcp_port, relay_dht_id, &berr);
    tox_add_tcp_relay(tox_node_get_tox(bob), "127.0.0.1", relay_tcp_port, relay_dht_id, &berr);

    tox_node_bootstrap(alice, relay);
    tox_node_bootstrap(bob, relay);

    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    tox_scenario_free(s);
    free(alice_state);
    free(bob_state);

    return (res == TOX_SCENARIO_DONE) ? 0 : 1;
}

#undef RELAY_TCP_PORT
