#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PEER0_NICK "Thomas"
#define PEER0_NICK_LEN (sizeof(PEER0_NICK) - 1)
#define PEER1_NICK "Winslow"
#define PEER1_NICK_LEN (sizeof(PEER1_NICK) - 1)
#define TEST_GROUP_NAME "Utah Data Center"
#define TEST_GROUP_NAME_LEN (sizeof(TEST_GROUP_NAME) - 1)
#define TEST_MESSAGE "Where is it I've read that someone condemned to death says or thinks..."
#define TEST_MESSAGE_LEN (sizeof(TEST_MESSAGE) - 1)
#define TEST_PRIVATE_MESSAGE "Don't spill yer beans"
#define TEST_PRIVATE_MESSAGE_LEN (sizeof(TEST_PRIVATE_MESSAGE) - 1)
#define TEST_CUSTOM_PACKET "Why'd ya spill yer beans?"
#define TEST_CUSTOM_PACKET_LEN (sizeof(TEST_CUSTOM_PACKET) - 1)
#define TEST_CUSTOM_PRIVATE_PACKET "This is a custom private packet. Enjoy."
#define TEST_CUSTOM_PRIVATE_PACKET_LEN (sizeof(TEST_CUSTOM_PRIVATE_PACKET) - 1)
#define MAX_NUM_MESSAGES_LOSSLESS_TEST 100

typedef struct {
    uint32_t group_number;
    uint32_t peer_id;
    bool peer_joined;
    bool message_received;
    bool private_message_received;
    size_t custom_packets_received;
    size_t custom_private_packets_received;
    int32_t last_msg_recv;
    bool lossless_done;
} GroupState;

static uint16_t get_message_checksum(const uint8_t *message, uint16_t length)
{
    uint16_t sum = 0;
    for (size_t i = 0; i < length; ++i) {
        sum += message[i];
    }
    return sum;
}

static void on_group_invite(const Tox_Event_Group_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    Tox_Err_Group_Invite_Accept err;
    state->group_number = tox_group_invite_accept(tox_node_get_tox(self),
                          tox_event_group_invite_get_friend_number(event),
                          tox_event_group_invite_get_invite_data(event),
                          tox_event_group_invite_get_invite_data_length(event),
                          (const uint8_t *)PEER1_NICK, PEER1_NICK_LEN, nullptr, 0, &err);
    tox_node_log(self, "Accepted group invite, group %u", state->group_number);
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->peer_joined = true;
    state->peer_id = tox_event_group_peer_join_get_peer_id(event);
    tox_node_log(self, "Peer %u joined group", state->peer_id);
}

static void on_group_message(const Tox_Event_Group_Message *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    const uint8_t *msg = tox_event_group_message_get_message(event);
    size_t len = tox_event_group_message_get_message_length(event);

    if (len == TEST_MESSAGE_LEN && memcmp(msg, TEST_MESSAGE, len) == 0) {
        state->message_received = true;
        tox_node_log(self, "Received group message");
    } else if (len >= 4) {
        uint16_t start, checksum;
        memcpy(&start, msg, 2);
        memcpy(&checksum, msg + 2, 2);
        if (checksum == get_message_checksum(msg + 4, len - 4)) {
            state->last_msg_recv = start;
            if (start == MAX_NUM_MESSAGES_LOSSLESS_TEST) {
                state->lossless_done = true;
            }
        }
    }
}

static void on_group_private_message(const Tox_Event_Group_Private_Message *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    const uint8_t *msg = tox_event_group_private_message_get_message(event);
    size_t len = tox_event_group_private_message_get_message_length(event);

    if (len == TEST_PRIVATE_MESSAGE_LEN && memcmp(msg, TEST_PRIVATE_MESSAGE, len) == 0) {
        state->private_message_received = true;
        tox_node_log(self, "Received private group message");
    }
}

static void on_group_custom_packet(const Tox_Event_Group_Custom_Packet *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->custom_packets_received++;
    tox_node_log(self, "Received custom packet %zu", state->custom_packets_received);
}

static void on_group_custom_private_packet(const Tox_Event_Group_Custom_Private_Packet *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->custom_private_packets_received++;
    tox_node_log(self, "Received custom private packet %zu", state->custom_private_packets_received);
}

static void peer0_script(ToxNode *self, void *ctx)
{
    GroupState *state = (GroupState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_message(dispatch, on_group_message);
    tox_events_callback_group_private_message(dispatch, on_group_private_message);
    tox_events_callback_group_custom_packet(dispatch, on_group_custom_packet);
    tox_events_callback_group_custom_private_packet(dispatch, on_group_custom_private_packet);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PRIVATE, (const uint8_t *)TEST_GROUP_NAME, TEST_GROUP_NAME_LEN, (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN, nullptr);
    tox_group_invite_friend(tox, state->group_number, 0, nullptr);
    tox_node_log(self, "Created group and invited friend");

    WAIT_UNTIL(state->peer_joined);
    WAIT_UNTIL(state->message_received);
    WAIT_UNTIL(state->private_message_received);
    WAIT_UNTIL(state->custom_packets_received >= 2);
    WAIT_UNTIL(state->custom_private_packets_received >= 2);

    // Lossless test
    uint8_t m[TOX_GROUP_MAX_MESSAGE_LENGTH];
    for (uint16_t i = 0; i <= MAX_NUM_MESSAGES_LOSSLESS_TEST; ++i) {
        uint32_t size = 4 + (rand() % 100);
        memcpy(m, &i, 2);
        for (size_t j = 4; j < size; ++j) {
            uint32_t val = rand() % 256;
            m[j] = (uint8_t)val;
        }
        uint16_t checksum = get_message_checksum(m + 4, (uint16_t)(size - 4));
        memcpy(m + 2, &checksum, 2);
        tox_group_send_message(tox, state->group_number, TOX_MESSAGE_TYPE_NORMAL, m, size, nullptr);
        if (i % 10 == 0) {
            tox_scenario_yield(self);
        }
    }

    tox_node_log(self, "Done");
}

static void peer1_script(ToxNode *self, void *ctx)
{
    const GroupState *state = (const GroupState *)ctx;
    const Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_group_invite(dispatch, on_group_invite);
    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_message(dispatch, on_group_message);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(state->peer_joined);

    tox_group_send_message(tox, state->group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)TEST_MESSAGE, TEST_MESSAGE_LEN, nullptr);
    tox_group_send_private_message(tox, state->group_number, state->peer_id, TOX_MESSAGE_TYPE_ACTION, (const uint8_t *)TEST_PRIVATE_MESSAGE, TEST_PRIVATE_MESSAGE_LEN, nullptr);

    tox_group_send_custom_packet(tox, state->group_number, true, (const uint8_t *)TEST_CUSTOM_PACKET, TEST_CUSTOM_PACKET_LEN, nullptr);
    tox_group_send_custom_packet(tox, state->group_number, false, (const uint8_t *)TEST_CUSTOM_PACKET, TEST_CUSTOM_PACKET_LEN, nullptr);

    tox_group_send_custom_private_packet(tox, state->group_number, state->peer_id, true, (const uint8_t *)TEST_CUSTOM_PRIVATE_PACKET, TEST_CUSTOM_PRIVATE_PACKET_LEN, nullptr);
    tox_group_send_custom_private_packet(tox, state->group_number, state->peer_id, false, (const uint8_t *)TEST_CUSTOM_PRIVATE_PACKET, TEST_CUSTOM_PRIVATE_PACKET_LEN, nullptr);

    WAIT_UNTIL(state->lossless_done);
    tox_node_log(self, "Done");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    GroupState s0 = { .last_msg_recv = -1 }, s1 = { .last_msg_recv = -1 };

    ToxNode *n0 = tox_scenario_add_node(s, "Peer0", peer0_script, &s0, sizeof(GroupState));
    ToxNode *n1 = tox_scenario_add_node(s, "Peer1", peer1_script, &s1, sizeof(GroupState));

    tox_node_friend_add(n0, n1);
    tox_node_friend_add(n1, n0);
    tox_node_bootstrap(n0, n1);
    tox_node_bootstrap(n1, n0);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef PEER0_NICK
#undef PEER0_NICK_LEN
#undef PEER1_NICK
#undef PEER1_NICK_LEN
