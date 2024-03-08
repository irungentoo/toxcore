/*
 * Tests message sending capabilities, including:
 * - The ability to send/receive plain, action, and custom messages
 * - The lossless UDP implementation
 * - The packet splitting implementation
 * - The ignore feature
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "auto_test_support.h"
#include "check_compat.h"
#include "../toxcore/util.h"

typedef struct State {
    uint32_t peer_id;
    bool peer_joined;
    bool message_sent;
    bool message_received;
    Tox_Group_Message_Id pseudo_msg_id;
    bool private_message_received;
    size_t custom_packets_received;
    size_t custom_private_packets_received;
    bool lossless_check;
    bool wraparound_check;
    int32_t last_msg_recv;
} State;

#define NUM_GROUP_TOXES 2
#define MAX_NUM_MESSAGES_LOSSLESS_TEST 300
#define MAX_NUM_MESSAGES_WRAPAROUND_TEST 9001

#define TEST_MESSAGE "Where is it I've read that someone condemned to death says or thinks, an hour before his death, that if he had to live on some high rock, on such a narrow ledge that he'd only room to stand, and the ocean, everlasting darkness, everlasting solitude, everlasting tempest around him, if he had to remain standing on a square yard of space all his life, a thousand years, eternity, it were better to live so than to die at once. Only to live, to live and live! Life, whatever it may be!"
#define TEST_MESSAGE_LEN (sizeof(TEST_MESSAGE) - 1)

#define TEST_GROUP_NAME "Utah Data Center"
#define TEST_GROUP_NAME_LEN (sizeof(TEST_GROUP_NAME) - 1)

#define TEST_PRIVATE_MESSAGE "Don't spill yer beans"
#define TEST_PRIVATE_MESSAGE_LEN (sizeof(TEST_PRIVATE_MESSAGE) - 1)

#define TEST_CUSTOM_PACKET "Why'd ya spill yer beans?"
#define TEST_CUSTOM_PACKET_LEN (sizeof(TEST_CUSTOM_PACKET) - 1)

#define TEST_CUSTOM_PACKET_LARGE "Where is it I've read that someone condemned to death says or thinks, an hour before his death, that if he had to live on some high rock, on such a narrow ledge that he'd only room to stand, and the ocean, everlasting darkness, everlasting solitude, everlasting tempest around him, if he had to remain standing on a square yard of space all his life, a thousand years, eternity, it were better to live so than to die at once. Only to live, to live and live! Life, whatever it may be! ...............................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................0123456789"
#define TEST_CUSTOM_PACKET_LARGE_LEN (sizeof(TEST_CUSTOM_PACKET_LARGE) - 1)
static_assert(TEST_CUSTOM_PACKET_LARGE_LEN == TOX_GROUP_MAX_CUSTOM_LOSSY_PACKET_LENGTH, "Should be max");

#define TEST_CUSTOM_PRIVATE_PACKET "This is a custom private packet. Enjoy."
#define TEST_CUSTOM_PRIVATE_PACKET_LEN (sizeof(TEST_CUSTOM_PRIVATE_PACKET) - 1)

#define IGNORE_MESSAGE "Am I bothering you?"
#define IGNORE_MESSAGE_LEN (sizeof(IGNORE_MESSAGE) - 1)

#define PEER0_NICK "Thomas"
#define PEER0_NICK_LEN (sizeof(PEER0_NICK) - 1)

#define PEER1_NICK "Winslow"
#define PEER1_NICK_LEN (sizeof(PEER1_NICK) - 1)

static uint16_t get_message_checksum(const uint8_t *message, uint16_t length)
{
    uint16_t sum = 0;

    for (size_t i = 0; i < length; ++i) {
        sum += message[i];
    }

    return sum;
}

static void group_invite_handler(const Tox_Event_Group_Invite *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    const uint32_t friend_number = tox_event_group_invite_get_friend_number(event);
    const uint8_t *invite_data = tox_event_group_invite_get_invite_data(event);
    const size_t length = tox_event_group_invite_get_invite_data_length(event);

    printf("invite arrived; accepting\n");
    Tox_Err_Group_Invite_Accept err_accept;
    tox_group_invite_accept(autotox->tox, friend_number, invite_data, length, (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN,
                            nullptr, 0, &err_accept);
    ck_assert(err_accept == TOX_ERR_GROUP_INVITE_ACCEPT_OK);
}

static void group_join_fail_handler(const Tox_Event_Group_Join_Fail *event, void *user_data)
{
    const Tox_Group_Join_Fail fail_type = tox_event_group_join_fail_get_fail_type(event);
    printf("join failed: %d\n", fail_type);
}

static void group_peer_join_handler(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint32_t peer_id = tox_event_group_peer_join_get_peer_id(event);

    ck_assert_msg(state->peer_joined == false, "Peer timedout");

    printf("peer %u joined, sending message\n", peer_id);
    state->peer_joined = true;
    state->peer_id = peer_id;
}

static void group_custom_private_packet_handler(const Tox_Event_Group_Custom_Private_Packet *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    const uint32_t groupnumber = tox_event_group_custom_private_packet_get_group_number(event);
    const uint32_t peer_id = tox_event_group_custom_private_packet_get_peer_id(event);
    const uint8_t *data = tox_event_group_custom_private_packet_get_data(event);
    const size_t length = tox_event_group_custom_private_packet_get_data_length(event);

    ck_assert_msg(length == TEST_CUSTOM_PRIVATE_PACKET_LEN,
                  "Failed to receive custom private packet. Invalid length: %zu\n", length);

    char message_buf[TOX_MAX_CUSTOM_PACKET_SIZE + 1];
    memcpy(message_buf, data, length);
    message_buf[length] = 0;

    Tox_Err_Group_Peer_Query q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(autotox->tox, groupnumber, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_peer_get_name(autotox->tox, groupnumber, peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(memcmp(peer_name, PEER0_NICK, peer_name_len) == 0);

    Tox_Err_Group_Self_Query s_err;
    size_t self_name_len = tox_group_self_get_name_size(autotox->tox, groupnumber, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_name_len <= TOX_MAX_NAME_LENGTH);

    char self_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_self_get_name(autotox->tox, groupnumber, (uint8_t *)self_name, &s_err);
    self_name[self_name_len] = 0;

    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(self_name, PEER1_NICK, self_name_len) == 0);

    printf("%s sent custom private packet to %s: %s\n", peer_name, self_name, message_buf);
    ck_assert(memcmp(message_buf, TEST_CUSTOM_PRIVATE_PACKET, length) == 0);

    State *state = (State *)autotox->state;

    ++state->custom_private_packets_received;
}

static void group_custom_packet_handler(const Tox_Event_Group_Custom_Packet *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    const uint32_t groupnumber = tox_event_group_custom_packet_get_group_number(event);
    const uint32_t peer_id = tox_event_group_custom_packet_get_peer_id(event);
    const uint8_t *data = tox_event_group_custom_packet_get_data(event);
    const size_t length = tox_event_group_custom_packet_get_data_length(event);

    ck_assert_msg(length == TEST_CUSTOM_PACKET_LEN, "Failed to receive custom packet. Invalid length: %zu\n", length);

    char message_buf[TOX_MAX_CUSTOM_PACKET_SIZE + 1];
    memcpy(message_buf, data, length);
    message_buf[length] = 0;

    Tox_Err_Group_Peer_Query q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(autotox->tox, groupnumber, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_peer_get_name(autotox->tox, groupnumber, peer_id, (uint8_t *)peer_name, &q_err);
    peer_name[peer_name_len] = 0;

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(memcmp(peer_name, PEER0_NICK, peer_name_len) == 0);

    Tox_Err_Group_Self_Query s_err;
    size_t self_name_len = tox_group_self_get_name_size(autotox->tox, groupnumber, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_name_len <= TOX_MAX_NAME_LENGTH);

    char self_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_self_get_name(autotox->tox, groupnumber, (uint8_t *)self_name, &s_err);
    self_name[self_name_len] = 0;

    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(self_name, PEER1_NICK, self_name_len) == 0);

    printf("%s sent custom packet to %s: %s\n", peer_name, self_name, message_buf);
    ck_assert(memcmp(message_buf, TEST_CUSTOM_PACKET, length) == 0);

    State *state = (State *)autotox->state;

    ++state->custom_packets_received;
}

static void group_custom_packet_large_handler(const Tox_Event_Group_Custom_Packet *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    const uint8_t *data = tox_event_group_custom_packet_get_data(event);
    const size_t length = tox_event_group_custom_packet_get_data_length(event);

    ck_assert_msg(length == TEST_CUSTOM_PACKET_LARGE_LEN, "Failed to receive large custom packet. Invalid length: %zu\n", length);

    ck_assert(memcmp(data, TEST_CUSTOM_PACKET_LARGE, length) == 0);

    State *state = (State *)autotox->state;

    ++state->custom_packets_received;
}

static void group_message_handler(const Tox_Event_Group_Message *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    const uint32_t groupnumber = tox_event_group_message_get_group_number(event);
    const uint32_t peer_id = tox_event_group_message_get_peer_id(event);
    const uint8_t *message = tox_event_group_message_get_message(event);
    const size_t length = tox_event_group_message_get_message_length(event);
    const uint32_t pseudo_msg_id = tox_event_group_message_get_message_id(event);

    ck_assert(!(length == IGNORE_MESSAGE_LEN && memcmp(message, IGNORE_MESSAGE, length) == 0));
    ck_assert_msg(length == TEST_MESSAGE_LEN, "Failed to receive message. Invalid length: %zu\n", length);

    char message_buf[TOX_GROUP_MAX_MESSAGE_LENGTH + 1];
    memcpy(message_buf, message, length);
    message_buf[length] = 0;

    Tox_Err_Group_Peer_Query q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(autotox->tox, groupnumber, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_peer_get_name(autotox->tox, groupnumber, peer_id, (uint8_t *)peer_name, &q_err);
    peer_name[peer_name_len] = 0;

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(memcmp(peer_name, PEER0_NICK, peer_name_len) == 0);

    Tox_Err_Group_Self_Query s_err;
    size_t self_name_len = tox_group_self_get_name_size(autotox->tox, groupnumber, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_name_len <= TOX_MAX_NAME_LENGTH);

    char self_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_self_get_name(autotox->tox, groupnumber, (uint8_t *)self_name, &s_err);
    self_name[self_name_len] = 0;

    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(self_name, PEER1_NICK, self_name_len) == 0);

    printf("%s sent message to %s:(id:%u) %s\n", peer_name, self_name, pseudo_msg_id, message_buf);
    ck_assert(memcmp(message_buf, TEST_MESSAGE, length) == 0);

    State *state = (State *)autotox->state;

    state->message_received = true;
    state->pseudo_msg_id = pseudo_msg_id;
}

static void group_private_message_handler(const Tox_Event_Group_Private_Message *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    const uint32_t groupnumber = tox_event_group_private_message_get_group_number(event);
    const uint32_t peer_id = tox_event_group_private_message_get_peer_id(event);
    const Tox_Message_Type type = tox_event_group_private_message_get_message_type(event);
    const uint8_t *message = tox_event_group_private_message_get_message(event);
    const size_t length = tox_event_group_private_message_get_message_length(event);
    const Tox_Group_Message_Id pseudo_msg_id = tox_event_group_private_message_get_message_id(event);

    ck_assert_msg(length == TEST_PRIVATE_MESSAGE_LEN, "Failed to receive message. Invalid length: %zu\n", length);

    char message_buf[TOX_GROUP_MAX_MESSAGE_LENGTH + 1];
    memcpy(message_buf, message, length);
    message_buf[length] = 0;

    Tox_Err_Group_Peer_Query q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(autotox->tox, groupnumber, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_peer_get_name(autotox->tox, groupnumber, peer_id, (uint8_t *)peer_name, &q_err);
    peer_name[peer_name_len] = 0;

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(memcmp(peer_name, PEER0_NICK, peer_name_len) == 0);

    Tox_Err_Group_Self_Query s_err;
    size_t self_name_len = tox_group_self_get_name_size(autotox->tox, groupnumber, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_name_len <= TOX_MAX_NAME_LENGTH);

    char self_name[TOX_MAX_NAME_LENGTH + 1];
    tox_group_self_get_name(autotox->tox, groupnumber, (uint8_t *)self_name, &s_err);
    self_name[self_name_len] = 0;

    ck_assert(s_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(self_name, PEER1_NICK, self_name_len) == 0);

    printf("%s sent private action to %s:(id: %u) %s\n", peer_name, self_name, pseudo_msg_id, message_buf);
    ck_assert(memcmp(message_buf, TEST_PRIVATE_MESSAGE, length) == 0);

    ck_assert(type == TOX_MESSAGE_TYPE_ACTION);

    State *state = (State *)autotox->state;

    state->private_message_received = true;
    state->pseudo_msg_id = pseudo_msg_id;
}

static void group_message_handler_lossless_test(const Tox_Event_Group_Message *event, void *user_data)
{
    const uint8_t *message = tox_event_group_message_get_message(event);
    const size_t length = tox_event_group_message_get_message_length(event);

    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    ck_assert(length >= 4 && length <= TOX_GROUP_MAX_MESSAGE_LENGTH);

    uint16_t start;
    uint16_t checksum;
    memcpy(&start, message, sizeof(uint16_t));
    memcpy(&checksum, message + sizeof(uint16_t), sizeof(uint16_t));

    ck_assert_msg(start == state->last_msg_recv + 1, "Expected %d, got start %u", state->last_msg_recv + 1, start);
    ck_assert_msg(checksum == get_message_checksum(message + 4, length - 4), "Wrong checksum");

    state->last_msg_recv = start;

    if (state->last_msg_recv == MAX_NUM_MESSAGES_LOSSLESS_TEST) {
        state->lossless_check = true;
    }
}
static void group_message_handler_wraparound_test(const Tox_Event_Group_Message *event, void *user_data)
{
    const uint8_t *message = tox_event_group_message_get_message(event);
    const size_t length = tox_event_group_message_get_message_length(event);

    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    ck_assert(length == 2);

    uint16_t num;
    memcpy(&num, message, sizeof(uint16_t));

    ck_assert_msg(num == state->last_msg_recv + 1, "Expected %d, got start %u", state->last_msg_recv + 1, num);

    state->last_msg_recv = num;

    if (state->last_msg_recv == MAX_NUM_MESSAGES_WRAPAROUND_TEST) {
        state->wraparound_check = true;
    }
}

static void group_message_test(AutoTox *autotoxes)
{
    ck_assert_msg(NUM_GROUP_TOXES >= 2, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    const Random *rng = os_random();
    ck_assert(rng != nullptr);

    Tox *tox0 = autotoxes[0].tox;
    const Tox *tox1 = autotoxes[1].tox;

    State *state0 = (State *)autotoxes[0].state;
    State *state1 = (State *)autotoxes[1].state;

    // initialize to different values
    state0->pseudo_msg_id = 0;
    state1->pseudo_msg_id = 1;

    tox_events_callback_group_invite(autotoxes[1].dispatch, group_invite_handler);
    tox_events_callback_group_join_fail(autotoxes[1].dispatch, group_join_fail_handler);
    tox_events_callback_group_peer_join(autotoxes[1].dispatch, group_peer_join_handler);
    tox_events_callback_group_join_fail(autotoxes[0].dispatch, group_join_fail_handler);
    tox_events_callback_group_peer_join(autotoxes[0].dispatch, group_peer_join_handler);
    tox_events_callback_group_message(autotoxes[0].dispatch, group_message_handler);
    tox_events_callback_group_custom_packet(autotoxes[0].dispatch, group_custom_packet_handler);
    tox_events_callback_group_custom_private_packet(autotoxes[0].dispatch, group_custom_private_packet_handler);
    tox_events_callback_group_private_message(autotoxes[0].dispatch, group_private_message_handler);

    Tox_Err_Group_Send_Message err_send;

    fprintf(stderr, "Tox 0 creates new group and invites tox1...\n");

    // tox0 makes new group.
    Tox_Err_Group_New err_new;
    const uint32_t group_number = tox_group_new(tox0, TOX_GROUP_PRIVACY_STATE_PRIVATE, (const uint8_t *)TEST_GROUP_NAME,
                                  TEST_GROUP_NAME_LEN, (const uint8_t *)PEER1_NICK, PEER1_NICK_LEN, &err_new);

    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    // tox0 invites tox1
    Tox_Err_Group_Invite_Friend err_invite;
    tox_group_invite_friend(tox0, group_number, 0, &err_invite);
    ck_assert(err_invite == TOX_ERR_GROUP_INVITE_FRIEND_OK);

    while (!state0->message_received) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

        if (state1->peer_joined && !state1->message_sent) {
            state1->pseudo_msg_id = tox_group_send_message(
                                        tox1, group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)TEST_MESSAGE,
                                        TEST_MESSAGE_LEN, &err_send);
            ck_assert(err_send == TOX_ERR_GROUP_SEND_MESSAGE_OK);
            state1->message_sent = true;
        }
    }

    ck_assert_msg(state0->pseudo_msg_id == state1->pseudo_msg_id, "id0:%u id1:%u",
                  state0->pseudo_msg_id, state1->pseudo_msg_id);

    // Make sure we're still connected to each friend
    Tox_Connection conn_1 = tox_friend_get_connection_status(tox0, 0, nullptr);
    Tox_Connection conn_2 = tox_friend_get_connection_status(tox1, 0, nullptr);

    ck_assert(conn_1 != TOX_CONNECTION_NONE && conn_2 != TOX_CONNECTION_NONE);

    // tox0 ignores tox1
    Tox_Err_Group_Set_Ignore ig_err;
    tox_group_set_ignore(tox0, group_number, state0->peer_id, true, &ig_err);
    ck_assert_msg(ig_err == TOX_ERR_GROUP_SET_IGNORE_OK, "%d", ig_err);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    // tox1 sends group a message which should not be seen by tox0's message handler
    tox_group_send_message(tox1, group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)IGNORE_MESSAGE,
                           IGNORE_MESSAGE_LEN, &err_send);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    // tox0 unignores tox1
    tox_group_set_ignore(tox0, group_number, state0->peer_id, false, &ig_err);
    ck_assert_msg(ig_err == TOX_ERR_GROUP_SET_IGNORE_OK, "%d", ig_err);

    fprintf(stderr, "Sending private action...\n");

    // tox1 sends a private action to tox0
    Tox_Err_Group_Send_Private_Message m_err;
    state1->pseudo_msg_id = tox_group_send_private_message(tox1, group_number, state1->peer_id,
                            TOX_MESSAGE_TYPE_ACTION, (const uint8_t *)TEST_PRIVATE_MESSAGE,
                            TEST_PRIVATE_MESSAGE_LEN, &m_err);

    ck_assert_msg(m_err == TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK, "%d", m_err);

    while (!state0->private_message_received) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    ck_assert_msg(state0->pseudo_msg_id == state1->pseudo_msg_id, "id0:%u id1:%u",
                  state0->pseudo_msg_id, state1->pseudo_msg_id);

    fprintf(stderr, "Sending custom packets...\n");

    // tox0 sends a lossless and lossy custom packet to tox1
    Tox_Err_Group_Send_Custom_Packet c_err;
    tox_group_send_custom_packet(tox1, group_number, true, (const uint8_t *)TEST_CUSTOM_PACKET, TEST_CUSTOM_PACKET_LEN,
                                 &c_err);
    ck_assert_msg(c_err == TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK, "%d", c_err);

    tox_group_send_custom_packet(tox1, group_number, false, (const uint8_t *)TEST_CUSTOM_PACKET, TEST_CUSTOM_PACKET_LEN,
                                 &c_err);
    ck_assert_msg(c_err == TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK, "%d", c_err);

    fprintf(stderr, "Sending custom private packets...\n");

    // tox0 sends a lossless and lossy custom private packet to tox1
    Tox_Err_Group_Send_Custom_Private_Packet cperr;
    tox_group_send_custom_private_packet(tox1, group_number, state1->peer_id, true,
                                         (const uint8_t *)TEST_CUSTOM_PRIVATE_PACKET,
                                         TEST_CUSTOM_PRIVATE_PACKET_LEN, &cperr);

    ck_assert_msg(cperr == TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK, "%d", cperr);

    tox_group_send_custom_private_packet(tox1, group_number, state1->peer_id, false,
                                         (const uint8_t *)TEST_CUSTOM_PRIVATE_PACKET,
                                         TEST_CUSTOM_PRIVATE_PACKET_LEN, &cperr);

    ck_assert_msg(cperr == TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK, "%d", cperr);

    while (state0->custom_packets_received < 2 || state0->custom_private_packets_received < 2) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    // tox0 sends a large max sized lossy custom packet

    // overwrite callback for larger packet
    tox_events_callback_group_custom_packet(autotoxes[0].dispatch, group_custom_packet_large_handler);

    tox_group_send_custom_packet(tox1, group_number, false, (const uint8_t *)TEST_CUSTOM_PACKET_LARGE, TEST_CUSTOM_PACKET_LARGE_LEN,
                                 &c_err);
    ck_assert_msg(c_err == TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK, "%d", c_err);

    while (state0->custom_packets_received < 3) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    uint8_t m[TOX_GROUP_MAX_MESSAGE_LENGTH] = {0};

    fprintf(stderr, "Doing lossless packet test...\n");

    tox_events_callback_group_message(autotoxes[1].dispatch, group_message_handler_lossless_test);
    state1->last_msg_recv = -1;

    // lossless and packet splitting/reassembly test
    for (uint16_t i = 0; i <= MAX_NUM_MESSAGES_LOSSLESS_TEST; ++i) {
        if (i % 10 == 0) {
            iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
        }

        uint16_t message_size = min_u16(4 + (random_u16(rng) % TOX_GROUP_MAX_MESSAGE_LENGTH), TOX_GROUP_MAX_MESSAGE_LENGTH);

        memcpy(m, &i, sizeof(uint16_t));

        for (size_t j = 4; j < message_size; ++j) {
            m[j] = random_u32(rng);
        }

        const uint16_t checksum = get_message_checksum(m + 4, message_size - 4);

        memcpy(m + 2, &checksum, sizeof(uint16_t));

        tox_group_send_message(tox0, group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)m, message_size, &err_send);

        ck_assert(err_send == TOX_ERR_GROUP_SEND_MESSAGE_OK);
    }

    while (!state1->lossless_check) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    state1->last_msg_recv = -1;
    tox_events_callback_group_message(autotoxes[1].dispatch, group_message_handler_wraparound_test);

    fprintf(stderr, "Doing wraparound test...\n");

    // packet array wrap-around test
    for (uint16_t i = 0; i <= MAX_NUM_MESSAGES_WRAPAROUND_TEST; ++i) {
        if (i % 10 == 0) {
            iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
        }

        memcpy(m, &i, sizeof(uint16_t));

        tox_group_send_message(tox0, group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)m, 2, &err_send);
        ck_assert(err_send == TOX_ERR_GROUP_SEND_MESSAGE_OK);
    }

    while (!state1->wraparound_check) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        Tox_Err_Group_Leave err_exit;
        tox_group_leave(autotoxes[i].tox, group_number, nullptr, 0, &err_exit);
        ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
    }

    fprintf(stderr, "All tests passed!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options autotest_opts = default_run_auto_options();
    autotest_opts.graph = GRAPH_COMPLETE;

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_message_test, sizeof(State), &autotest_opts);
    return 0;
}

#undef NUM_GROUP_TOXES
#undef PEER1_NICK
#undef PEER1_NICK_LEN
#undef PEER0_NICK
#undef PEER0_NICK_LEN
#undef TEST_GROUP_NAME
#undef TEST_GROUP_NAME_LEN
#undef TEST_MESSAGE
#undef TEST_MESSAGE_LEN
#undef TEST_PRIVATE_MESSAGE_LEN
#undef TEST_CUSTOM_PACKET
#undef TEST_CUSTOM_PACKET_LEN
#undef TEST_CUSTOM_PACKET_LARGE
#undef TEST_CUSTOM_PACKET_LARGE_LEN
#undef TEST_CUSTOM_PRIVATE_PACKET
#undef TEST_CUSTOM_PRIVATE_PACKET_LEN
#undef IGNORE_MESSAGE
#undef IGNORE_MESSAGE_LEN
#undef MAX_NUM_MESSAGES_LOSSLESS_TEST
#undef MAX_NUM_MESSAGES_WRAPAROUND_TEST
