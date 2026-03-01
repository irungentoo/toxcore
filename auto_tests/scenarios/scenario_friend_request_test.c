#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const uint8_t *message;
    size_t length;
} RequestData;

static void on_friend_request(const Tox_Event_Friend_Request *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    Tox *tox = tox_node_get_tox(self);
    const RequestData *data = (const RequestData *)tox_node_get_script_ctx(self);

    const uint8_t *msg = tox_event_friend_request_get_message(event);
    size_t len = tox_event_friend_request_get_message_length(event);

    if (len == data->length && memcmp(msg, data->message, len) == 0) {
        tox_friend_add_norequest(tox, tox_event_friend_request_get_public_key(event), nullptr);
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    RequestData *data = (RequestData *)ctx;

    WAIT_UNTIL(tox_node_is_self_connected(self));

    ToxNode *bob = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    uint8_t bob_addr[TOX_ADDRESS_SIZE];
    tox_node_get_address(bob, bob_addr);

    tox_friend_add(tox, bob_addr, data->message, data->length, nullptr);

    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_events_callback_friend_request(tox_node_get_dispatch(self), on_friend_request);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
}

static void test_with_message(int argc, char *argv[], const char *label, const uint8_t *message, size_t length)
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);
    tox_scenario_log(s, "Testing friend request: %s (length %zu)", label, length);
    RequestData data = {message, length};

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, &data, sizeof(RequestData));
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, &data, sizeof(RequestData));

    tox_node_bootstrap(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        exit(1);
    }
    tox_scenario_free(s);
}

int main(int argc, char *argv[])
{
    test_with_message(argc, argv, "Short", (const uint8_t *)"a", 1);
    test_with_message(argc, argv, "Medium", (const uint8_t *)"Hello, let\'s be friends!", 24);

    uint8_t long_msg[TOX_MAX_FRIEND_REQUEST_LENGTH];
    memset(long_msg, 'F', sizeof(long_msg));
    test_with_message(argc, argv, "Max length", long_msg, sizeof(long_msg));

    return 0;
}
