/* Tests that we can send lossy packets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/util.h"
#include "check_compat.h"

typedef struct State {
    bool custom_packet_received;
} State;

#include "auto_test_support.h"

#define LOSSY_PACKET_FILLER 200

static void handle_lossy_packet(const Tox_Event_Friend_Lossy_Packet *event, void *user_data)
{
    //const uint32_t friend_number = tox_event_friend_lossy_packet_get_friend_number(event);
    const uint8_t *data = tox_event_friend_lossy_packet_get_data(event);
    const uint32_t data_length = tox_event_friend_lossy_packet_get_data_length(event);

    uint8_t *cmp_packet = (uint8_t *)malloc(tox_max_custom_packet_size());
    ck_assert(cmp_packet != nullptr);
    memset(cmp_packet, LOSSY_PACKET_FILLER, tox_max_custom_packet_size());

    if (data_length == tox_max_custom_packet_size() && memcmp(data, cmp_packet, tox_max_custom_packet_size()) == 0) {
        const AutoTox *autotox = (AutoTox *)user_data;
        State *state = (State *)autotox->state;
        state->custom_packet_received = true;
    }

    free(cmp_packet);
}

static void test_lossy_packet(AutoTox *autotoxes)
{
    tox_events_callback_friend_lossy_packet(autotoxes[1].dispatch, &handle_lossy_packet);
    const size_t packet_size = tox_max_custom_packet_size() + 1;
    uint8_t *packet = (uint8_t *)malloc(packet_size);
    ck_assert(packet != nullptr);
    memset(packet, LOSSY_PACKET_FILLER, packet_size);

    bool ret = tox_friend_send_lossy_packet(autotoxes[0].tox, 0, packet, packet_size, nullptr);
    ck_assert_msg(ret == false, "should not be able to send custom packets this big %i", ret);

    ret = tox_friend_send_lossy_packet(autotoxes[0].tox, 0, packet, tox_max_custom_packet_size(), nullptr);
    ck_assert_msg(ret == true, "tox_friend_send_lossy_packet fail %i", ret);

    free(packet);

    do {
        iterate_all_wait(autotoxes, 2, ITERATION_INTERVAL);
    } while (!((State *)autotoxes[1].state)->custom_packet_received);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;

    run_auto_test(nullptr, 2, test_lossy_packet, sizeof(State), &options);

    return 0;
}
