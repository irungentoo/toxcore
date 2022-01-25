/* Tests that we can send lossless packets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

typedef struct State {
    bool custom_packet_received;
} State;

#include "auto_test_support.h"

#define LOSSLESS_PACKET_FILLER 160

static void handle_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                   void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    uint8_t cmp_packet[TOX_MAX_CUSTOM_PACKET_SIZE];
    memset(cmp_packet, LOSSLESS_PACKET_FILLER, sizeof(cmp_packet));

    if (length == TOX_MAX_CUSTOM_PACKET_SIZE && memcmp(data, cmp_packet, sizeof(cmp_packet)) == 0) {
        state->custom_packet_received = true;
    }
}

static void test_lossless_packet(AutoTox *autotoxes)
{
    tox_callback_friend_lossless_packet(autotoxes[1].tox, &handle_lossless_packet);
    uint8_t packet[TOX_MAX_CUSTOM_PACKET_SIZE + 1];
    memset(packet, LOSSLESS_PACKET_FILLER, sizeof(packet));

    bool ret = tox_friend_send_lossless_packet(autotoxes[0].tox, 0, packet, sizeof(packet), nullptr);
    ck_assert_msg(ret == false, "should not be able to send custom packets this big %i", ret);

    ret = tox_friend_send_lossless_packet(autotoxes[0].tox, 0, packet, TOX_MAX_CUSTOM_PACKET_SIZE, nullptr);
    ck_assert_msg(ret == true, "tox_friend_send_lossless_packet fail %i", ret);

    do {
        iterate_all_wait(2, autotoxes, ITERATION_INTERVAL);
    } while (!((State *)autotoxes[1].state)->custom_packet_received);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options;
    options.graph = GRAPH_LINEAR;

    run_auto_test(nullptr, 2, test_lossless_packet, sizeof(State), &options);

    return 0;
}
