/* Tests that we can send lossless packets.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
    uint32_t index;
    uint64_t clock;

    bool custom_packet_received;
} State;

#include "run_auto_test.h"

#define LOSSLESS_PACKET_FILLER 160

static void handle_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                   void *user_data)
{
    State *state = (State *)user_data;

    uint8_t cmp_packet[TOX_MAX_CUSTOM_PACKET_SIZE];
    memset(cmp_packet, LOSSLESS_PACKET_FILLER, sizeof(cmp_packet));

    if (length == TOX_MAX_CUSTOM_PACKET_SIZE && memcmp(data, cmp_packet, sizeof(cmp_packet)) == 0) {
        state->custom_packet_received = true;
    }
}

static void test_lossless_packet(Tox **toxes, State *state)
{
    tox_callback_friend_lossless_packet(toxes[1], &handle_lossless_packet);
    uint8_t packet[TOX_MAX_CUSTOM_PACKET_SIZE + 1];
    memset(packet, LOSSLESS_PACKET_FILLER, sizeof(packet));

    bool ret = tox_friend_send_lossless_packet(toxes[0], 0, packet, sizeof(packet), nullptr);
    ck_assert_msg(ret == false, "should not be able to send custom packets this big %i", ret);

    ret = tox_friend_send_lossless_packet(toxes[0], 0, packet, TOX_MAX_CUSTOM_PACKET_SIZE, nullptr);
    ck_assert_msg(ret == true, "tox_friend_send_lossless_packet fail %i", ret);

    do {
        iterate_all_wait(2, toxes, state, ITERATION_INTERVAL);
    } while (!state[1].custom_packet_received);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, test_lossless_packet);
    return 0;
}
