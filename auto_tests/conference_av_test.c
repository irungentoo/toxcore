/* Auto Tests: Conferences AV.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "../toxav/toxav.h"
#include "check_compat.h"

#define NUM_AV_GROUP_TOX 16
#define NUM_AV_DISCONNECT (NUM_AV_GROUP_TOX / 2)
#define NUM_AV_DISABLE (NUM_AV_GROUP_TOX / 2)

#include "auto_test_support.h"

typedef struct State {
    bool invited_next;

    uint32_t received_audio_peers[NUM_AV_GROUP_TOX];
    uint32_t received_audio_num;
} State;

static void handle_self_connection_status(
    const Tox_Event_Self_Connection_Status *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;

    const Tox_Connection connection_status = tox_event_self_connection_status_get_connection_status(event);
    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected\n", autotox->index);
    } else {
        printf("tox #%u: is now disconnected\n", autotox->index);
    }
}

static void handle_friend_connection_status(
    const Tox_Event_Friend_Connection_Status *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;

    const uint32_t friendnumber = tox_event_friend_connection_status_get_friend_number(event);
    const Tox_Connection connection_status = tox_event_friend_connection_status_get_connection_status(event);

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected to friend %u\n", autotox->index, friendnumber);
    } else {
        printf("tox #%u: is now disconnected from friend %u\n", autotox->index, friendnumber);
    }
}

static void audio_callback(void *tox, uint32_t groupnumber, uint32_t peernumber,
                           const int16_t *pcm, unsigned int samples, uint8_t channels, uint32_t
                           sample_rate, void *user_data)
{
    if (samples == 0) {
        return;
    }

    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    for (uint32_t i = 0; i < state->received_audio_num; ++i) {
        if (state->received_audio_peers[i] == peernumber) {
            return;
        }
    }

    ck_assert(state->received_audio_num < NUM_AV_GROUP_TOX);

    state->received_audio_peers[state->received_audio_num] = peernumber;
    ++state->received_audio_num;
}

static void handle_conference_invite(
    const Tox_Event_Conference_Invite *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;

    const uint32_t friend_number = tox_event_conference_invite_get_friend_number(event);
    const Tox_Conference_Type type = tox_event_conference_invite_get_type(event);
    const uint8_t *cookie = tox_event_conference_invite_get_cookie(event);
    const size_t length = tox_event_conference_invite_get_cookie_length(event);

    ck_assert_msg(type == TOX_CONFERENCE_TYPE_AV, "tox #%u: wrong conference type: %d", autotox->index, type);

    ck_assert_msg(toxav_join_av_groupchat(autotox->tox, friend_number, cookie, length, audio_callback, user_data) == 0,
                  "tox #%u: failed to join group", autotox->index);
}

static void handle_conference_connected(
    const Tox_Event_Conference_Connected *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    if (state->invited_next || tox_self_get_friend_list_size(autotox->tox) <= 1) {
        return;
    }

    Tox_Err_Conference_Invite err;
    tox_conference_invite(autotox->tox, 1, 0, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "tox #%u failed to invite next friend: err = %d", autotox->index,
                  err);
    printf("tox #%u: invited next friend\n", autotox->index);
    state->invited_next = true;
}

static bool toxes_are_disconnected_from_group(uint32_t tox_count, AutoTox *autotoxes,
        const bool *disconnected)
{
    uint32_t num_disconnected = 0;

    for (uint32_t i = 0; i < tox_count; ++i) {
        num_disconnected += disconnected[i];
    }

    for (uint32_t i = 0; i < tox_count; ++i) {
        if (disconnected[i]) {
            continue;
        }

        if (tox_conference_peer_count(autotoxes[i].tox, 0, nullptr) > tox_count - num_disconnected) {
            return false;
        }
    }

    return true;
}

static void disconnect_toxes(uint32_t tox_count, AutoTox *autotoxes,
                             const bool *disconnect, const bool *exclude)
{
    /* Fake a network outage for a set of peers D by iterating only the other
     * peers D' until the connections time out according to D', then iterating
     * only D until the connections time out according to D. */

    VLA(bool, disconnect_now, tox_count);
    bool invert = false;

    do {
        for (uint32_t i = 0; i < tox_count; ++i) {
            disconnect_now[i] = exclude[i] || (invert ^ disconnect[i]);
        }

        do {
            for (uint32_t i = 0; i < tox_count; ++i) {
                if (!disconnect_now[i]) {
                    Tox_Err_Events_Iterate err;
                    Tox_Events *events = tox_events_iterate(autotoxes[i].tox, true, &err);
                    tox_dispatch_invoke(autotoxes[i].dispatch, events, &autotoxes[i]);
                    tox_events_free(events);
                    autotoxes[i].clock += 1000;
                }
            }

            c_sleep(20);
        } while (!toxes_are_disconnected_from_group(tox_count, autotoxes, disconnect_now));

        invert = !invert;
    } while (invert);
}

static bool all_connected_to_group(uint32_t tox_count, AutoTox *autotoxes)
{
    for (uint32_t i = 0; i < tox_count; ++i) {
        if (tox_conference_peer_count(autotoxes[i].tox, 0, nullptr) < tox_count) {
            return false;
        }
    }

    return true;
}

/**
 * returns a random index at which a list of booleans is false
 * (some such index is required to exist)
 */
static uint32_t random_false_index(const Random *rng, const bool *list, const uint32_t length)
{
    uint32_t index;

    do {
        index = random_u32(rng) % length;
    } while (list[index]);

    return index;
}

static bool all_got_audio(AutoTox *autotoxes, const bool *disabled)
{
    uint32_t num_disabled = 0;

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        num_disabled += disabled[i];
    }

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        const State *state = (const State *)autotoxes[i].state;

        if (disabled[i] ^ (state->received_audio_num
                           != NUM_AV_GROUP_TOX - num_disabled - 1)) {
            return false;
        }
    }

    return true;
}

static void reset_received_audio(AutoTox *autotoxes)
{
    for (uint32_t j = 0; j < NUM_AV_GROUP_TOX; ++j) {
        ((State *)autotoxes[j].state)->received_audio_num = 0;
    }
}

#define GROUP_AV_TEST_SAMPLES 960

/* must have
 * GROUP_AV_AUDIO_ITERATIONS - NUM_AV_GROUP_TOX >= 2^n >= GROUP_JBUF_SIZE
 * for some n, to give messages time to be relayed and to let the jitter
 * buffers fill up. */
#define GROUP_AV_AUDIO_ITERATIONS (8 + NUM_AV_GROUP_TOX)

static bool test_audio(AutoTox *autotoxes, const bool *disabled, bool quiet)
{
    if (!quiet) {
        printf("testing sending and receiving audio\n");
    }

    const int16_t pcm[GROUP_AV_TEST_SAMPLES] = {0};

    reset_received_audio(autotoxes);

    for (uint32_t n = 0; n < GROUP_AV_AUDIO_ITERATIONS; ++n) {
        for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            if (disabled[i]) {
                continue;
            }

            if (toxav_group_send_audio(autotoxes[i].tox, 0, pcm, GROUP_AV_TEST_SAMPLES, 1, 48000) != 0) {
                if (!quiet) {
                    ck_abort_msg("#%u failed to send audio", autotoxes[i].index);
                }

                return false;
            }
        }

        iterate_all_wait(autotoxes, NUM_AV_GROUP_TOX, ITERATION_INTERVAL);

        if (all_got_audio(autotoxes, disabled)) {
            return true;
        }
    }

    if (!quiet) {
        ck_abort_msg("group failed to receive audio");
    }

    return false;
}

static void test_eventual_audio(AutoTox *autotoxes, const bool *disabled, uint64_t timeout)
{
    uint64_t start = autotoxes[0].clock;

    while (autotoxes[0].clock < start + timeout) {
        if (!test_audio(autotoxes, disabled, true)) {
            continue;
        }

        // It needs to succeed twice in a row for the test to pass.
        if (test_audio(autotoxes, disabled, true)) {
            printf("audio test successful after %d seconds\n", (int)((autotoxes[0].clock - start) / 1000));
            return;
        }
    }

    printf("audio seems not to be getting through: testing again with errors.\n");
    test_audio(autotoxes, disabled, false);
}

static void do_audio(AutoTox *autotoxes, uint32_t iterations)
{
    const int16_t pcm[GROUP_AV_TEST_SAMPLES] = {0};
    printf("running audio for %u iterations\n", iterations);

    for (uint32_t f = 0; f < iterations; ++f) {
        for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            ck_assert_msg(toxav_group_send_audio(autotoxes[i].tox, 0, pcm, GROUP_AV_TEST_SAMPLES, 1, 48000) == 0,
                          "#%u failed to send audio", autotoxes[i].index);
            iterate_all_wait(autotoxes, NUM_AV_GROUP_TOX, ITERATION_INTERVAL);
        }
    }
}

// should agree with value in groupav.c
#define GROUP_JBUF_DEAD_SECONDS 4

#define JITTER_SETTLE_TIME (GROUP_JBUF_DEAD_SECONDS*1000 + NUM_AV_GROUP_TOX*ITERATION_INTERVAL*(GROUP_AV_AUDIO_ITERATIONS+1))

static void run_conference_tests(AutoTox *autotoxes)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    bool disabled[NUM_AV_GROUP_TOX] = {0};

    test_audio(autotoxes, disabled, false);

    /* have everyone send audio for a bit so we can test that the audio
     * sequnums dropping to 0 on restart isn't a problem */
    do_audio(autotoxes, 20);

    printf("letting random toxes timeout\n");
    bool disconnected[NUM_AV_GROUP_TOX] = {0};
    bool restarting[NUM_AV_GROUP_TOX] = {0};

    ck_assert(NUM_AV_DISCONNECT < NUM_AV_GROUP_TOX);

    for (uint32_t i = 0; i < NUM_AV_DISCONNECT; ++i) {
        uint32_t disconnect = random_false_index(rng, disconnected, NUM_AV_GROUP_TOX);
        disconnected[disconnect] = true;

        if (i < NUM_AV_DISCONNECT / 2) {
            restarting[disconnect] = true;
            printf("Restarting #%u\n", autotoxes[disconnect].index);
        } else {
            printf("Disconnecting #%u\n", autotoxes[disconnect].index);
        }
    }

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (restarting[i]) {
            save_autotox(&autotoxes[i]);
            kill_autotox(&autotoxes[i]);
        }
    }

    disconnect_toxes(NUM_AV_GROUP_TOX, autotoxes, disconnected, restarting);

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (restarting[i]) {
            reload(&autotoxes[i]);
        }
    }

    printf("reconnecting toxes\n");

    do {
        iterate_all_wait(autotoxes, NUM_AV_GROUP_TOX, ITERATION_INTERVAL);
    } while (!all_connected_to_group(NUM_AV_GROUP_TOX, autotoxes));

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (restarting[i]) {
            ck_assert_msg(!toxav_groupchat_av_enabled(autotoxes[i].tox, 0),
                          "#%u restarted but av enabled", autotoxes[i].index);
            ck_assert_msg(toxav_groupchat_enable_av(autotoxes[i].tox, 0, audio_callback, &autotoxes[i]) == 0,
                          "#%u failed to re-enable av", autotoxes[i].index);
            ck_assert_msg(toxav_groupchat_av_enabled(autotoxes[i].tox, 0),
                          "#%u av not enabled even after enabling", autotoxes[i].index);
        }
    }

    printf("testing audio\n");

    /* Allow time for the jitter buffers to reset and for the group to become
     * connected enough for lossy messages to get through
     * (all_connected_to_group() only checks lossless connectivity, which is a
     * looser condition). */
    test_eventual_audio(autotoxes, disabled, JITTER_SETTLE_TIME + NUM_AV_GROUP_TOX * 1000);

    printf("testing disabling av\n");

    ck_assert(NUM_AV_DISABLE < NUM_AV_GROUP_TOX);

    for (uint32_t i = 0; i < NUM_AV_DISABLE; ++i) {
        uint32_t disable = random_false_index(rng, disabled, NUM_AV_GROUP_TOX);
        disabled[disable] = true;
        printf("Disabling #%u\n", autotoxes[disable].index);
        ck_assert_msg(toxav_groupchat_enable_av(autotoxes[disable].tox, 0, audio_callback, &autotoxes[disable]) != 0,
                      "#%u could enable already enabled av!", autotoxes[i].index);
        ck_assert_msg(toxav_groupchat_disable_av(autotoxes[disable].tox, 0) == 0,
                      "#%u failed to disable av", autotoxes[i].index);
    }

    // Run test without error to clear out messages from now-disabled peers.
    test_audio(autotoxes, disabled, true);

    printf("testing audio with some peers having disabled their av\n");
    test_audio(autotoxes, disabled, false);

    for (uint32_t i = 0; i < NUM_AV_DISABLE; ++i) {
        if (!disabled[i]) {
            continue;
        }

        disabled[i] = false;
        ck_assert_msg(toxav_groupchat_disable_av(autotoxes[i].tox, 0) != 0,
                      "#%u could disable already disabled av!", autotoxes[i].index);
        ck_assert_msg(!toxav_groupchat_av_enabled(autotoxes[i].tox, 0),
                      "#%u av enabled after disabling", autotoxes[i].index);
        ck_assert_msg(toxav_groupchat_enable_av(autotoxes[i].tox, 0, audio_callback, &autotoxes[i]) == 0,
                      "#%u failed to re-enable av", autotoxes[i].index);
    }

    printf("testing audio after re-enabling all av\n");
    test_eventual_audio(autotoxes, disabled, JITTER_SETTLE_TIME);
}

static void test_groupav(AutoTox *autotoxes)
{
    const time_t test_start_time = time(nullptr);

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        tox_events_callback_self_connection_status(autotoxes[i].dispatch, handle_self_connection_status);
        tox_events_callback_friend_connection_status(autotoxes[i].dispatch, handle_friend_connection_status);
        tox_events_callback_conference_invite(autotoxes[i].dispatch, handle_conference_invite);
        tox_events_callback_conference_connected(autotoxes[i].dispatch, handle_conference_connected);
    }

    ck_assert_msg(toxav_add_av_groupchat(autotoxes[0].tox, audio_callback, &autotoxes[0]) != UINT32_MAX,
                  "failed to create group");
    printf("tox #%u: inviting its first friend\n", autotoxes[0].index);
    ck_assert_msg(tox_conference_invite(autotoxes[0].tox, 0, 0, nullptr) != 0, "failed to invite friend");
    ((State *)autotoxes[0].state)->invited_next = true;

    printf("waiting for invitations to be made\n");
    uint32_t invited_count = 0;

    do {
        iterate_all_wait(autotoxes, NUM_AV_GROUP_TOX, ITERATION_INTERVAL);

        invited_count = 0;

        for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            invited_count += ((State *)autotoxes[i].state)->invited_next;
        }
    } while (invited_count != NUM_AV_GROUP_TOX - 1);

    uint64_t pregroup_clock = autotoxes[0].clock;
    printf("waiting for all toxes to be in the group\n");
    uint32_t fully_connected_count = 0;

    do {
        fully_connected_count = 0;
        iterate_all_wait(autotoxes, NUM_AV_GROUP_TOX, ITERATION_INTERVAL);

        for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            Tox_Err_Conference_Peer_Query err;
            uint32_t peer_count = tox_conference_peer_count(autotoxes[i].tox, 0, &err);

            if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
                peer_count = 0;
            }

            fully_connected_count += peer_count == NUM_AV_GROUP_TOX;
        }
    } while (fully_connected_count != NUM_AV_GROUP_TOX);

    printf("group connected, took %d seconds\n", (int)((autotoxes[0].clock - pregroup_clock) / 1000));

    run_conference_tests(autotoxes);

    printf("test_many_group succeeded, took %d seconds\n", (int)(time(nullptr) - test_start_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;

    run_auto_test(nullptr, NUM_AV_GROUP_TOX, test_groupav, sizeof(State), &options);

    return 0;
}
