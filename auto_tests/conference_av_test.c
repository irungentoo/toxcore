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

typedef struct State {
    uint32_t index;
    uint64_t clock;

    bool invited_next;

    uint32_t received_audio_peers[NUM_AV_GROUP_TOX];
    uint32_t received_audio_num;
} State;

#include "run_auto_test.h"

static void handle_self_connection_status(
    Tox *tox, Tox_Connection connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected\n", state->index);
    } else {
        printf("tox #%u: is now disconnected\n", state->index);
    }
}

static void handle_friend_connection_status(
    Tox *tox, uint32_t friendnumber, Tox_Connection connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected to friend %u\n", state->index, friendnumber);
    } else {
        printf("tox #%u: is now disconnected from friend %u\n", state->index, friendnumber);
    }
}

static void audio_callback(void *tox, uint32_t groupnumber, uint32_t peernumber,
                           const int16_t *pcm, unsigned int samples, uint8_t channels, uint32_t
                           sample_rate, void *userdata)
{
    if (samples == 0) {
        return;
    }

    State *state = (State *)userdata;

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
    Tox *tox, uint32_t friendnumber, Tox_Conference_Type type,
    const uint8_t *data, size_t length, void *user_data)
{
    const State *state = (State *)user_data;
    ck_assert_msg(type == TOX_CONFERENCE_TYPE_AV, "tox #%u: wrong conference type: %d", state->index, type);

    ck_assert_msg(toxav_join_av_groupchat(tox, friendnumber, data, length, audio_callback, user_data) == 0,
                  "tox #%u: failed to join group", state->index);
}

static void handle_conference_connected(
    Tox *tox, uint32_t conference_number, void *user_data)
{
    State *state = (State *)user_data;

    if (state->invited_next || tox_self_get_friend_list_size(tox) <= 1) {
        return;
    }

    Tox_Err_Conference_Invite err;
    tox_conference_invite(tox, 1, 0, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "tox #%u failed to invite next friend: err = %d", state->index, err);
    printf("tox #%u: invited next friend\n", state->index);
    state->invited_next = true;
}

static bool toxes_are_disconnected_from_group(uint32_t tox_count, Tox **toxes,
        bool *disconnected)
{
    uint32_t num_disconnected = 0;

    for (uint32_t i = 0; i < tox_count; ++i) {
        num_disconnected += disconnected[i];
    }

    for (uint32_t i = 0; i < tox_count; i++) {
        if (disconnected[i]) {
            continue;
        }

        if (tox_conference_peer_count(toxes[i], 0, nullptr) > tox_count - num_disconnected) {
            return false;
        }
    }

    return true;
}

static void disconnect_toxes(uint32_t tox_count, Tox **toxes, State *state,
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
                    tox_iterate(toxes[i], &state[i]);
                    state[i].clock += 1000;
                }
            }

            c_sleep(20);
        } while (!toxes_are_disconnected_from_group(tox_count, toxes, disconnect_now));

        invert = !invert;
    } while (invert);
}

static bool all_connected_to_group(uint32_t tox_count, Tox **toxes)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (tox_conference_peer_count(toxes[i], 0, nullptr) < tox_count) {
            return false;
        }
    }

    return true;
}

/**
 * returns a random index at which a list of booleans is false
 * (some such index is required to exist)
 */
static uint32_t random_false_index(bool *list, const uint32_t length)
{
    uint32_t index;

    do {
        index = random_u32() % length;
    } while (list[index]);

    return index;
}

static bool all_got_audio(State *state, const bool *disabled)
{
    uint32_t num_disabled = 0;

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        num_disabled += disabled[i];
    }

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (disabled[i] ^ (state[i].received_audio_num
                           != NUM_AV_GROUP_TOX - num_disabled - 1)) {
            return false;
        }
    }

    return true;
}

static void reset_received_audio(Tox **toxes, State *state)
{
    for (uint32_t j = 0; j < NUM_AV_GROUP_TOX; ++j) {
        state[j].received_audio_num = 0;
    }
}

#define GROUP_AV_TEST_SAMPLES 960

/* must have
 * GROUP_AV_AUDIO_ITERATIONS - NUM_AV_GROUP_TOX >= 2^n >= GROUP_JBUF_SIZE
 * for some n, to give messages time to be relayed and to let the jitter
 * buffers fill up. */
#define GROUP_AV_AUDIO_ITERATIONS (8 + NUM_AV_GROUP_TOX)

static bool test_audio(Tox **toxes, State *state, const bool *disabled, bool quiet)
{
    if (!quiet) {
        printf("testing sending and receiving audio\n");
    }

    int16_t PCM[GROUP_AV_TEST_SAMPLES];

    reset_received_audio(toxes, state);

    for (uint32_t n = 0; n < GROUP_AV_AUDIO_ITERATIONS; n++) {
        for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            if (disabled[i]) {
                continue;
            }

            if (toxav_group_send_audio(toxes[i], 0, PCM, GROUP_AV_TEST_SAMPLES, 1, 48000) != 0) {
                if (!quiet) {
                    ck_abort_msg("#%u failed to send audio", state[i].index);
                }

                return false;
            }
        }

        iterate_all_wait(NUM_AV_GROUP_TOX, toxes, state, ITERATION_INTERVAL);

        if (all_got_audio(state, disabled)) {
            return true;
        }
    }

    if (!quiet) {
        ck_abort_msg("group failed to receive audio");
    }

    return false;
}

static void test_eventual_audio(Tox **toxes, State *state, const bool *disabled, uint64_t timeout)
{
    uint64_t start = state[0].clock;

    while (state[0].clock < start + timeout) {
        if (test_audio(toxes, state, disabled, true)
                && test_audio(toxes, state, disabled, true)) {
            printf("audio test successful after %d seconds\n", (int)((state[0].clock - start) / 1000));
            return;
        }
    }

    printf("audio seems not to be getting through: testing again with errors.\n");
    test_audio(toxes, state, disabled, false);
}

static void do_audio(Tox **toxes, State *state, uint32_t iterations)
{
    int16_t PCM[GROUP_AV_TEST_SAMPLES];
    printf("running audio for %u iterations\n", iterations);

    for (uint32_t f = 0; f < iterations; ++f) {
        for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            ck_assert_msg(toxav_group_send_audio(toxes[i], 0, PCM, GROUP_AV_TEST_SAMPLES, 1, 48000) == 0,
                          "#%u failed to send audio", state[i].index);
            iterate_all_wait(NUM_AV_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
        }
    }
}

// should agree with value in groupav.c
#define GROUP_JBUF_DEAD_SECONDS 4

#define JITTER_SETTLE_TIME (GROUP_JBUF_DEAD_SECONDS*1000 + NUM_AV_GROUP_TOX*ITERATION_INTERVAL*(GROUP_AV_AUDIO_ITERATIONS+1))

static void run_conference_tests(Tox **toxes, State *state)
{
    bool disabled[NUM_AV_GROUP_TOX] = {0};

    test_audio(toxes, state, disabled, false);

    /* have everyone send audio for a bit so we can test that the audio
     * sequnums dropping to 0 on restart isn't a problem */
    do_audio(toxes, state, 20);

    printf("letting random toxes timeout\n");
    bool disconnected[NUM_AV_GROUP_TOX] = {0};
    bool restarting[NUM_AV_GROUP_TOX] = {0};

    ck_assert(NUM_AV_DISCONNECT < NUM_AV_GROUP_TOX);

    for (uint32_t i = 0; i < NUM_AV_DISCONNECT; ++i) {
        uint32_t disconnect = random_false_index(disconnected, NUM_AV_GROUP_TOX);
        disconnected[disconnect] = true;

        if (i < NUM_AV_DISCONNECT / 2) {
            restarting[disconnect] = true;
            printf("Restarting #%u\n", state[disconnect].index);
        } else {
            printf("Disconnecting #%u\n", state[disconnect].index);
        }
    }

    uint8_t *save[NUM_AV_GROUP_TOX];
    size_t save_size[NUM_AV_GROUP_TOX];

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (restarting[i]) {
            save_size[i] = tox_get_savedata_size(toxes[i]);
            ck_assert_msg(save_size[i] != 0, "save is invalid size %u", (unsigned)save_size[i]);
            save[i] = (uint8_t *)malloc(save_size[i]);
            ck_assert_msg(save[i] != nullptr, "malloc failed");
            tox_get_savedata(toxes[i], save[i]);
            tox_kill(toxes[i]);
        }
    }

    disconnect_toxes(NUM_AV_GROUP_TOX, toxes, state, disconnected, restarting);

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (restarting[i]) {
            struct Tox_Options *const options = tox_options_new(nullptr);
            tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
            tox_options_set_savedata_data(options, save[i], save_size[i]);
            toxes[i] = tox_new_log(options, nullptr, &state[i].index);
            tox_options_free(options);
            free(save[i]);

            set_mono_time_callback(toxes[i], &state[i]);
        }
    }

    printf("reconnecting toxes\n");

    do {
        iterate_all_wait(NUM_AV_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
    } while (!all_connected_to_group(NUM_AV_GROUP_TOX, toxes));

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        if (restarting[i]) {
            ck_assert_msg(!toxav_groupchat_av_enabled(toxes[i], 0),
                          "#%u restarted but av enabled", state[i].index);
            ck_assert_msg(toxav_groupchat_enable_av(toxes[i], 0, audio_callback, &state[i]) == 0,
                          "#%u failed to re-enable av", state[i].index);
            ck_assert_msg(toxav_groupchat_av_enabled(toxes[i], 0),
                          "#%u av not enabled even after enabling", state[i].index);
        }
    }

    printf("testing audio\n");

    /* Allow time for the jitter buffers to reset and for the group to become
     * connected enough for lossy messages to get through
     * (all_connected_to_group() only checks lossless connectivity, which is a
     * looser condition). */
    test_eventual_audio(toxes, state, disabled, JITTER_SETTLE_TIME + NUM_AV_GROUP_TOX * 1000);

    printf("testing disabling av\n");

    ck_assert(NUM_AV_DISABLE < NUM_AV_GROUP_TOX);

    for (uint32_t i = 0; i < NUM_AV_DISABLE; ++i) {
        uint32_t disable = random_false_index(disabled, NUM_AV_GROUP_TOX);
        disabled[disable] = true;
        printf("Disabling #%u\n", state[disable].index);
        ck_assert_msg(toxav_groupchat_enable_av(toxes[disable], 0, audio_callback, &state[disable]) != 0,
                      "#%u could enable already enabled av!", state[i].index);
        ck_assert_msg(toxav_groupchat_disable_av(toxes[disable], 0) == 0,
                      "#%u failed to disable av", state[i].index);
    }

    // Run test without error to clear out messages from now-disabled peers.
    test_audio(toxes, state, disabled, true);

    printf("testing audio with some peers having disabled their av\n");
    test_audio(toxes, state, disabled, false);

    for (uint32_t i = 0; i < NUM_AV_DISABLE; ++i) {
        if (!disabled[i]) {
            continue;
        }

        disabled[i] = false;
        ck_assert_msg(toxav_groupchat_disable_av(toxes[i], 0) != 0,
                      "#%u could disable already disabled av!", state[i].index);
        ck_assert_msg(!toxav_groupchat_av_enabled(toxes[i], 0),
                      "#%u av enabled after disabling", state[i].index);
        ck_assert_msg(toxav_groupchat_enable_av(toxes[i], 0, audio_callback, &state[i]) == 0,
                      "#%u failed to re-enable av", state[i].index);
    }

    printf("testing audio after re-enabling all av\n");
    test_eventual_audio(toxes, state, disabled, JITTER_SETTLE_TIME);
}

static void test_groupav(Tox **toxes, State *state)
{
    const time_t test_start_time = time(nullptr);

    for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
        tox_callback_self_connection_status(toxes[i], &handle_self_connection_status);
        tox_callback_friend_connection_status(toxes[i], &handle_friend_connection_status);
        tox_callback_conference_invite(toxes[i], &handle_conference_invite);
        tox_callback_conference_connected(toxes[i], &handle_conference_connected);
    }

    ck_assert_msg(toxav_add_av_groupchat(toxes[0], audio_callback, &state[0]) != UINT32_MAX, "failed to create group");
    printf("tox #%u: inviting its first friend\n", state[0].index);
    ck_assert_msg(tox_conference_invite(toxes[0], 0, 0, nullptr) != 0, "failed to invite friend");
    state[0].invited_next = true;


    printf("waiting for invitations to be made\n");
    uint32_t invited_count = 0;

    do {
        iterate_all_wait(NUM_AV_GROUP_TOX, toxes, state, ITERATION_INTERVAL);

        invited_count = 0;

        for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            invited_count += state[i].invited_next;
        }
    } while (invited_count != NUM_AV_GROUP_TOX - 1);

    uint64_t pregroup_clock = state[0].clock;
    printf("waiting for all toxes to be in the group\n");
    uint32_t fully_connected_count = 0;

    do {
        fully_connected_count = 0;
        iterate_all_wait(NUM_AV_GROUP_TOX, toxes, state, ITERATION_INTERVAL);

        for (uint32_t i = 0; i < NUM_AV_GROUP_TOX; ++i) {
            Tox_Err_Conference_Peer_Query err;
            uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, &err);

            if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
                peer_count = 0;
            }

            fully_connected_count += peer_count == NUM_AV_GROUP_TOX;
        }
    } while (fully_connected_count != NUM_AV_GROUP_TOX);

    printf("group connected, took %d seconds\n", (int)((state[0].clock - pregroup_clock) / 1000));

    run_conference_tests(toxes, state);

    printf("test_many_group succeeded, took %d seconds\n", (int)(time(nullptr) - test_start_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(nullptr, NUM_AV_GROUP_TOX, test_groupav, true);
    return 0;
}
