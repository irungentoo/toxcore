#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#if !defined(_WIN32) && !defined(__WIN32__) && !defined(WIN32)
#include <pthread.h>
#endif

#include <vpx/vpx_image.h>

#include "../testing/misc_tools.h"
#include "../toxav/toxav.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/logger.h"
#include "../toxcore/tox.h"
#include "../toxcore/tox_struct.h"
#include "../toxcore/util.h"
#include "auto_test_support.h"
#include "check_compat.h"

typedef struct CallControl {
    bool incoming;
    uint32_t state;
} CallControl;

typedef struct Thread_Data {
    ToxAV *alice_av;
    ToxAV *bob_av;
    CallControl *alice_cc;
    CallControl *bob_cc;
    uint32_t friend_number;
} Thread_Data;

/**
 * Callbacks
 */
static void t_toxav_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    printf("Handling CALL callback\n");
    ((CallControl *)user_data)[friend_number].incoming = true;
}

static void t_toxav_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    printf("Handling CALL STATE callback: %u %p\n", state, (void *)av);
    ((CallControl *)user_data)[friend_number].state = state;
}

static void t_toxav_receive_video_frame_cb(ToxAV *av, uint32_t friend_number,
        uint16_t width, uint16_t height,
        uint8_t const *y, uint8_t const *u, uint8_t const *v,
        int32_t ystride, int32_t ustride, int32_t vstride,
        void *user_data)
{
}

static void t_toxav_receive_audio_frame_cb(ToxAV *av, uint32_t friend_number,
        int16_t const *pcm,
        size_t sample_count,
        uint8_t channels,
        uint32_t sampling_rate,
        void *user_data)
{
}

static void t_accept_friend_request_cb(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length,
                                       void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        ck_assert(tox_friend_add_norequest(m, public_key, nullptr) != (uint32_t) -1);
    }
}

/**
 * Iterate helper
 */
static ToxAV *setup_av_instance(Tox *tox, CallControl *cc)
{
    Toxav_Err_New error;

    ToxAV *av = toxav_new(tox, &error);
    ck_assert(error == TOXAV_ERR_NEW_OK);

    toxav_callback_call(av, t_toxav_call_cb, cc);
    toxav_callback_call_state(av, t_toxav_call_state_cb, cc);
    toxav_callback_video_receive_frame(av, t_toxav_receive_video_frame_cb, cc);
    toxav_callback_audio_receive_frame(av, t_toxav_receive_audio_frame_cb, cc);

    return av;
}

static void *call_thread(void *pd)
{
    ToxAV *alice_av = ((Thread_Data *) pd)->alice_av;
    ToxAV *bob_av = ((Thread_Data *) pd)->bob_av;
    uint32_t friend_number = ((Thread_Data *) pd)->friend_number;

    int16_t *pcm = (int16_t *)calloc(960, sizeof(int16_t));
    uint8_t *video_y = (uint8_t *)calloc(800 * 600, sizeof(uint8_t));
    uint8_t *video_u = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));
    uint8_t *video_v = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));

    time_t start_time = time(nullptr);

    do {
        toxav_iterate(alice_av);
        toxav_iterate(bob_av);

        toxav_audio_send_frame(alice_av, friend_number, pcm, 960, 1, 48000, nullptr);
        toxav_audio_send_frame(bob_av, 0, pcm, 960, 1, 48000, nullptr);

        toxav_video_send_frame(alice_av, friend_number, 800, 600, video_y, video_u, video_v, nullptr);
        toxav_video_send_frame(bob_av, 0, 800, 600, video_y, video_u, video_v, nullptr);

        c_sleep(10);
    } while (time(nullptr) - start_time < 4);

    free(pcm);
    free(video_y);
    free(video_u);
    free(video_v);

    printf("Closing thread\n");
    pthread_exit(nullptr);

    return nullptr;
}

typedef struct Time_Data {
    pthread_mutex_t lock;
    uint64_t clock;
} Time_Data;

static uint64_t get_state_clock_callback(void *user_data)
{
    Time_Data *time_data = (Time_Data *)user_data;
    pthread_mutex_lock(&time_data->lock);
    uint64_t clock = time_data->clock;
    pthread_mutex_unlock(&time_data->lock);
    return clock;
}

static void increment_clock(Time_Data *time_data, uint64_t count)
{
    pthread_mutex_lock(&time_data->lock);
    time_data->clock += count;
    pthread_mutex_unlock(&time_data->lock);
}

static void set_current_time_callback(Tox *tox, Time_Data *time_data)
{
    Mono_Time *mono_time = tox->mono_time;
    mono_time_set_current_time_callback(mono_time, get_state_clock_callback, time_data);
}

static void test_av_three_calls(void)
{
    uint32_t index[] = { 1, 2, 3, 4, 5 };
    Tox *alice, *bootstrap, *bobs[3];
    ToxAV *alice_av, *bobs_av[3];
    void *retval;

    CallControl alice_cc[3], bobs_cc[3];

    Time_Data time_data;
    pthread_mutex_init(&time_data.lock, nullptr);
    {
        Tox_Err_New error;

        bootstrap = tox_new_log(nullptr, &error, &index[0]);
        ck_assert(error == TOX_ERR_NEW_OK);

        time_data.clock = current_time_monotonic(bootstrap->mono_time);
        set_current_time_callback(bootstrap, &time_data);

        alice = tox_new_log(nullptr, &error, &index[1]);
        ck_assert(error == TOX_ERR_NEW_OK);
        set_current_time_callback(alice, &time_data);

        bobs[0] = tox_new_log(nullptr, &error, &index[2]);
        ck_assert(error == TOX_ERR_NEW_OK);
        set_current_time_callback(bobs[0], &time_data);

        bobs[1] = tox_new_log(nullptr, &error, &index[3]);
        ck_assert(error == TOX_ERR_NEW_OK);
        set_current_time_callback(bobs[1], &time_data);

        bobs[2] = tox_new_log(nullptr, &error, &index[4]);
        ck_assert(error == TOX_ERR_NEW_OK);
        set_current_time_callback(bobs[2], &time_data);
    }

    printf("Created 5 instances of Tox\n");
    printf("Preparing network...\n");
    time_t cur_time = time(nullptr);

    uint8_t address[TOX_ADDRESS_SIZE];

    tox_callback_friend_request(alice, t_accept_friend_request_cb);
    tox_self_get_address(alice, address);

    printf("bootstrapping Alice and the %u Bobs off a third bootstrap node\n",
           (unsigned)(sizeof(bobs) / sizeof(bobs[0])));
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(bootstrap, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(bootstrap, nullptr);

    tox_bootstrap(alice, "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(bobs[0], "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(bobs[1], "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(bobs[2], "localhost", dht_port, dht_key, nullptr);

    ck_assert(tox_friend_add(bobs[0], address, (const uint8_t *)"gentoo", 7, nullptr) != (uint32_t) -1);
    ck_assert(tox_friend_add(bobs[1], address, (const uint8_t *)"gentoo", 7, nullptr) != (uint32_t) -1);
    ck_assert(tox_friend_add(bobs[2], address, (const uint8_t *)"gentoo", 7, nullptr) != (uint32_t) -1);

    uint8_t off = 1;

    while (true) {
        tox_iterate(bootstrap, nullptr);
        tox_iterate(alice, nullptr);
        tox_iterate(bobs[0], nullptr);
        tox_iterate(bobs[1], nullptr);
        tox_iterate(bobs[2], nullptr);

        if (tox_self_get_connection_status(bootstrap) &&
                tox_self_get_connection_status(alice) &&
                tox_self_get_connection_status(bobs[0]) &&
                tox_self_get_connection_status(bobs[1]) &&
                tox_self_get_connection_status(bobs[2]) && off) {
            printf("Toxes are online, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
            off = 0;
        }

        if (tox_friend_get_connection_status(alice, 0, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(alice, 1, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(alice, 2, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(bobs[0], 0, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(bobs[1], 0, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(bobs[2], 0, nullptr) == TOX_CONNECTION_UDP) {
            break;
        }

        increment_clock(&time_data, 200);
        c_sleep(5);
    }

    alice_av = setup_av_instance(alice, alice_cc);
    bobs_av[0] = setup_av_instance(bobs[0], &bobs_cc[0]);
    bobs_av[1] = setup_av_instance(bobs[1], &bobs_cc[1]);
    bobs_av[2] = setup_av_instance(bobs[2], &bobs_cc[2]);

    printf("Created 4 instances of ToxAV\n");
    printf("All set after %lu seconds!\n", (unsigned long)(time(nullptr) - cur_time));

    Thread_Data tds[3];

    for (size_t i = 0; i < 3; i++) {
        tds[i].alice_av = alice_av;
        tds[i].bob_av = bobs_av[i];
        tds[i].alice_cc = &alice_cc[i];
        tds[i].bob_cc = &bobs_cc[i];
        tds[i].friend_number = i;
        memset(tds[i].alice_cc, 0, sizeof(CallControl));
        memset(tds[i].bob_cc, 0, sizeof(CallControl));
    }

    pthread_t tids[3];

    for (size_t i = 0; i < 3; i++) {
        (void) pthread_create(&tids[i], nullptr, call_thread, &tds[i]);
    }

    time_t start_time = time(nullptr);

    do {
        tox_iterate(bootstrap, nullptr);
        tox_iterate(alice, nullptr);
        tox_iterate(bobs[0], nullptr);
        tox_iterate(bobs[1], nullptr);
        tox_iterate(bobs[2], nullptr);

        increment_clock(&time_data, 100);
        c_sleep(5);
    } while (time(nullptr) - start_time < 1);

    /* Call */
    for (size_t i = 0; i < 3; i++) {
        Toxav_Err_Call rc;
        toxav_call(alice_av, tds[i].friend_number, 48, 3000, &rc);

        if (rc != TOXAV_ERR_CALL_OK) {
            printf("toxav_call failed: %d\n", rc);
            ck_assert(0);
        }
    }

    do {
        tox_iterate(bootstrap, nullptr);
        tox_iterate(alice, nullptr);
        tox_iterate(bobs[0], nullptr);
        tox_iterate(bobs[1], nullptr);
        tox_iterate(bobs[2], nullptr);

        for (size_t i = 0; i < 3; i++) {
            if (bobs_cc[i].incoming) {
                /* Answer */
                Toxav_Err_Answer rc;
                toxav_answer(bobs_av[i], 0, 8, 500, &rc);

                if (rc != TOXAV_ERR_ANSWER_OK) {
                    printf("toxav_answer failed: %d\n", rc);
                    ck_assert(0);
                }

                bobs_cc[i].incoming = false;
            }
        }

        increment_clock(&time_data, 100);
        c_sleep(5);
    } while (time(nullptr) - start_time < 3);

    /* Hangup */
    for (size_t i = 0; i < 3; i++) {
        Toxav_Err_Call_Control rc;
        toxav_call_control(alice_av, i, TOXAV_CALL_CONTROL_CANCEL, &rc);

        if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
            printf("toxav_call_control failed: %d %p %p\n", rc, (void *)alice_av, (void *)&bobs_av[i]);
        }
    }

    do {
        tox_iterate(bootstrap, nullptr);
        tox_iterate(alice, nullptr);
        tox_iterate(bobs[0], nullptr);
        tox_iterate(bobs[1], nullptr);
        tox_iterate(bobs[2], nullptr);

        increment_clock(&time_data, 100);
        c_sleep(5);
    } while (time(nullptr) - start_time < 5);

    ck_assert(pthread_join(tids[0], &retval) == 0);
    ck_assert(retval == nullptr);

    ck_assert(pthread_join(tids[1], &retval) == 0);
    ck_assert(retval == nullptr);

    ck_assert(pthread_join(tids[2], &retval) == 0);
    ck_assert(retval == nullptr);

    printf("Killing all instances\n");
    toxav_kill(bobs_av[2]);
    toxav_kill(bobs_av[1]);
    toxav_kill(bobs_av[0]);
    toxav_kill(alice_av);
    tox_kill(bobs[2]);
    tox_kill(bobs[1]);
    tox_kill(bobs[0]);
    tox_kill(alice);
    tox_kill(bootstrap);

    pthread_mutex_destroy(&time_data.lock);

    printf("\nTest successful!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_av_three_calls();
    return 0;
}
