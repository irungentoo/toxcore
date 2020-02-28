#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include "../toxcore/util.h"
#include "check_compat.h"

typedef struct {
    bool incoming;
    uint32_t state;
} CallControl;

typedef struct {
    ToxAV *AliceAV;
    ToxAV *BobAV;
    CallControl *AliceCC;
    CallControl *BobCC;
    uint32_t friend_number;
} thread_data;

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
    printf("Handling CALL STATE callback: %d %p\n", state, (void *)av);
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
static ToxAV *setup_av_instance(Tox *tox, CallControl *CC)
{
    Toxav_Err_New error;

    ToxAV *av = toxav_new(tox, &error);
    ck_assert(error == TOXAV_ERR_NEW_OK);

    toxav_callback_call(av, t_toxav_call_cb, CC);
    toxav_callback_call_state(av, t_toxav_call_state_cb, CC);
    toxav_callback_video_receive_frame(av, t_toxav_receive_video_frame_cb, CC);
    toxav_callback_audio_receive_frame(av, t_toxav_receive_audio_frame_cb, CC);

    return av;
}

static void *call_thread(void *pd)
{
    ToxAV *AliceAV = ((thread_data *) pd)->AliceAV;
    ToxAV *BobAV = ((thread_data *) pd)->BobAV;
    uint32_t friend_number = ((thread_data *) pd)->friend_number;

    int16_t *PCM = (int16_t *)calloc(960, sizeof(int16_t));
    uint8_t *video_y = (uint8_t *)calloc(800 * 600, sizeof(uint8_t));
    uint8_t *video_u = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));
    uint8_t *video_v = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));

    time_t start_time = time(nullptr);

    do {
        toxav_iterate(AliceAV);
        toxav_iterate(BobAV);

        toxav_audio_send_frame(AliceAV, friend_number, PCM, 960, 1, 48000, nullptr);
        toxav_audio_send_frame(BobAV, 0, PCM, 960, 1, 48000, nullptr);

        toxav_video_send_frame(AliceAV, friend_number, 800, 600, video_y, video_u, video_v, nullptr);
        toxav_video_send_frame(BobAV, 0, 800, 600, video_y, video_u, video_v, nullptr);

        c_sleep(10);
    } while (time(nullptr) - start_time < 4);

    free(PCM);
    free(video_y);
    free(video_u);
    free(video_v);

    printf("Closing thread\n");
    pthread_exit(nullptr);

    return nullptr;
}

static void test_av_three_calls(void)
{
    uint32_t index[] = { 1, 2, 3, 4, 5 };
    Tox *Alice, *bootstrap, *Bobs[3];
    ToxAV *AliceAV, *BobsAV[3];
    void *retval;

    CallControl AliceCC[3], BobsCC[3];

    {
        Tox_Err_New error;

        bootstrap = tox_new_log(nullptr, &error, &index[0]);
        ck_assert(error == TOX_ERR_NEW_OK);

        Alice = tox_new_log(nullptr, &error, &index[1]);
        ck_assert(error == TOX_ERR_NEW_OK);

        Bobs[0] = tox_new_log(nullptr, &error, &index[2]);
        ck_assert(error == TOX_ERR_NEW_OK);

        Bobs[1] = tox_new_log(nullptr, &error, &index[3]);
        ck_assert(error == TOX_ERR_NEW_OK);

        Bobs[2] = tox_new_log(nullptr, &error, &index[4]);
        ck_assert(error == TOX_ERR_NEW_OK);
    }

    printf("Created 5 instances of Tox\n");
    printf("Preparing network...\n");
    time_t cur_time = time(nullptr);

    uint8_t address[TOX_ADDRESS_SIZE];

    tox_callback_friend_request(Alice, t_accept_friend_request_cb);
    tox_self_get_address(Alice, address);

    printf("bootstrapping Alice and the %u Bobs off a third bootstrap node\n",
           (unsigned)(sizeof(Bobs) / sizeof(Bobs[0])));
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(bootstrap, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(bootstrap, nullptr);

    tox_bootstrap(Alice, "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(Bobs[0], "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(Bobs[1], "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(Bobs[2], "localhost", dht_port, dht_key, nullptr);

    ck_assert(tox_friend_add(Bobs[0], address, (const uint8_t *)"gentoo", 7, nullptr) != (uint32_t) -1);
    ck_assert(tox_friend_add(Bobs[1], address, (const uint8_t *)"gentoo", 7, nullptr) != (uint32_t) -1);
    ck_assert(tox_friend_add(Bobs[2], address, (const uint8_t *)"gentoo", 7, nullptr) != (uint32_t) -1);

    uint8_t off = 1;

    while (true) {
        tox_iterate(bootstrap, nullptr);
        tox_iterate(Alice, nullptr);
        tox_iterate(Bobs[0], nullptr);
        tox_iterate(Bobs[1], nullptr);
        tox_iterate(Bobs[2], nullptr);

        if (tox_self_get_connection_status(bootstrap) &&
                tox_self_get_connection_status(Alice) &&
                tox_self_get_connection_status(Bobs[0]) &&
                tox_self_get_connection_status(Bobs[1]) &&
                tox_self_get_connection_status(Bobs[2]) && off) {
            printf("Toxes are online, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
            off = 0;
        }

        if (tox_friend_get_connection_status(Alice, 0, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Alice, 1, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Alice, 2, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Bobs[0], 0, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Bobs[1], 0, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Bobs[2], 0, nullptr) == TOX_CONNECTION_UDP) {
            break;
        }

        c_sleep(20);
    }

    AliceAV = setup_av_instance(Alice, AliceCC);
    BobsAV[0] = setup_av_instance(Bobs[0], &BobsCC[0]);
    BobsAV[1] = setup_av_instance(Bobs[1], &BobsCC[1]);
    BobsAV[2] = setup_av_instance(Bobs[2], &BobsCC[2]);

    printf("Created 4 instances of ToxAV\n");
    printf("All set after %lu seconds!\n", (unsigned long)(time(nullptr) - cur_time));

    thread_data tds[3];

    for (size_t i = 0; i < 3; i++) {
        tds[i].AliceAV = AliceAV;
        tds[i].BobAV = BobsAV[i];
        tds[i].AliceCC = &AliceCC[i];
        tds[i].BobCC = &BobsCC[i];
        tds[i].friend_number = i;
        memset(tds[i].AliceCC, 0, sizeof(CallControl));
        memset(tds[i].BobCC, 0, sizeof(CallControl));
    }

    pthread_t tids[3];

    for (size_t i = 0; i < 3; i++) {
        (void) pthread_create(&tids[i], nullptr, call_thread, &tds[i]);
    }

    time_t start_time = time(nullptr);

    do {
        tox_iterate(bootstrap, nullptr);
        tox_iterate(Alice, nullptr);
        tox_iterate(Bobs[0], nullptr);
        tox_iterate(Bobs[1], nullptr);
        tox_iterate(Bobs[2], nullptr);
        c_sleep(20);
    } while (time(nullptr) - start_time < 1);

    /* Call */
    for (size_t i = 0; i < 3; i++) {
        Toxav_Err_Call rc;
        toxav_call(AliceAV, tds[i].friend_number, 48, 3000, &rc);

        if (rc != TOXAV_ERR_CALL_OK) {
            printf("toxav_call failed: %d\n", rc);
            ck_assert(0);
        }
    }


    do {
        tox_iterate(bootstrap, nullptr);
        tox_iterate(Alice, nullptr);
        tox_iterate(Bobs[0], nullptr);
        tox_iterate(Bobs[1], nullptr);
        tox_iterate(Bobs[2], nullptr);

        for (size_t i = 0; i < 3; i++) {
            if (BobsCC[i].incoming) {
                /* Answer */
                Toxav_Err_Answer rc;
                toxav_answer(BobsAV[i], 0, 8, 500, &rc);

                if (rc != TOXAV_ERR_ANSWER_OK) {
                    printf("toxav_answer failed: %d\n", rc);
                    ck_assert(0);
                }

                BobsCC[i].incoming = false;
            }
        }

        c_sleep(20);
    } while (time(nullptr) - start_time < 3);

    /* Hangup */
    for (size_t i = 0; i < 3; i++) {
        Toxav_Err_Call_Control rc;
        toxav_call_control(AliceAV, i, TOXAV_CALL_CONTROL_CANCEL, &rc);

        if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
            printf("toxav_call_control failed: %d %p %p\n", rc, (void *)AliceAV, (void *)&BobsAV[i]);
        }
    }

    do {
        tox_iterate(bootstrap, nullptr);
        tox_iterate(Alice, nullptr);
        tox_iterate(Bobs[0], nullptr);
        tox_iterate(Bobs[1], nullptr);
        tox_iterate(Bobs[2], nullptr);

        c_sleep(20);
    } while (time(nullptr) - start_time < 5);

    ck_assert(pthread_join(tids[0], &retval) == 0);
    ck_assert(retval == nullptr);

    ck_assert(pthread_join(tids[1], &retval) == 0);
    ck_assert(retval == nullptr);

    ck_assert(pthread_join(tids[2], &retval) == 0);
    ck_assert(retval == nullptr);

    printf("Killing all instances\n");
    toxav_kill(BobsAV[2]);
    toxav_kill(BobsAV[1]);
    toxav_kill(BobsAV[0]);
    toxav_kill(AliceAV);
    tox_kill(Bobs[2]);
    tox_kill(Bobs[1]);
    tox_kill(Bobs[0]);
    tox_kill(Alice);
    tox_kill(bootstrap);

    printf("\nTest successful!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_av_three_calls();
    return 0;
}
