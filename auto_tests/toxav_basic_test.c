#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "../toxcore/tox.h"
#include "../toxcore/logger.h"
#include "../toxcore/crypto_core.h"
#include "../toxav/toxav.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif



typedef enum _CallStatus {
    none,
    InCall,
    Ringing,
    Ended,
    Rejected,
    Cancel,
    TimedOut

} CallStatus;

typedef struct _Party {
    CallStatus status;
    ToxAv *av;
    time_t *CallStarted;
    int call_index;
} Party;

typedef struct _Status {
    Party Alice;
    Party Bob;
} Status;

/* My default settings */
static ToxAvCSettings muhcaps;

void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        tox_add_friend_norequest(m, public_key);
    }
}


/******************************************************************************/
void callback_recv_invite ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    /* Bob always receives invite */
    cast->Bob.status = Ringing;
    cast->Bob.call_index = call_index;
}
void callback_recv_ringing ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    /* Alice always sends invite */
    cast->Alice.status = Ringing;
}
void callback_recv_starting ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    /* Alice always sends invite */
    printf("Call started on Alice side...\n");
    cast->Alice.status = InCall;
    toxav_prepare_transmission(av, call_index, av_jbufdc, av_VADd, 1);
}
void callback_recv_ending ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    if ( cast->Alice.status == Rejected) {
        printf ( "Call ended for Bob!\n" );
        cast->Bob.status = Ended;
    } else {
        printf ( "Call ended for Alice!\n" );
        cast->Alice.status = Ended;
    }
}


void callback_call_started ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    /* Alice always sends invite */
    printf("Call started on Bob side...\n");
    cast->Bob.status = InCall;
    toxav_prepare_transmission(av, call_index, av_jbufdc, av_VADd, 1);
}
void callback_call_canceled ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    printf ( "Call Canceled for Bob!\n" );
    cast->Bob.status = Cancel;
}
void callback_call_rejected ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    printf ( "Call rejected by Bob!\n"
             "Call ended for Alice!\n" );
    /* If Bob rejects, call is ended for alice and she sends ending */
    cast->Alice.status = Rejected;
}
void callback_call_ended ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    printf ( "Call ended for Bob!\n" );
    cast->Bob.status = Ended;
}

void callback_call_type_change ( void *av, int32_t call_index, void *_arg )
{
    ToxAvCSettings csettings;
    toxav_get_peer_csettings(av, call_index, 0, &csettings);

    printf("New settings: \n"
           "Type: %u \n"
           "Video bitrate: %u \n"
           "Video height: %u \n"
           "Video width: %u \n"
           "Audio bitrate: %u \n"
           "Audio framedur: %u \n"
           "Audio sample rate: %u \n"
           "Audio channels: %u \n",
           csettings.call_type,
           csettings.video_bitrate,
           csettings.max_video_height,
           csettings.max_video_width,
           csettings.audio_bitrate,
           csettings.audio_frame_duration,
           csettings.audio_sample_rate,
           csettings.audio_channels
          );
}

void callback_requ_timeout ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;
    printf("Call timed-out!\n");
    cast->Alice.status = TimedOut;
}

static void callback_audio(ToxAv *av, int32_t call_index, int16_t *data, int length, void *userdata)
{
}

static void callback_video(ToxAv *av, int32_t call_index, vpx_image_t *img, void *userdata)
{
}

void register_callbacks(ToxAv *av, void *data)
{
    toxav_register_callstate_callback(av, callback_call_started, av_OnStart, data);
    toxav_register_callstate_callback(av, callback_call_canceled, av_OnCancel, data);
    toxav_register_callstate_callback(av, callback_call_rejected, av_OnReject, data);
    toxav_register_callstate_callback(av, callback_call_ended, av_OnEnd, data);
    toxav_register_callstate_callback(av, callback_recv_invite, av_OnInvite, data);

    toxav_register_callstate_callback(av, callback_recv_ringing, av_OnRinging, data);
    toxav_register_callstate_callback(av, callback_recv_starting, av_OnStarting, data);
    toxav_register_callstate_callback(av, callback_recv_ending, av_OnEnding, data);

    toxav_register_callstate_callback(av, callback_requ_timeout, av_OnRequestTimeout, data);
    toxav_register_callstate_callback(av, callback_call_type_change, av_OnMediaChange, data);


    toxav_register_audio_recv_callback(av, callback_audio, NULL);
    toxav_register_video_recv_callback(av, callback_video, NULL);
}


/*************************************************************************************************/

/* Alice calls bob and the call starts.
 * What happens during the call is defined after. To quit the loop use: step++;
 */
#define CALL_AND_START_LOOP(AliceCallType, BobCallType) \
{ int step = 0, running = 1; while (running) {\
    tox_do(bootstrap_node); tox_do(Alice); tox_do(Bob); \
    switch ( step ) {\
        case 0: /* Alice */  printf("Alice is calling...\n");\
            toxav_call(status_control.Alice.av, &status_control.Alice.call_index, 0, &muhcaps, 10); step++; break;\
        case 1: /* Bob */ if (status_control.Bob.status == Ringing) { printf("Bob answers...\n");\
            cur_time = time(NULL); toxav_answer(status_control.Bob.av, status_control.Bob.call_index, &muhcaps); step++; } break; \
        case 2: /* Rtp transmission */ \
            if (status_control.Bob.status == InCall && status_control.Alice.status == InCall)


#define TERMINATE_SCOPE() break;\
case 3: /* Wait for Both to have status ended */\
if (status_control.Alice.status == Ended && status_control.Bob.status == Ended) running = 0; break; } c_sleep(20); } } printf("\n");

START_TEST(test_AV_flows)
// int test_AV_flows()
{
    long long unsigned int cur_time = time(NULL);
    Tox *bootstrap_node = tox_new(0);
    Tox *Alice = tox_new(0);
    Tox *Bob = tox_new(0);

    ck_assert_msg(bootstrap_node || Alice || Bob, "Failed to create 3 tox instances");

    uint32_t to_compare = 974536;
    tox_callback_friend_request(Alice, accept_friend_request, &to_compare);
    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(Alice, address);
    int test = tox_add_friend(Bob, address, (uint8_t *)"gentoo", 7);

    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    uint8_t off = 1;

    while (1) {
        tox_do(bootstrap_node);
        tox_do(Alice);
        tox_do(Bob);

        if (tox_isconnected(bootstrap_node) && tox_isconnected(Alice) && tox_isconnected(Bob) && off) {
            printf("Toxes are online, took %llu seconds\n", time(NULL) - cur_time);
            off = 0;
        }

        if (tox_get_friend_connection_status(Alice, 0) == 1 && tox_get_friend_connection_status(Bob, 0) == 1)
            break;

        c_sleep(20);
    }

    printf("All set after %llu seconds! Starting call...\n", time(NULL) - cur_time);

    muhcaps = av_DefaultSettings;
    muhcaps.max_video_height = muhcaps.max_video_width = 128;

    Status status_control = {
        {none, toxav_new(Alice, 1), NULL, -1},
        {none, toxav_new(Bob, 1), NULL, -1},
    };

    ck_assert_msg(status_control.Alice.av || status_control.Bob.av, "Failed to create 2 toxav instances");


    register_callbacks(status_control.Alice.av, &status_control);
    register_callbacks(status_control.Bob.av, &status_control);

    const int frame_size = (av_DefaultSettings.audio_sample_rate * av_DefaultSettings.audio_frame_duration / 1000);
    int16_t sample_payload[frame_size];
    randombytes((uint8_t *)sample_payload, sizeof(int16_t) * frame_size);

    uint8_t prepared_payload[RTP_PAYLOAD_SIZE];
    int payload_size;

    vpx_image_t *sample_image = vpx_img_alloc(NULL, VPX_IMG_FMT_I420, 128, 128, 1);

    memcpy(sample_image->planes[VPX_PLANE_Y], sample_payload, 10);
    memcpy(sample_image->planes[VPX_PLANE_U], sample_payload, 10);
    memcpy(sample_image->planes[VPX_PLANE_V], sample_payload, 10);


    /*************************************************************************************************
     * Successful flows (when call starts)
     */

    /*
     * Call with audio only on both sides. Alice calls Bob.
     */


    CALL_AND_START_LOOP(TypeAudio, TypeAudio) {
        /* Both send */
        payload_size = toxav_prepare_audio_frame(status_control.Alice.av, status_control.Alice.call_index, prepared_payload,
                       1000, sample_payload, frame_size);

        if ( payload_size < 0 ) {
            ck_assert_msg ( 0, "Failed to encode payload" );
        }

        toxav_send_audio(status_control.Alice.av, status_control.Alice.call_index, prepared_payload, payload_size);

        payload_size = toxav_prepare_audio_frame(status_control.Bob.av, status_control.Bob.call_index, prepared_payload, 1000,
                       sample_payload, frame_size);

        if ( payload_size < 0 ) {
            ck_assert_msg ( 0, "Failed to encode payload" );
        }

        toxav_send_audio(status_control.Bob.av, status_control.Bob.call_index, prepared_payload, payload_size);

        if (time(NULL) - cur_time > 10) { /* Transmit for 10 seconds */
            step++; /* This terminates the loop */
            toxav_kill_transmission(status_control.Alice.av, status_control.Alice.call_index);
            toxav_kill_transmission(status_control.Bob.av, status_control.Bob.call_index);

            /* Call over Alice hangs up */
            toxav_hangup(status_control.Alice.av, status_control.Alice.call_index);
        }
    }
    TERMINATE_SCOPE()


    /*
     * Call with audio on both sides and video on one side. Alice calls Bob.
     */
    CALL_AND_START_LOOP(TypeAudio, TypeVideo) {
        /* Both send */
        payload_size = toxav_prepare_audio_frame(status_control.Alice.av, status_control.Alice.call_index, prepared_payload,
                       1000, sample_payload, frame_size);

        if ( payload_size < 0 ) {
            ck_assert_msg ( 0, "Failed to encode payload" );
        }

        toxav_send_audio(status_control.Alice.av, status_control.Alice.call_index, prepared_payload, payload_size);

        payload_size = toxav_prepare_audio_frame(status_control.Bob.av, status_control.Bob.call_index, prepared_payload, 1000,
                       sample_payload, frame_size);

        if ( payload_size < 0 ) {
            ck_assert_msg ( 0, "Failed to encode payload" );
        }

        toxav_send_audio(status_control.Bob.av, status_control.Bob.call_index, prepared_payload, payload_size);

//         toxav_send_video(status_control.Bob.av, status_control.Bob.call_index, sample_image);

        if (time(NULL) - cur_time > 10) { /* Transmit for 10 seconds */
            step++; /* This terminates the loop */
            toxav_kill_transmission(status_control.Alice.av, status_control.Alice.call_index);
            toxav_kill_transmission(status_control.Bob.av, status_control.Bob.call_index);

            /* Call over Alice hangs up */
            toxav_hangup(status_control.Alice.av, status_control.Alice.call_index);
        }
    }
    TERMINATE_SCOPE()


    /*
     * Call with audio and video on both sides. Alice calls Bob.
     */
    CALL_AND_START_LOOP(TypeVideo, TypeVideo) {
        /* Both send */

        payload_size = toxav_prepare_audio_frame(status_control.Alice.av, status_control.Alice.call_index, prepared_payload,
                       1000, sample_payload, frame_size);

        if ( payload_size < 0 ) {
            ck_assert_msg ( 0, "Failed to encode payload" );
        }

        toxav_send_audio(status_control.Alice.av, status_control.Alice.call_index, prepared_payload, payload_size);

        payload_size = toxav_prepare_audio_frame(status_control.Bob.av, status_control.Bob.call_index, prepared_payload, 1000,
                       sample_payload, frame_size);

        if ( payload_size < 0 ) {
            ck_assert_msg ( 0, "Failed to encode payload" );
        }

        toxav_send_audio(status_control.Bob.av, status_control.Bob.call_index, prepared_payload, payload_size);

//         toxav_send_video(status_control.Alice.av, status_control.Alice.call_index, sample_image);
//         toxav_send_video(status_control.Bob.av, status_control.Bob.call_index, sample_image);


        if (time(NULL) - cur_time > 10) { /* Transmit for 10 seconds */
            step++; /* This terminates the loop */
            toxav_kill_transmission(status_control.Alice.av, status_control.Alice.call_index);
            toxav_kill_transmission(status_control.Bob.av, status_control.Bob.call_index);

            /* Call over Alice hangs up */
            toxav_hangup(status_control.Alice.av, status_control.Alice.call_index);
        }
    }
    TERMINATE_SCOPE()


    uint64_t times_they_are_a_changin = time(NULL);
    /* Media change */
    CALL_AND_START_LOOP(TypeAudio, TypeAudio) {
        /* Both send */
        payload_size = toxav_prepare_audio_frame(status_control.Alice.av, status_control.Alice.call_index, prepared_payload,
                       1000, sample_payload, frame_size);

        if ( payload_size < 0 ) {
            ck_assert_msg ( 0, "Failed to encode payload" );
        }

        toxav_send_audio(status_control.Alice.av, status_control.Alice.call_index, prepared_payload, payload_size);

        payload_size = toxav_prepare_audio_frame(status_control.Bob.av, status_control.Bob.call_index, prepared_payload, 1000,
                       sample_payload, frame_size);

        if ( payload_size < 0 ) {
            ck_assert_msg ( 0, "Failed to encode payload" );
        }

        toxav_send_audio(status_control.Bob.av, status_control.Bob.call_index, prepared_payload, payload_size);

        /* Wait 2 seconds and change transmission type */
        if (time(NULL) - times_they_are_a_changin > 2) {
            times_they_are_a_changin = time(NULL);
            muhcaps.audio_bitrate ++;
            toxav_change_settings(status_control.Alice.av, status_control.Alice.call_index, &muhcaps);
        }

        if (time(NULL) - cur_time > 10) { /* Transmit for 10 seconds */
            step++; /* This terminates the loop */
            toxav_kill_transmission(status_control.Alice.av, status_control.Alice.call_index);
            toxav_kill_transmission(status_control.Bob.av, status_control.Bob.call_index);

            /* Call over Alice hangs up */
            toxav_hangup(status_control.Alice.av, status_control.Alice.call_index);
        }
    }
    TERMINATE_SCOPE()


    /*************************************************************************************************
     * Other flows
     */

    /*
     * Call and reject
     */
    {
        int step = 0;
        int running = 1;

        while (running) {
            tox_do(bootstrap_node);
            tox_do(Alice);
            tox_do(Bob);

            switch ( step ) {
                case 0: /* Alice */
                    printf("Alice is calling...\n");
                    toxav_call(status_control.Alice.av, &status_control.Alice.call_index, 0, &muhcaps, 10);
                    step++;
                    break;

                case 1: /* Bob */
                    if (status_control.Bob.status == Ringing) {
                        printf("Bob rejects...\n");
                        toxav_reject(status_control.Bob.av, status_control.Bob.call_index, "Who likes D's anyway?");
                        step++;
                    }

                    break;

                case 2:  /* Wait for Both to have status ended */
                    if (status_control.Alice.status == Rejected && status_control.Bob.status == Ended) running = 0;

                    break;
            }

            c_sleep(20);
        }

        printf("\n");
    }


    /*
     * Call and cancel
     */
    {
        int step = 0;
        int running = 1;

        while (running) {
            tox_do(bootstrap_node);
            tox_do(Alice);
            tox_do(Bob);

            switch ( step ) {
                case 0: /* Alice */
                    printf("Alice is calling...\n");
                    toxav_call(status_control.Alice.av, &status_control.Alice.call_index, 0, &muhcaps, 10);
                    step++;
                    break;


                case 1: /* Alice again */
                    if (status_control.Bob.status == Ringing) {
                        printf("Alice cancels...\n");
                        toxav_cancel(status_control.Alice.av, status_control.Alice.call_index, 0, "Who likes D's anyway?");
                        step++;
                    }

                    break;

                case 2:  /* Wait for Both to have status ended */
                    if (status_control.Bob.status == Cancel) running = 0;

                    break;
            }

            c_sleep(20);
        }

        printf("\n");
    }

    /*
     * Timeout
     */
    {
        int step = 0;
        int running = 1;

        while (running) {
            tox_do(bootstrap_node);
            tox_do(Alice);
            tox_do(Bob);

            switch ( step ) {
                case 0:
                    printf("Alice is calling...\n");
                    toxav_call(status_control.Alice.av, &status_control.Alice.call_index, 0, &muhcaps, 10);
                    step++;
                    break;

                case 1:
                    if (status_control.Alice.status == TimedOut) running = 0;

                    break;
            }

            c_sleep(20);
        }

        printf("\n");
    }




    printf("Calls ended!\n");
}
END_TEST

/*************************************************************************************************/


/*************************************************************************************************/

/*************************************************************************************************/


Suite *tox_suite(void)
{
    Suite *s = suite_create("ToxAV");

    TCase *tc_av_flows = tcase_create("AV_flows");
    tcase_add_test(tc_av_flows, test_AV_flows);
    tcase_set_timeout(tc_av_flows, 200);
    suite_add_tcase(s, tc_av_flows);

    return s;
}
int main(int argc, char *argv[])
{
    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    setbuf(stdout, NULL);

    srunner_run_all(test_runner, CK_NORMAL);
    int number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;

//     return test_AV_flows();
}
