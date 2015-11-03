/**  av_test.c
 *
 *   Copyright (C) 2013-2015 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox. If not, see <http://www.gnu.org/licenses/>.
 *
 *   Compile with (Linux only; in newly created directory toxcore/dir_name):
 *   gcc -o av_test ../toxav/av_test.c ../build/.libs/libtox*.a -lopencv_core \
 *   -lopencv_highgui -lopencv_imgproc -lsndfile -pthread -lvpx -lopus -lsodium -lportaudio
 */


#include "../toxav/toxav.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "../toxcore/network.h" /* current_time_monotonic() */

/* Playing audio data */
#include <portaudio.h>
/* Reading audio */
#include <sndfile.h>

/* Reading and Displaying video data */
#include <opencv/cv.h>
#include <opencv/highgui.h>
#include <opencv/cvwimage.h>

#include <sys/stat.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define c_sleep(x) usleep(1000*x)


#define CLIP(X) ((X) > 255 ? 255 : (X) < 0 ? 0 : X)

// RGB -> YUV
#define RGB2Y(R, G, B) CLIP((( 66 * (R) + 129 * (G) +  25 * (B) + 128) >> 8) +  16)
#define RGB2U(R, G, B) CLIP(((-38 * (R) -  74 * (G) + 112 * (B) + 128) >> 8) + 128)
#define RGB2V(R, G, B) CLIP(((112 * (R) -  94 * (G) -  18 * (B) + 128) >> 8) + 128)

// YUV -> RGB
#define C(Y) ((Y) - 16  )
#define D(U) ((U) - 128 )
#define E(V) ((V) - 128 )

#define YUV2R(Y, U, V) CLIP((298 * C(Y)              + 409 * E(V) + 128) >> 8)
#define YUV2G(Y, U, V) CLIP((298 * C(Y) - 100 * D(U) - 208 * E(V) + 128) >> 8)
#define YUV2B(Y, U, V) CLIP((298 * C(Y) + 516 * D(U)              + 128) >> 8)


#define TEST_TRANSFER_A 0
#define TEST_TRANSFER_V 1


typedef struct {
    bool incoming;
    uint32_t state;
    pthread_mutex_t arb_mutex[1];
    RingBuffer *arb; /* Audio ring buffer */

} CallControl;

struct toxav_thread_data {
    ToxAV  *AliceAV;
    ToxAV  *BobAV;
    int32_t sig;
};

const char *vdout = "AV Test"; /* Video output */
PaStream *adout = NULL; /* Audio output */

typedef struct {
    uint16_t size;
    int16_t data[];
} frame;

void *pa_write_thread (void *d)
{
    /* The purpose of this thread is to make sure Pa_WriteStream will not block
     * toxav_iterate thread
     */
    CallControl *cc = d;

    while (Pa_IsStreamActive(adout)) {
        frame *f;
        pthread_mutex_lock(cc->arb_mutex);

        if (rb_read(cc->arb, (void **)&f)) {
            pthread_mutex_unlock(cc->arb_mutex);
            Pa_WriteStream(adout, f->data, f->size);
            free(f);
        } else {
            pthread_mutex_unlock(cc->arb_mutex);
            c_sleep(10);
        }
    }
}

/**
 * Callbacks
 */
void t_toxav_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    printf("Handling CALL callback\n");
    ((CallControl *)user_data)->incoming = true;
}
void t_toxav_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    printf("Handling CALL STATE callback: %d\n", state);
    ((CallControl *)user_data)->state = state;
}
void t_toxav_receive_video_frame_cb(ToxAV *av, uint32_t friend_number,
                                    uint16_t width, uint16_t height,
                                    uint8_t const *y, uint8_t const *u, uint8_t const *v,
                                    int32_t ystride, int32_t ustride, int32_t vstride,
                                    void *user_data)
{
    ystride = abs(ystride);
    ustride = abs(ustride);
    vstride = abs(vstride);

    uint16_t *img_data = malloc(height * width * 6);

    unsigned long int i, j;

    for (i = 0; i < height; ++i) {
        for (j = 0; j < width; ++j) {
            uint8_t *point = (uint8_t *) img_data + 3 * ((i * width) + j);
            int yx = y[(i * ystride) + j];
            int ux = u[((i / 2) * ustride) + (j / 2)];
            int vx = v[((i / 2) * vstride) + (j / 2)];

            point[0] = YUV2R(yx, ux, vx);
            point[1] = YUV2G(yx, ux, vx);
            point[2] = YUV2B(yx, ux, vx);
        }
    }


    CvMat mat = cvMat(height, width, CV_8UC3, img_data);

    CvSize sz = {.height = height, .width = width};

    IplImage *header = cvCreateImageHeader(sz, 1, 3);
    IplImage *img = cvGetImage(&mat, header);
    cvShowImage(vdout, img);
    free(img_data);
}
void t_toxav_receive_audio_frame_cb(ToxAV *av, uint32_t friend_number,
                                    int16_t const *pcm,
                                    size_t sample_count,
                                    uint8_t channels,
                                    uint32_t sampling_rate,
                                    void *user_data)
{
    CallControl *cc = user_data;
    frame *f = malloc(sizeof(uint16_t) + sample_count * sizeof(int16_t) * channels);
    memcpy(f->data, pcm, sample_count * sizeof(int16_t) * channels);
    f->size = sample_count;

    pthread_mutex_lock(cc->arb_mutex);
    free(rb_write(cc->arb, f));
    pthread_mutex_unlock(cc->arb_mutex);
}
void t_toxav_bit_rate_status_cb(ToxAV *av, uint32_t friend_number,
                                uint32_t audio_bit_rate, uint32_t video_bit_rate,
                                void *user_data)
{
    printf ("Suggested bit rates: audio: %d video: %d\n", audio_bit_rate, video_bit_rate);
}
void t_accept_friend_request_cb(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        assert(tox_friend_add_norequest(m, public_key, NULL) != (uint32_t) ~0);
    }
}

/**
 */
void initialize_tox(Tox **bootstrap, ToxAV **AliceAV, CallControl *AliceCC, ToxAV **BobAV, CallControl *BobCC)
{
    Tox *Alice;
    Tox *Bob;

    struct Tox_Options opts;
    tox_options_default(&opts);

    opts.end_port = 0;
    opts.ipv6_enabled = false;

    {
        TOX_ERR_NEW error;

        opts.start_port = 33445;
        *bootstrap = tox_new(&opts, &error);
        assert(error == TOX_ERR_NEW_OK);

        opts.start_port = 33455;
        Alice = tox_new(&opts, &error);
        assert(error == TOX_ERR_NEW_OK);

        opts.start_port = 33465;
        Bob = tox_new(&opts, &error);
        assert(error == TOX_ERR_NEW_OK);
    }

    printf("Created 3 instances of Tox\n");
    printf("Preparing network...\n");
    long long unsigned int cur_time = time(NULL);

    uint32_t to_compare = 974536;
    uint8_t address[TOX_ADDRESS_SIZE];

    tox_callback_friend_request(Alice, t_accept_friend_request_cb, &to_compare);
    tox_self_get_address(Alice, address);


    assert(tox_friend_add(Bob, address, (uint8_t *)"gentoo", 7, NULL) != (uint32_t) ~0);

    uint8_t off = 1;

    while (1) {
        tox_iterate(*bootstrap);
        tox_iterate(Alice);
        tox_iterate(Bob);

        if (tox_self_get_connection_status(*bootstrap) &&
                tox_self_get_connection_status(Alice) &&
                tox_self_get_connection_status(Bob) && off) {
            printf("Toxes are online, took %llu seconds\n", time(NULL) - cur_time);
            off = 0;
        }

        if (tox_friend_get_connection_status(Alice, 0, NULL) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Bob, 0, NULL) == TOX_CONNECTION_UDP)
            break;

        c_sleep(20);
    }


    TOXAV_ERR_NEW rc;
    *AliceAV = toxav_new(Alice, &rc);
    assert(rc == TOXAV_ERR_NEW_OK);

    *BobAV = toxav_new(Bob, &rc);
    assert(rc == TOXAV_ERR_NEW_OK);


    /* Alice */
    toxav_callback_call(*AliceAV, t_toxav_call_cb, AliceCC);
    toxav_callback_call_state(*AliceAV, t_toxav_call_state_cb, AliceCC);
    toxav_callback_bit_rate_status(*AliceAV, t_toxav_bit_rate_status_cb, AliceCC);
    toxav_callback_video_receive_frame(*AliceAV, t_toxav_receive_video_frame_cb, AliceCC);
    toxav_callback_audio_receive_frame(*AliceAV, t_toxav_receive_audio_frame_cb, AliceCC);

    /* Bob */
    toxav_callback_call(*BobAV, t_toxav_call_cb, BobCC);
    toxav_callback_call_state(*BobAV, t_toxav_call_state_cb, BobCC);
    toxav_callback_bit_rate_status(*BobAV, t_toxav_bit_rate_status_cb, BobCC);
    toxav_callback_video_receive_frame(*BobAV, t_toxav_receive_video_frame_cb, BobCC);
    toxav_callback_audio_receive_frame(*BobAV, t_toxav_receive_audio_frame_cb, BobCC);


    printf("Created 2 instances of ToxAV\n");
    printf("All set after %llu seconds!\n", time(NULL) - cur_time);
}
int iterate_tox(Tox *bootstrap, ToxAV *AliceAV, ToxAV *BobAV)
{
    tox_iterate(bootstrap);
    tox_iterate(toxav_get_tox(AliceAV));
    tox_iterate(toxav_get_tox(BobAV));

    return MIN(tox_iteration_interval(toxav_get_tox(AliceAV)), tox_iteration_interval(toxav_get_tox(BobAV)));
}
void *iterate_toxav (void *data)
{
    struct toxav_thread_data *data_cast = data;
#if defined TEST_TRANSFER_V && TEST_TRANSFER_V == 1
    cvNamedWindow(vdout, CV_WINDOW_AUTOSIZE);
#endif

    while (data_cast->sig == 0) {
        toxav_iterate(data_cast->AliceAV);
        toxav_iterate(data_cast->BobAV);
        int rc = MIN(toxav_iteration_interval(data_cast->AliceAV), toxav_iteration_interval(data_cast->BobAV));

        printf("\rIteration interval: %d            ", rc);
        fflush(stdout);

#if defined TEST_TRANSFER_V && TEST_TRANSFER_V == 1

        if (!rc)
            rc = 1;

        cvWaitKey(rc);
#else
        c_sleep(rc);
#endif
    }

    data_cast->sig = 1;

#if defined TEST_TRANSFER_V && TEST_TRANSFER_V == 1
    cvDestroyWindow(vdout);
#endif

    pthread_exit(NULL);
}

int send_opencv_img(ToxAV *av, uint32_t friend_number, const IplImage *img)
{
    int32_t strides[3] = { 1280, 640, 640 };
    uint8_t *planes[3] = {
        malloc(img->height * img->width),
        malloc(img->height * img->width / 4),
        malloc(img->height * img->width / 4),
    };

    int x_chroma_shift = 1;
    int y_chroma_shift = 1;

    int x, y;

    for (y = 0; y < img->height; ++y) {
        for (x = 0; x < img->width; ++x) {
            uint8_t r = img->imageData[(x + y * img->width) * 3 + 0];
            uint8_t g = img->imageData[(x + y * img->width) * 3 + 1];
            uint8_t b = img->imageData[(x + y * img->width) * 3 + 2];

            planes[0][x + y * strides[0]] = RGB2Y(r, g, b);

            if (!(x % (1 << x_chroma_shift)) && !(y % (1 << y_chroma_shift))) {
                const int i = x / (1 << x_chroma_shift);
                const int j = y / (1 << y_chroma_shift);
                planes[1][i + j * strides[1]] = RGB2U(r, g, b);
                planes[2][i + j * strides[2]] = RGB2V(r, g, b);
            }
        }
    }

    int rc = toxav_video_send_frame(av, friend_number, img->width, img->height,
                                    planes[0], planes[1], planes[2], NULL);
    free(planes[0]);
    free(planes[1]);
    free(planes[2]);
    return rc;
}
int print_audio_devices()
{
    int i = 0;

    for (i = 0; i < Pa_GetDeviceCount(); ++i) {
        const PaDeviceInfo *info = Pa_GetDeviceInfo(i);

        if (info)
            printf("%d) %s\n", i, info->name);
    }

    return 0;
}
int print_help (const char *name)
{
    printf("Usage: %s -[a:v:o:dh]\n"
           "-a <path> audio input file\n"
           "-b <ms> audio frame duration\n"
           "-v <path> video input file\n"
           "-x <ms> video frame duration\n"
           "-o <idx> output audio device index\n"
           "-d print output audio devices\n"
           "-h print this help\n", name);

    return 0;
}

int main (int argc, char **argv)
{
    freopen("/dev/zero", "w", stderr);
    Pa_Initialize();

    struct stat st;

    /* AV files for testing */
    const char *af_name = NULL;
    const char *vf_name = NULL;
    long audio_out_dev_idx = -1;

    int32_t audio_frame_duration = 20;
    int32_t video_frame_duration = 10;

    /* Parse settings */
CHECK_ARG:

    switch (getopt(argc, argv, "a:b:v:x:o:dh")) {
        case 'a':
            af_name = optarg;
            goto CHECK_ARG;

        case 'b': {
            char *d;
            audio_frame_duration = strtol(optarg, &d, 10);

            if (*d) {
                printf("Invalid value for argument: 'b'");
                exit(1);
            }

            goto CHECK_ARG;
        }

        case 'v':
            vf_name = optarg;
            goto CHECK_ARG;

        case 'x': {
            char *d;
            video_frame_duration = strtol(optarg, &d, 10);

            if (*d) {
                printf("Invalid value for argument: 'x'");
                exit(1);
            }

            goto CHECK_ARG;
        }

        case 'o': {
            char *d;
            audio_out_dev_idx = strtol(optarg, &d, 10);

            if (*d) {
                printf("Invalid value for argument: 'o'");
                exit(1);
            }

            goto CHECK_ARG;
        }

        case 'd':
            return print_audio_devices();

        case 'h':
            return print_help(argv[0]);

        case '?':
            exit(1);

        case -1:
            ;
    }

    { /* Check files */
        if (!af_name) {
            printf("Required audio input file!\n");
            exit(1);
        }

        if (!vf_name) {
            printf("Required video input file!\n");
            exit(1);
        }

        /* Check for files */
        if (stat(af_name, &st) != 0 || !S_ISREG(st.st_mode)) {
            printf("%s doesn't seem to be a regular file!\n", af_name);
            exit(1);
        }

        if (stat(vf_name, &st) != 0 || !S_ISREG(st.st_mode)) {
            printf("%s doesn't seem to be a regular file!\n", vf_name);
            exit(1);
        }
    }

    if (audio_out_dev_idx < 0)
        audio_out_dev_idx = Pa_GetDefaultOutputDevice();

    const PaDeviceInfo *audio_dev = Pa_GetDeviceInfo(audio_out_dev_idx);

    if (!audio_dev) {
        fprintf(stderr, "Device under index: %ld invalid", audio_out_dev_idx);
        return 1;
    }

    printf("Using audio device: %s\n", audio_dev->name);
    printf("Using audio file: %s\n", af_name);
    printf("Using video file: %s\n", vf_name);

    /* START TOX NETWORK */

    Tox *bootstrap;
    ToxAV *AliceAV;
    ToxAV *BobAV;

    CallControl AliceCC;
    CallControl BobCC;

    initialize_tox(&bootstrap, &AliceAV, &AliceCC, &BobAV, &BobCC);

    if (TEST_TRANSFER_A) {
        SNDFILE *af_handle;
        SF_INFO af_info;

        printf("\nTrying audio enc/dec...\n");

        memset(&AliceCC, 0, sizeof(CallControl));
        memset(&BobCC, 0, sizeof(CallControl));

        pthread_mutex_init(AliceCC.arb_mutex, NULL);
        pthread_mutex_init(BobCC.arb_mutex, NULL);

        AliceCC.arb = rb_new(16);
        BobCC.arb = rb_new(16);

        { /* Call */
            TOXAV_ERR_CALL rc;
            toxav_call(AliceAV, 0, 48, 0, &rc);

            if (rc != TOXAV_ERR_CALL_OK) {
                printf("toxav_call failed: %d\n", rc);
                exit(1);
            }
        }

        while (!BobCC.incoming)
            iterate_tox(bootstrap, AliceAV, BobAV);

        { /* Answer */
            TOXAV_ERR_ANSWER rc;
            toxav_answer(BobAV, 0, 48, 0, &rc);

            if (rc != TOXAV_ERR_ANSWER_OK) {
                printf("toxav_answer failed: %d\n", rc);
                exit(1);
            }
        }

        while (AliceCC.state == 0)
            iterate_tox(bootstrap, AliceAV, BobAV);

        /* Open audio file */
        af_handle = sf_open(af_name, SFM_READ, &af_info);

        if (af_handle == NULL) {
            printf("Failed to open the file.\n");
            exit(1);
        }

        int16_t PCM[5760];

        time_t start_time = time(NULL);
        time_t expected_time = af_info.frames / af_info.samplerate + 2;


        /* Start decode thread */
        struct toxav_thread_data data = {
            .AliceAV = AliceAV,
            .BobAV = BobAV,
            .sig = 0
        };

        pthread_t dect;
        pthread_create(&dect, NULL, iterate_toxav, &data);
        pthread_detach(dect);

        int frame_size = (af_info.samplerate * audio_frame_duration / 1000) * af_info.channels;

        struct PaStreamParameters output;
        output.device = audio_out_dev_idx;
        output.channelCount = af_info.channels;
        output.sampleFormat = paInt16;
        output.suggestedLatency = audio_dev->defaultHighOutputLatency;
        output.hostApiSpecificStreamInfo = NULL;

        PaError err = Pa_OpenStream(&adout, NULL, &output, af_info.samplerate, frame_size, paNoFlag, NULL, NULL);
        assert(err == paNoError);

        err = Pa_StartStream(adout);
        assert(err == paNoError);

//         toxav_audio_bit_rate_set(AliceAV, 0, 64, false, NULL);

        /* Start write thread */
        pthread_t t;
        pthread_create(&t, NULL, pa_write_thread, &BobCC);
        pthread_detach(t);

        printf("Sample rate %d\n", af_info.samplerate);

        while (start_time + expected_time > time(NULL) ) {
            uint64_t enc_start_time = current_time_monotonic();
            int64_t count = sf_read_short(af_handle, PCM, frame_size);

            if (count > 0) {
                TOXAV_ERR_SEND_FRAME rc;

                if (toxav_audio_send_frame(AliceAV, 0, PCM, count / af_info.channels, af_info.channels, af_info.samplerate,
                                           &rc) == false) {
                    printf("Error sending frame of size %ld: %d\n", count, rc);
                }
            }

            iterate_tox(bootstrap, AliceAV, BobAV);
            c_sleep(abs(audio_frame_duration - (current_time_monotonic() - enc_start_time) - 1));
        }

        printf("Played file in: %lu; stopping stream...\n", time(NULL) - start_time);

        Pa_StopStream(adout);
        sf_close(af_handle);

        { /* Hangup */
            TOXAV_ERR_CALL_CONTROL rc;
            toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);

            if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
                printf("toxav_call_control failed: %d\n", rc);
                exit(1);
            }
        }

        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state == TOXAV_FRIEND_CALL_STATE_FINISHED);

        /* Stop decode thread */
        data.sig = -1;

        while (data.sig != 1)
            pthread_yield();

        pthread_mutex_destroy(AliceCC.arb_mutex);
        pthread_mutex_destroy(BobCC.arb_mutex);

        void *f = NULL;

        while (rb_read(AliceCC.arb, &f))
            free(f);

        while (rb_read(BobCC.arb, &f))
            free(f);

        printf("Success!");
    }

    if (TEST_TRANSFER_V) {
        printf("\nTrying video enc/dec...\n");

        memset(&AliceCC, 0, sizeof(CallControl));
        memset(&BobCC, 0, sizeof(CallControl));

        { /* Call */
            TOXAV_ERR_CALL rc;
            toxav_call(AliceAV, 0, 0, 2000, &rc);

            if (rc != TOXAV_ERR_CALL_OK) {
                printf("toxav_call failed: %d\n", rc);
                exit(1);
            }
        }

        while (!BobCC.incoming)
            iterate_tox(bootstrap, AliceAV, BobAV);

        { /* Answer */
            TOXAV_ERR_ANSWER rc;
            toxav_answer(BobAV, 0, 0, 5000, &rc);

            if (rc != TOXAV_ERR_ANSWER_OK) {
                printf("toxav_answer failed: %d\n", rc);
                exit(1);
            }
        }

        iterate_tox(bootstrap, AliceAV, BobAV);

        /* Start decode thread */
        struct toxav_thread_data data = {
            .AliceAV = AliceAV,
            .BobAV = BobAV,
            .sig = 0
        };

        pthread_t dect;
        pthread_create(&dect, NULL, iterate_toxav, &data);
        pthread_detach(dect);

        CvCapture *capture = cvCreateFileCapture(vf_name);

        if (!capture) {
            printf("Failed to open video file: %s\n", vf_name);
            exit(1);
        }

//         toxav_video_bit_rate_set(AliceAV, 0, 5000, false, NULL);

        time_t start_time = time(NULL);

        while (start_time + 90 > time(NULL)) {
            IplImage *frame = cvQueryFrame(capture );

            if (!frame)
                break;

            send_opencv_img(AliceAV, 0, frame);
            iterate_tox(bootstrap, AliceAV, BobAV);
            c_sleep(10);
        }

        cvReleaseCapture(&capture);

        { /* Hangup */
            TOXAV_ERR_CALL_CONTROL rc;
            toxav_call_control(AliceAV, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);

            if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
                printf("toxav_call_control failed: %d\n", rc);
                exit(1);
            }
        }

        iterate_tox(bootstrap, AliceAV, BobAV);
        assert(BobCC.state == TOXAV_FRIEND_CALL_STATE_FINISHED);

        /* Stop decode thread */
        printf("Stopping decode thread\n");
        data.sig = -1;

        while (data.sig != 1)
            pthread_yield();

        printf("Success!");
    }


    Tox *Alice = toxav_get_tox(AliceAV);
    Tox *Bob = toxav_get_tox(BobAV);
    toxav_kill(BobAV);
    toxav_kill(AliceAV);
    tox_kill(Bob);
    tox_kill(Alice);
    tox_kill(bootstrap);

    printf("\nTest successful!\n");

    Pa_Terminate();
    return 0;
}
