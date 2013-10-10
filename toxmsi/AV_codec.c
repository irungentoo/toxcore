/* AV_codec.c
//  *
 * Audio and video codec intitialisation, encoding/decoding and playback
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*----------------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <math.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>
#include <libavdevice/avdevice.h>
#include <libavutil/opt.h>
#include <AL/al.h>
#include <AL/alc.h>
#include <SDL.h>
#include <SDL_thread.h>
#include <pthread.h>
#include <opus/opus.h>

#include "toxmsi.h"
#include "toxmsi_message.h"
#include "toxrtp_message.h"
#include "toxrtp/tests/test_helper.h"
#include "phone.h"
#include "AV_codec.h"

int display_received_frame(codec_state *cs, AVFrame *r_video_frame)
{
    AVPicture pict;
    SDL_LockYUVOverlay(cs->video_picture.bmp);

    pict.data[0] = cs->video_picture.bmp->pixels[0];
    pict.data[1] = cs->video_picture.bmp->pixels[2];
    pict.data[2] = cs->video_picture.bmp->pixels[1];
    pict.linesize[0] = cs->video_picture.bmp->pitches[0];
    pict.linesize[1] = cs->video_picture.bmp->pitches[2];
    pict.linesize[2] = cs->video_picture.bmp->pitches[1];

    /* Convert the image into YUV format that SDL uses */
    sws_scale(cs->sws_SDL_r_ctx, (uint8_t const * const *)r_video_frame->data, r_video_frame->linesize, 0,
              cs->video_decoder_ctx->height, pict.data, pict.linesize );

    SDL_UnlockYUVOverlay(cs->video_picture.bmp);
    SDL_Rect rect;
    rect.x = 0;
    rect.y = 0;
    rect.w = cs->video_decoder_ctx->width;
    rect.h = cs->video_decoder_ctx->height;
    SDL_DisplayYUVOverlay(cs->video_picture.bmp, &rect);
    return 1;
}

struct jitter_buffer {
    rtp_msg_t **queue;
    uint16_t capacity;
    uint16_t size;
    uint16_t front;
    uint16_t rear;
    uint8_t queue_ready;
    uint16_t current_id;
    uint32_t current_ts;
    uint8_t id_set;
};

struct jitter_buffer *create_queue(int capacity)
{
    struct jitter_buffer *q;
    q = (struct jitter_buffer *)malloc(sizeof(struct jitter_buffer));
    q->queue = (rtp_msg_t **)malloc(sizeof(rtp_msg_t) * capacity);
    int i = 0;

    for (i = 0; i < capacity; ++i) {
        q->queue[i] = NULL;
    }

    q->size = 0;
    q->capacity = capacity;
    q->front = 0;
    q->rear = -1;
    q->queue_ready = 0;
    q->current_id = 0;
    q->current_ts = 0;
    q->id_set = 0;
    return q;
}

/* returns 1 if 'a' has a higher sequence number than 'b' */
uint8_t sequence_number_older(uint16_t sn_a, uint16_t sn_b, uint32_t ts_a, uint32_t ts_b)
{
    /* should be stable enough */
    return (sn_a > sn_b || ts_a > ts_b);
}

/* success is 0 when there is nothing to dequeue, 1 when there's a good packet, 2 when there's a lost packet */
rtp_msg_t *dequeue(struct jitter_buffer *q, int *success)
{
    if (q->size == 0 || q->queue_ready == 0) {
        q->queue_ready = 0;
        *success = 0;
        return NULL;
    }

    int front = q->front;

    if (q->id_set == 0) {
        q->current_id = q->queue[front]->_header->_sequence_number;
        q->current_ts = q->queue[front]->_header->_timestamp;
        q->id_set = 1;
    } else {
        int next_id = q->queue[front]->_header->_sequence_number;
        int next_ts = q->queue[front]->_header->_timestamp;

        /* if this packet is indeed the expected packet */
        if (next_id == (q->current_id + 1) % _MAX_SEQU_NUM) {
            q->current_id = next_id;
            q->current_ts = next_ts;
        } else {
            if (sequence_number_older(next_id, q->current_id, next_ts, q->current_ts)) {
                printf("nextid: %d current: %d\n", next_id, q->current_id);
                q->current_id = (q->current_id + 1) % _MAX_SEQU_NUM;
                *success = 2; /* tell the decoder the packet is lost */
                return NULL;
            } else {
                /* packet too old */
                printf("packet too old\n");
                *success = 0;
                return NULL;
            }
        }
    }

    q->size--;
    q->front++;

    if (q->front == q->capacity)
        q->front = 0;

    *success = 1;
    q->current_id = q->queue[front]->_header->_sequence_number;
    q->current_ts = q->queue[front]->_header->_timestamp;
    return q->queue[front];
}

int empty_queue(struct jitter_buffer *q)
{
    while (q->size > 0) {
        q->size--;
        /* FIXME: */
        /* rtp_free_msg(cs->_rtp_video, q->queue[q->front]); */
        q->front++;

        if (q->front == q->capacity)
            q->front = 0;
    }

    q->id_set = 0;
    q->queue_ready = 0;
    return 0;
}

int queue(struct jitter_buffer *q, rtp_msg_t *pk)
{
    if (q->size == q->capacity) {
        printf("buffer full, emptying buffer...\n");
        empty_queue(q);
        return 0;
    }

    if (q->size > 8)
        q->queue_ready = 1;

    ++q->size;
    ++q->rear;

    if (q->rear == q->capacity)
        q->rear = 0;

    q->queue[q->rear] = pk;

    int a;
    int b;
    int j;
    a = q->rear;

    for (j = 0; j < q->size - 1; ++j) {
        b = a - 1;

        if (b < 0)
            b += q->capacity;

        if (sequence_number_older(q->queue[b]->_header->_sequence_number, q->queue[a]->_header->_sequence_number,
                                  q->queue[b]->_header->_timestamp, q->queue[a]->_header->_timestamp)) {
            rtp_msg_t *temp;
            temp = q->queue[a];
            q->queue[a] = q->queue[b];
            q->queue[b] = temp;
            printf("had to swap\n");
        } else {
            break;
        }

        a -= 1;

        if (a < 0)
            a += q->capacity;
    }

    if (pk)
        return 1;

    return 0;
}

int init_receive_audio(codec_state *cs)
{
    int err = OPUS_OK;
    cs->audio_decoder = opus_decoder_create(48000, 1, &err);
    opus_decoder_init(cs->audio_decoder, 48000, 1);
    printf("init audio decoder successful\n");
    return 1;
}

int init_receive_video(codec_state *cs)
{
    cs->video_decoder = avcodec_find_decoder(VIDEO_CODEC);

    if (!cs->video_decoder) {
        printf("init video_decoder failed\n");
        return 0;
    }

    cs->video_decoder_ctx = avcodec_alloc_context3(cs->video_decoder);

    if (!cs->video_decoder_ctx) {
        printf("init video_decoder_ctx failed\n");
        return 0;
    }

    if (avcodec_open2(cs->video_decoder_ctx, cs->video_decoder, NULL) < 0) {
        printf("opening video decoder failed\n");
        return 0;
    }

    printf("init video decoder successful\n");
    return 1;
}

int init_send_video(codec_state *cs)
{
    cs->video_input_format = av_find_input_format(VIDEO_DRIVER);

    if (avformat_open_input(&cs->video_format_ctx, DEFAULT_WEBCAM, cs->video_input_format, NULL) != 0) {
        printf("opening video_input_format failed\n");
        return 0;
    }

    avformat_find_stream_info(cs->video_format_ctx, NULL);
    av_dump_format(cs->video_format_ctx, 0, DEFAULT_WEBCAM, 0);

    int i;

    for (i = 0; i < cs->video_format_ctx->nb_streams; ++i) {
        if (cs->video_format_ctx->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO) {
            cs->video_stream = i;
            break;
        }
    }

    cs->webcam_decoder_ctx = cs->video_format_ctx->streams[cs->video_stream]->codec;
    cs->webcam_decoder = avcodec_find_decoder(cs->webcam_decoder_ctx->codec_id);

    if (cs->webcam_decoder == NULL) {
        printf("Unsupported codec\n");
        return 0;
    }

    if (cs->webcam_decoder_ctx == NULL) {
        printf("init webcam_decoder_ctx failed\n");
        return 0;
    }

    if (avcodec_open2(cs->webcam_decoder_ctx, cs->webcam_decoder, NULL) < 0) {
        printf("opening webcam decoder failed\n");
        return 0;
    }

    cs->video_encoder = avcodec_find_encoder(VIDEO_CODEC);

    if (!cs->video_encoder) {
        printf("init video_encoder failed\n");
        return 0;
    }

    cs->video_encoder_ctx = avcodec_alloc_context3(cs->video_encoder);

    if (!cs->video_encoder_ctx) {
        printf("init video_encoder_ctx failed\n");
        return 0;
    }

    cs->video_encoder_ctx->bit_rate = VIDEO_BITRATE;
    cs->video_encoder_ctx->rc_min_rate = cs->video_encoder_ctx->rc_max_rate = cs->video_encoder_ctx->bit_rate;
    av_opt_set_double(cs->video_encoder_ctx->priv_data, "max-intra-rate", 90, 0);
    av_opt_set(cs->video_encoder_ctx->priv_data, "quality", "realtime", 0);

    cs->video_encoder_ctx->thread_count = 4;
    cs->video_encoder_ctx->rc_buffer_aggressivity = 0.95;
    cs->video_encoder_ctx->rc_buffer_size = VIDEO_BITRATE * 6;
    cs->video_encoder_ctx->profile = 3;
    cs->video_encoder_ctx->qmax = 54;
    cs->video_encoder_ctx->qmin = 4;
    AVRational myrational = {1, 25};
    cs->video_encoder_ctx->time_base = myrational;
    cs->video_encoder_ctx->gop_size = 99999;
    cs->video_encoder_ctx->pix_fmt = PIX_FMT_YUV420P;
    cs->video_encoder_ctx->width = cs->webcam_decoder_ctx->width;
    cs->video_encoder_ctx->height = cs->webcam_decoder_ctx->height;

    if (avcodec_open2(cs->video_encoder_ctx, cs->video_encoder, NULL) < 0) {
        printf("opening video encoder failed\n");
        return 0;
    }

    printf("init video encoder successful\n");
    return 1;
}

int init_send_audio(codec_state *cs)
{
    cs->support_send_audio = 0;

    const ALchar *pDeviceList = alcGetString(NULL, ALC_CAPTURE_DEVICE_SPECIFIER);
    int i = 0;
    const ALchar *device_names[20];

    if (pDeviceList) {
        printf("\nAvailable Capture Devices are:\n");

        while (*pDeviceList) {
            device_names[i] = pDeviceList;
            printf("%d) %s\n", i, device_names[i]);
            pDeviceList += strlen(pDeviceList) + 1;
            ++i;
        }
    }

    printf("enter capture device number: \n");
    char dev[2];
    fgets(dev, sizeof(dev), stdin);
    cs->audio_capture_device = alcCaptureOpenDevice(device_names[dev[0] - 48], AUDIO_SAMPLE_RATE, AL_FORMAT_MONO16,
                               AUDIO_FRAME_SIZE * 4);

    if (alcGetError(cs->audio_capture_device) != AL_NO_ERROR) {
        printf("could not start capture device! %d\n", alcGetError(cs->audio_capture_device));
        return 0;
    }

    int err = OPUS_OK;
    cs->audio_bitrate = AUDIO_BITRATE;
    cs->audio_encoder = opus_encoder_create(AUDIO_SAMPLE_RATE, 1, OPUS_APPLICATION_VOIP, &err);
    err = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_BITRATE(cs->audio_bitrate));
    err = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_COMPLEXITY(10));
    err = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));

    opus_encoder_init(cs->audio_encoder, AUDIO_SAMPLE_RATE, 1, OPUS_APPLICATION_VOIP);

    int nfo;
    err = opus_encoder_ctl(cs->audio_encoder, OPUS_GET_LOOKAHEAD(&nfo));
    /* printf("Encoder lookahead delay : %d\n", nfo); */
    printf("init audio encoder successful\n");

    return 1;
}

int init_encoder(codec_state *cs)
{
    avdevice_register_all();
    avcodec_register_all();
    avdevice_register_all();
    av_register_all();

    pthread_mutex_init(&cs->rtp_msg_mutex_lock, NULL);
    pthread_mutex_init(&cs->avcodec_mutex_lock, NULL);

    cs->support_send_video = init_send_video(cs);
    cs->support_send_audio = init_send_audio(cs);

    cs->send_audio = 1;
    cs->send_video = 1;

    return 1;
}

int init_decoder(codec_state *cs)
{
    avdevice_register_all();
    avcodec_register_all();
    avdevice_register_all();
    av_register_all();

    cs->receive_video = 0;
    cs->receive_audio = 0;

    cs->support_receive_video = init_receive_video(cs);
    cs->support_receive_audio = init_receive_audio(cs);

    cs->receive_audio = 1;
    cs->receive_video = 1;

    return 1;
}

int video_encoder_refresh(codec_state *cs, int bps)
{
    if (cs->video_encoder_ctx)
        avcodec_close(cs->video_encoder_ctx);

    cs->video_encoder = avcodec_find_encoder(VIDEO_CODEC);

    if (!cs->video_encoder) {
        printf("init video_encoder failed\n");
        return -1;
    }

    cs->video_encoder_ctx = avcodec_alloc_context3(cs->video_encoder);

    if (!cs->video_encoder_ctx) {
        printf("init video_encoder_ctx failed\n");
        return -1;
    }

    cs->video_encoder_ctx->bit_rate = bps;
    cs->video_encoder_ctx->rc_min_rate = cs->video_encoder_ctx->rc_max_rate = cs->video_encoder_ctx->bit_rate;
    av_opt_set_double(cs->video_encoder_ctx->priv_data, "max-intra-rate", 90, 0);
    av_opt_set(cs->video_encoder_ctx->priv_data, "quality", "realtime", 0);

    cs->video_encoder_ctx->thread_count = 4;
    cs->video_encoder_ctx->rc_buffer_aggressivity = 0.95;
    cs->video_encoder_ctx->rc_buffer_size = bps * 6;
    cs->video_encoder_ctx->profile = 0;
    cs->video_encoder_ctx->qmax = 54;
    cs->video_encoder_ctx->qmin = 4;
    AVRational myrational = {1, 25};
    cs->video_encoder_ctx->time_base = myrational;
    cs->video_encoder_ctx->gop_size = 99999;
    cs->video_encoder_ctx->pix_fmt = PIX_FMT_YUV420P;
    cs->video_encoder_ctx->width = cs->webcam_decoder_ctx->width;
    cs->video_encoder_ctx->height = cs->webcam_decoder_ctx->height;

    if (avcodec_open2(cs->video_encoder_ctx, cs->video_encoder, NULL) < 0) {
        printf("opening video encoder failed\n");
        return -1;
    }
    return 0;
}

void *encode_video_thread(void *arg)
{
    codec_state *cs = (codec_state *)arg;
    AVPacket pkt1, *packet = &pkt1;
    int p = 0;
    int err;
    int got_packet;
    rtp_msg_t *s_video_msg;
    int video_frame_finished;
    AVFrame *s_video_frame;
    AVFrame *webcam_frame;
    s_video_frame = avcodec_alloc_frame();
    webcam_frame = avcodec_alloc_frame();
    AVPacket enc_video_packet;

    uint8_t *buffer;
    int numBytes;
    /* Determine required buffer size and allocate buffer */
    numBytes = avpicture_get_size(PIX_FMT_YUV420P, cs->webcam_decoder_ctx->width, cs->webcam_decoder_ctx->height);
    buffer = (uint8_t *)av_malloc(numBytes * sizeof(uint8_t));
    avpicture_fill((AVPicture *)s_video_frame, buffer, PIX_FMT_YUV420P, cs->webcam_decoder_ctx->width,
                   cs->webcam_decoder_ctx->height);
    cs->sws_ctx = sws_getContext(cs->webcam_decoder_ctx->width, cs->webcam_decoder_ctx->height,
                                 cs->webcam_decoder_ctx->pix_fmt, cs->webcam_decoder_ctx->width, cs->webcam_decoder_ctx->height, PIX_FMT_YUV420P,
                                 SWS_BILINEAR, NULL, NULL, NULL);

    while (!cs->quit && cs->send_video) {

        if (av_read_frame(cs->video_format_ctx, packet) < 0) {
            printf("error reading frame\n");

            if (cs->video_format_ctx->pb->error != 0)
                break;

            continue;
        }

        if (packet->stream_index == cs->video_stream) {
            if (avcodec_decode_video2(cs->webcam_decoder_ctx, webcam_frame, &video_frame_finished, packet) < 0) {
                printf("couldn't decode\n");
                continue;
            }

            av_free_packet(packet);
            sws_scale(cs->sws_ctx, (uint8_t const * const *)webcam_frame->data, webcam_frame->linesize, 0,
                      cs->webcam_decoder_ctx->height, s_video_frame->data, s_video_frame->linesize);
            /* create a new I-frame every 60 frames */
            ++p;

            if (p == 60) {

                s_video_frame->pict_type = AV_PICTURE_TYPE_BI ;
            } else if (p == 61) {
                s_video_frame->pict_type = AV_PICTURE_TYPE_I ;
                p = 0;
            } else {
                s_video_frame->pict_type = AV_PICTURE_TYPE_P ;
            }

            if (video_frame_finished) {
                err = avcodec_encode_video2(cs->video_encoder_ctx, &enc_video_packet, s_video_frame, &got_packet);

                if (err < 0) {
                    printf("could not encode video frame\n");
                    continue;
                }

                if (!got_packet) {
                    continue;
                }

                pthread_mutex_lock(&cs->rtp_msg_mutex_lock);
                THREADLOCK()

                if (!enc_video_packet.data) fprintf(stderr, "video packet data is NULL\n");

                s_video_msg = rtp_msg_new ( cs->_rtp_video, enc_video_packet.data, enc_video_packet.size ) ;

                if (!s_video_msg) {
                    printf("invalid message\n");
                }

                rtp_send_msg ( cs->_rtp_video, s_video_msg, cs->_networking );
                THREADUNLOCK()
                pthread_mutex_unlock(&cs->rtp_msg_mutex_lock);
                av_free_packet(&enc_video_packet);
            }
        } else {
            av_free_packet(packet);
        }
    }

    /* clean up codecs */
    pthread_mutex_lock(&cs->avcodec_mutex_lock);
    av_free(buffer);
    av_free(webcam_frame);
    av_free(s_video_frame);
    sws_freeContext(cs->sws_ctx);
    avcodec_close(cs->webcam_decoder_ctx);
    avcodec_close(cs->video_encoder_ctx);
    pthread_mutex_unlock(&cs->avcodec_mutex_lock);
    pthread_exit ( NULL );
}

void *encode_audio_thread(void *arg)
{
    codec_state *cs = (codec_state *)arg;
    rtp_msg_t *s_audio_msg;
    unsigned char encoded_data[4096];
    int encoded_size = 0;
    int16_t frame[4096];
    int frame_size = AUDIO_FRAME_SIZE;
    ALint sample = 0;
    alcCaptureStart(cs->audio_capture_device);

    while (!cs->quit && cs->send_audio) {
        alcGetIntegerv(cs->audio_capture_device, ALC_CAPTURE_SAMPLES, (ALCsizei)sizeof(ALint), &sample);

        if (sample >= frame_size) {
            alcCaptureSamples(cs->audio_capture_device, frame, frame_size);
            encoded_size = opus_encode(cs->audio_encoder, frame, frame_size, encoded_data, 480);

            if (encoded_size <= 0) {
                printf("Could not encode audio packet\n");
            } else {
                pthread_mutex_lock(&cs->rtp_msg_mutex_lock);
                THREADLOCK()
                rtp_set_payload_type(cs->_rtp_audio, 96);
                s_audio_msg = rtp_msg_new (cs->_rtp_audio, encoded_data, encoded_size) ;
                rtp_send_msg ( cs->_rtp_audio, s_audio_msg, cs->_networking );
                pthread_mutex_unlock(&cs->rtp_msg_mutex_lock);
                THREADUNLOCK()
            }
        } else {
            usleep(1000);
        }
    }

    /* clean up codecs */
    pthread_mutex_lock(&cs->avcodec_mutex_lock);
    alcCaptureStop(cs->audio_capture_device);
    alcCaptureCloseDevice(cs->audio_capture_device);

    pthread_mutex_unlock(&cs->avcodec_mutex_lock);
    pthread_exit ( NULL );
}


int video_decoder_refresh(codec_state *cs, int width, int height)
{
    printf("need to refresh\n");
    screen = SDL_SetVideoMode(width, height, 0, 0);

    if (cs->video_picture.bmp)
        SDL_FreeYUVOverlay(cs->video_picture.bmp);

    cs->video_picture.bmp = SDL_CreateYUVOverlay(width, height, SDL_YV12_OVERLAY, screen);
    cs->sws_SDL_r_ctx = sws_getContext(width, height, cs->video_decoder_ctx->pix_fmt, width, height, PIX_FMT_YUV420P,
                                       SWS_BILINEAR, NULL, NULL, NULL);
    return 1;
}

void *decode_video_thread(void *arg)
{
    codec_state *cs = (codec_state *)arg;
    cs->video_stream = 0;
    rtp_msg_t *r_msg;
    int dec_frame_finished;
    AVFrame *r_video_frame;
    r_video_frame = avcodec_alloc_frame();
    AVPacket dec_video_packet;
    av_new_packet (&dec_video_packet, 65536);
    int width = 0;
    int height = 0;

    while (!cs->quit && cs->receive_video) {
        r_msg = rtp_recv_msg ( cs->_rtp_video );

        if (r_msg) {
            memcpy(dec_video_packet.data, r_msg->_data, r_msg->_length);
            dec_video_packet.size = r_msg->_length;
            avcodec_decode_video2(cs->video_decoder_ctx, r_video_frame, &dec_frame_finished, &dec_video_packet);

            if (dec_frame_finished) {
                if (cs->video_decoder_ctx->width != width || cs->video_decoder_ctx->height != height) {
                    width = cs->video_decoder_ctx->width;
                    height = cs->video_decoder_ctx->height;
                    printf("w: %d h%d \n", width, height);
                    video_decoder_refresh(cs, width, height);
                }

                display_received_frame(cs, r_video_frame);
            } else {
                /* TODO: request the sender to create a new i-frame immediatly */
                printf("bad video packet\n");
            }

            rtp_free_msg(cs->_rtp_video, r_msg);
        }

        usleep(1000);
    }

    printf("vend\n");
    /* clean up codecs */
    pthread_mutex_lock(&cs->avcodec_mutex_lock);
    av_free(r_video_frame);
    avcodec_close(cs->video_decoder_ctx);
    pthread_mutex_unlock(&cs->avcodec_mutex_lock);
    pthread_exit ( NULL );
}

void *decode_audio_thread(void *arg)
{
    codec_state *cs = (codec_state *)arg;
    rtp_msg_t *r_msg;

    int frame_size = AUDIO_FRAME_SIZE;
    int data_size;

    ALCdevice *dev;
    ALCcontext *ctx;
    ALuint source, *buffers;
    dev = alcOpenDevice(NULL);
    ctx = alcCreateContext(dev, NULL);
    alcMakeContextCurrent(ctx);
    int openal_buffers = 5;

    buffers = malloc(sizeof(ALuint) * openal_buffers);
    alGenBuffers(openal_buffers, buffers);
    alGenSources((ALuint)1, &source);
    alSourcei(source, AL_LOOPING, AL_FALSE);

    ALuint buffer;
    ALint val;

    ALenum error;
    uint16_t zeros[frame_size];
    int i;

    for (i = 0; i < frame_size; i++) {
        zeros[i] = 0;
    }

    for (i = 0; i < openal_buffers; ++i) {
        alBufferData(buffers[i], AL_FORMAT_MONO16, zeros, frame_size, 48000);
    }

    alSourceQueueBuffers(source, openal_buffers, buffers);
    alSourcePlay(source);

    if (alGetError() != AL_NO_ERROR) {
        fprintf(stderr, "Error starting audio\n");
        cs->quit = 1;
    }

    struct jitter_buffer *j_buf = NULL;

    j_buf = create_queue(20);

    int success = 0;

    int dec_frame_len;

    opus_int16 PCM[frame_size];

    while (!cs->quit && cs->receive_audio) {
        THREADLOCK()
        r_msg = rtp_recv_msg ( cs->_rtp_audio );

        if (r_msg) {
            /* push the packet into the queue */
            queue(j_buf, r_msg);
        }

        /* grab a packet from the queue */
        success = 0;
        alGetSourcei(source, AL_BUFFERS_PROCESSED, &val);

        if (val > 0)
            r_msg = dequeue(j_buf, &success);

        if (success > 0) {
            /* good packet */
            if (success == 1) {
                dec_frame_len = opus_decode(cs->audio_decoder, r_msg->_data, r_msg->_length, PCM, frame_size, 0);
                rtp_free_msg(cs->_rtp_audio, r_msg);
            }

            /* lost packet  */
            if (success == 2) {
                printf("lost packet\n");
                dec_frame_len = opus_decode(cs->audio_decoder, NULL, 0, PCM, frame_size, 1);
            }

            if (dec_frame_len > 0) {
                alGetSourcei(source, AL_BUFFERS_PROCESSED, &val);

                if (val <= 0)
                    continue;

                alSourceUnqueueBuffers(source, 1, &buffer);
                data_size = av_samples_get_buffer_size(NULL, 1, dec_frame_len, AV_SAMPLE_FMT_S16, 1);
                alBufferData(buffer, AL_FORMAT_MONO16, PCM, data_size, 48000);
                int error = alGetError();

                if (error != AL_NO_ERROR) {
                    fprintf(stderr, "Error setting buffer %d\n", error);
                    break;
                }

                alSourceQueueBuffers(source, 1, &buffer);

                if (alGetError() != AL_NO_ERROR) {
                    fprintf(stderr, "error: could not buffer audio\n");
                    break;
                }

                alGetSourcei(source, AL_SOURCE_STATE, &val);

                if (val != AL_PLAYING)
                    alSourcePlay(source);


            }
        }

        THREADUNLOCK()
        usleep(1000);
    }

    /* clean up codecs */
    pthread_mutex_lock(&cs->avcodec_mutex_lock);

    /* clean up openal */
    alDeleteSources(1, &source);
    alDeleteBuffers(openal_buffers, buffers);
    alcMakeContextCurrent(NULL);
    alcDestroyContext(ctx);
    alcCloseDevice(dev);
    pthread_mutex_unlock(&cs->avcodec_mutex_lock);
    pthread_exit ( NULL );
}