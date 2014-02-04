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
#include <opus/opus.h>
#include <assert.h>

#include "toxmsi.h"
#include "toxrtp.h"
#include "toxmedia.h"

struct jitter_buffer {
    RTPMessage **queue;
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
    q = (struct jitter_buffer *)calloc(sizeof(struct jitter_buffer),1);
    q->queue = (RTPMessage **)calloc((sizeof(RTPMessage) * capacity),1);
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
    
    /* TODO: There is already this kind of function in toxrtp.c.
     *       Maybe merge?
     */
    return (sn_a > sn_b || ts_a > ts_b);
}

/* success is 0 when there is nothing to dequeue, 1 when there's a good packet, 2 when there's a lost packet */
RTPMessage *dequeue(struct jitter_buffer *q, int *success)
{
    if (q->size == 0 || q->queue_ready == 0) {
        q->queue_ready = 0;
        *success = 0;
        return NULL;
    }

    int front = q->front;

    if (q->id_set == 0) {
        q->current_id = q->queue[front]->header->sequnum;
        q->current_ts = q->queue[front]->header->timestamp;
        q->id_set = 1;
    } else {
        int next_id = q->queue[front]->header->sequnum;
        int next_ts = q->queue[front]->header->timestamp;

        /* if this packet is indeed the expected packet */
        if (next_id == (q->current_id + 1) % MAX_SEQU_NUM) {
            q->current_id = next_id;
            q->current_ts = next_ts;
        } else {
            if (sequence_number_older(next_id, q->current_id, next_ts, q->current_ts)) {
                printf("nextid: %d current: %d\n", next_id, q->current_id);
                q->current_id = (q->current_id + 1) % MAX_SEQU_NUM;
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
    q->current_id = q->queue[front]->header->sequnum;
    q->current_ts = q->queue[front]->header->timestamp;
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

int queue(struct jitter_buffer *q, RTPMessage *pk)
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

        if (sequence_number_older(q->queue[b]->header->sequnum, q->queue[a]->header->sequnum,
                                  q->queue[b]->header->timestamp, q->queue[a]->header->timestamp)) {
            RTPMessage *temp;
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
    int rc;
    cs->audio_decoder = opus_decoder_create(48000, 1, &rc );    
    
    if ( rc != OPUS_OK ){
        printf("Error while starting audio decoder!\n");
        return 0;
    }
    
    rc = opus_decoder_init(cs->audio_decoder, 48000, 1);
    
    if ( rc != OPUS_OK ){
        printf("Error while starting audio decoder!\n");
        return 0;
    }
    
    
    printf("Init audio decoder successful\n");
    return 1;
}

int init_receive_video(codec_state *cs)
{
    cs->video_decoder = avcodec_find_decoder(VIDEO_CODEC);

    if (!cs->video_decoder) {
        printf("Init video_decoder failed\n");
        return 0;
    }

    cs->video_decoder_ctx = avcodec_alloc_context3(cs->video_decoder);

    if (!cs->video_decoder_ctx) {
        printf("Init video_decoder_ctx failed\n");
        return 0;
    }

    if (avcodec_open2(cs->video_decoder_ctx, cs->video_decoder, NULL) < 0) {
        printf("Opening video decoder failed\n");
        return 0;
    }

    printf("Init video decoder successful\n");
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

    int err = OPUS_OK;
    cs->audio_bitrate = AUDIO_BITRATE;
    cs->audio_encoder = opus_encoder_create(AUDIO_SAMPLE_RATE, 1, OPUS_APPLICATION_VOIP, &err);
    err = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_BITRATE(cs->audio_bitrate));
    err = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_COMPLEXITY(10));
    err = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));

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

    pthread_mutex_init(&cs->ctrl_mutex, NULL);

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