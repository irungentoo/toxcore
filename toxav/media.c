/**  media.c
 *
 *   Audio and video codec intitialization, encoding/decoding and playback
 *
 *   Copyright (C) 2013 Tox project All Rights Reserved.
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
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

#include "rtp.h"
#include "media.h"

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
    q = (struct jitter_buffer *)calloc(sizeof(struct jitter_buffer), 1);
    q->queue = (RTPMessage **)calloc(sizeof(RTPMessage *), capacity);
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
        rtp_free_msg(NULL, q->queue[q->front]);
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


int init_video_decoder(CodecState *cs)
{
    if (vpx_codec_dec_init_ver(&cs->v_decoder, VIDEO_CODEC_DECODER_INTERFACE, NULL, 0,
                               VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
        fprintf(stderr, "Init video_decoder failed!\n");
        return -1;
    }

    return 0;
}

int init_audio_decoder(CodecState *cs, uint32_t audio_channels)
{
    int rc;
    cs->audio_decoder = opus_decoder_create(cs->audio_sample_rate, audio_channels, &rc );

    if ( rc != OPUS_OK ) {
        fprintf(stderr, "Error while starting audio decoder!\n");
        return -1;
    }

    return 0;
}


int init_video_encoder(CodecState *cs, uint16_t width, uint16_t height, uint32_t video_bitrate)
{
    vpx_codec_enc_cfg_t  cfg;
    int res = vpx_codec_enc_config_default(VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0);

    if (res) {
        printf("Failed to get config: %s\n", vpx_codec_err_to_string(res));
        return -1;
    }

    cfg.rc_target_bitrate = video_bitrate;
    cfg.g_w = width;
    cfg.g_h = height;

    if (vpx_codec_enc_init_ver(&cs->v_encoder, VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0,
                               VPX_ENCODER_ABI_VERSION) != VPX_CODEC_OK) {
        fprintf(stderr, "Failed to initialize encoder\n");
        return -1;
    }

    return 0;
}

int init_audio_encoder(CodecState *cs, uint32_t audio_channels)
{
    int err = OPUS_OK;
    cs->audio_encoder = opus_encoder_create(cs->audio_sample_rate, audio_channels, OPUS_APPLICATION_AUDIO, &err);
    err = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_BITRATE(cs->audio_bitrate));
    err = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_COMPLEXITY(10));


    return err == OPUS_OK ? 0 : -1;
}


CodecState *codec_init_session ( uint32_t audio_bitrate,
                                 uint16_t audio_frame_duration,
                                 uint32_t audio_sample_rate,
                                 uint32_t audio_channels,
                                 uint16_t video_width,
                                 uint16_t video_height,
                                 uint32_t video_bitrate )
{
    CodecState *_retu = calloc(sizeof(CodecState), 1);
    assert(_retu);

    _retu->audio_bitrate = audio_bitrate;
    _retu->audio_sample_rate = audio_sample_rate;

    /* Encoders */
    if (!video_width || !video_height) {
        video_width = 320;
        video_height = 240;
    }

    if ( 0 == init_video_encoder(_retu, video_width, video_height, video_bitrate) )
        printf("Video encoder initialized!\n");

    if ( 0 == init_audio_encoder(_retu, audio_channels) )
        printf("Audio encoder initialized!\n");


    /* Decoders */
    if ( 0 == init_video_decoder(_retu) )
        printf("Video decoder initialized!\n");

    if ( 0 == init_audio_decoder(_retu, audio_channels) )
        printf("Audio decoder initialized!\n");


    return _retu;
}

void codec_terminate_session ( CodecState *cs )
{
    if ( cs->audio_encoder ) {
        opus_encoder_destroy(cs->audio_encoder);
        printf("Terminated encoder!\n");
    }

    if ( cs->audio_decoder ) {
        opus_decoder_destroy(cs->audio_decoder);
        printf("Terminated decoder!\n");
    }

    /* TODO: Terminate video */
    vpx_codec_destroy(&cs->v_decoder);
    vpx_codec_destroy(&cs->v_encoder);
}
