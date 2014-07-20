/**  codec.c
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

#include "../toxcore/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

#include "rtp.h"
#include "codec.h"

const uint16_t min_jbuf_size = 4;
const uint16_t min_readiness_idx = 2; /* when is buffer ready to dqq */

int empty_queue(JitterBuffer *q)
{
    while (q->size > 0) {
        rtp_free_msg(NULL, q->queue[q->front]);
        q->front++;

        if (q->front == q->capacity)
            q->front = 0;

        q->size--;
    }

    q->id_set = 0;
    q->queue_ready = 0;
    return 0;
}

JitterBuffer *create_queue(int capacity)
{
    JitterBuffer *q;

    if ( !(q = calloc(sizeof(JitterBuffer), 1)) ) return NULL;

    if (!(q->queue = calloc(sizeof(RTPMessage *), capacity))) {
        free(q);
        return NULL;
    }

    q->size = 0;
    q->capacity = capacity >= min_jbuf_size ? capacity : min_jbuf_size;
    q->front = 0;
    q->rear = -1;
    q->queue_ready = 0;
    q->current_id = 0;
    q->current_ts = 0;
    q->id_set = 0;
    return q;
}

void terminate_queue(JitterBuffer *q)
{
    if (!q) return;

    empty_queue(q);
    free(q->queue);

    LOGGER_DEBUG("Terminated jitter buffer: %p", q);
    free(q);
}

#define sequnum_older(sn_a, sn_b, ts_a, ts_b) (sn_a > sn_b || ts_a > ts_b)

/* success is 0 when there is nothing to dequeue, 1 when there's a good packet, 2 when there's a lost packet */
RTPMessage *dequeue(JitterBuffer *q, int *success)
{
    if (q->size == 0 || q->queue_ready == 0) { /* Empty queue */
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
            if (sequnum_older(next_id, q->current_id, next_ts, q->current_ts)) {
                LOGGER_DEBUG("nextid: %d current: %d\n", next_id, q->current_id);
                q->current_id = (q->current_id + 1) % MAX_SEQU_NUM;
                *success = 2; /* tell the decoder the packet is lost */
                return NULL;
            } else {
                LOGGER_DEBUG("Packet too old");
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


void queue(JitterBuffer *q, RTPMessage *pk)
{
    if (q->size == q->capacity) { /* Full, empty queue */
        LOGGER_DEBUG("Queue full s(%d) c(%d), emptying...", q->size, q->capacity);
        empty_queue(q);
    }

    if (q->size >= min_readiness_idx) q->queue_ready = 1;

    ++q->size;
    ++q->rear;

    if (q->rear == q->capacity) q->rear = 0;

    q->queue[q->rear] = pk;

    int a;
    int j;
    a = q->rear;

    for (j = 0; j < q->size - 1; ++j) {
        int b = a - 1;

        if (b < 0)
            b += q->capacity;

        if (sequnum_older(q->queue[b]->header->sequnum, q->queue[a]->header->sequnum,
                          q->queue[b]->header->timestamp, q->queue[a]->header->timestamp)) {
            RTPMessage *temp;
            temp = q->queue[a];
            q->queue[a] = q->queue[b];
            q->queue[b] = temp;
            LOGGER_DEBUG("Had to swap");
        } else {
            break;
        }

        a -= 1;

        if (a < 0) a += q->capacity;
    }
}


int init_video_decoder(CodecState *cs)
{
    int rc = vpx_codec_dec_init_ver(&cs->v_decoder, VIDEO_CODEC_DECODER_INTERFACE, NULL, 0, VPX_DECODER_ABI_VERSION);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Init video_decoder failed: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    return 0;
}

int init_audio_decoder(CodecState *cs, uint32_t audio_channels)
{
    int rc;
    cs->audio_decoder = opus_decoder_create(cs->audio_sample_rate, audio_channels, &rc );

    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while starting audio decoder: %s", opus_strerror(rc));
        return -1;
    }

    return 0;
}

int reconfigure_video_encoder_resolution(CodecState *cs, uint16_t width, uint16_t height)
{
    vpx_codec_enc_cfg_t cfg = *cs->v_encoder.config.enc;

    if (cfg.g_w == width && cfg.g_h == height)
        return 0;

    if (width * height > cs->max_width * cs->max_height)
        return -1;

    LOGGER_DEBUG("New video resolution: %u %u", width, height);
    cfg.g_w = width;
    cfg.g_h = height;
    int rc = vpx_codec_enc_config_set(&cs->v_encoder, &cfg);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    return 0;
}

int reconfigure_video_encoder_bitrate(CodecState *cs, uint32_t video_bitrate)
{
    vpx_codec_enc_cfg_t cfg = *cs->v_encoder.config.enc;

    if (cfg.rc_target_bitrate == video_bitrate)
        return 0;

    LOGGER_DEBUG("New video bitrate: %u", video_bitrate);
    cfg.rc_target_bitrate = video_bitrate;
    int rc = vpx_codec_enc_config_set(&cs->v_encoder, &cfg);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    return 0;
}

int init_video_encoder(CodecState *cs, uint16_t max_width, uint16_t max_height, uint32_t video_bitrate)
{
    vpx_codec_enc_cfg_t  cfg;
    int rc = vpx_codec_enc_config_default(VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to get config: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    cfg.rc_target_bitrate = video_bitrate;
    cfg.g_w = max_width;
    cfg.g_h = max_height;
    cfg.g_pass = VPX_RC_ONE_PASS;
    cfg.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT | VPX_ERROR_RESILIENT_PARTITIONS;
    cfg.g_lag_in_frames = 0;
    cfg.kf_min_dist = 0;
    cfg.kf_max_dist = 300;
    cfg.kf_mode = VPX_KF_AUTO;

    cs->max_width = max_width;
    cs->max_height = max_height;
    cs->bitrate = video_bitrate;

    rc = vpx_codec_enc_init_ver(&cs->v_encoder, VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0, VPX_ENCODER_ABI_VERSION);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    rc = vpx_codec_control(&cs->v_encoder, VP8E_SET_CPUUSED, 7);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    return 0;
}

int init_audio_encoder(CodecState *cs, uint32_t audio_channels)
{
    int rc = OPUS_OK;
    cs->audio_encoder = opus_encoder_create(cs->audio_sample_rate, audio_channels, OPUS_APPLICATION_AUDIO, &rc);

    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while starting audio encoder: %s", opus_strerror(rc));
        return -1;
    }

    rc = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_BITRATE(cs->audio_bitrate));

    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(rc));
        return -1;
    }

    rc = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_COMPLEXITY(10));

    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(rc));
        return -1;
    }


    return 0;
}


CodecState *codec_init_session ( uint32_t audio_bitrate,
                                 uint16_t audio_frame_duration,
                                 uint32_t audio_sample_rate,
                                 uint32_t audio_channels,
                                 uint32_t audio_VAD_tolerance_ms,
                                 uint16_t max_video_width,
                                 uint16_t max_video_height,
                                 uint32_t video_bitrate )
{
    CodecState *retu = calloc(sizeof(CodecState), 1);

    if (!retu) return NULL;

    retu->audio_bitrate = audio_bitrate;
    retu->audio_sample_rate = audio_sample_rate;

    /* Encoders */
    if (!max_video_width || !max_video_height) { /* Disable video */
        /*video_width = 320;
        video_height = 240; */
    } else {
        retu->capabilities |= ( 0 == init_video_encoder(retu, max_video_width, max_video_height,
                                video_bitrate) ) ? v_encoding : 0;
        retu->capabilities |= ( 0 == init_video_decoder(retu) ) ? v_decoding : 0;
    }

    retu->capabilities |= ( 0 == init_audio_encoder(retu, audio_channels) ) ? a_encoding : 0;
    retu->capabilities |= ( 0 == init_audio_decoder(retu, audio_channels) ) ? a_decoding : 0;

    if ( retu->capabilities == 0  ) { /* everything failed */
        free (retu);
        return NULL;
    }


    retu->EVAD_tolerance = audio_VAD_tolerance_ms > audio_frame_duration ?
                           audio_VAD_tolerance_ms / audio_frame_duration : audio_frame_duration;

    return retu;
}

void codec_terminate_session ( CodecState *cs )
{
    if (!cs) return;

    if ( cs->audio_encoder )
        opus_encoder_destroy(cs->audio_encoder);

    if ( cs->audio_decoder )
        opus_decoder_destroy(cs->audio_decoder);

    if ( cs->capabilities & v_decoding )
        vpx_codec_destroy(&cs->v_decoder);

    if ( cs->capabilities & v_encoding )
        vpx_codec_destroy(&cs->v_encoder);

    LOGGER_DEBUG("Terminated codec state: %p", cs);
    free(cs);
}

static inline float calculate_sum_sq (int16_t *n, uint16_t k)
{
    float result = 0;
    uint16_t i = 0;

    for ( ; i < k; i ++) result += (float) (n[i] * n[i]);

    return result;
}

int energy_VAD(CodecState *cs, int16_t *PCM, uint16_t frame_size, float energy)
{
    float frame_energy = sqrt(calculate_sum_sq(PCM, frame_size)) / frame_size;

    if ( frame_energy > energy) {
        cs->EVAD_tolerance_cr = cs->EVAD_tolerance; /* Reset counter */
        return 1;
    }

    if ( cs->EVAD_tolerance_cr ) {
        cs->EVAD_tolerance_cr --;
        return 1;
    }

    return 0;
}
