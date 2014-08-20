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

JitterBuffer *create_queue(unsigned int capacity)
{
    unsigned int size = 1;

    while (size <= capacity) {
        size *= 2;
    }

    JitterBuffer *q;

    if ( !(q = calloc(sizeof(JitterBuffer), 1)) ) return NULL;

    if (!(q->queue = calloc(sizeof(RTPMessage *), size))) {
        free(q);
        return NULL;
    }

    q->size = size;
    q->capacity = capacity;
    return q;
}

static void clear_queue(JitterBuffer *q)
{
    for (; q->bottom != q->top; ++q->bottom) {
        if (q->queue[q->bottom % q->size]) {
            rtp_free_msg(NULL, q->queue[q->bottom % q->size]);
            q->queue[q->bottom % q->size] = NULL;
        }
    }
}

void terminate_queue(JitterBuffer *q)
{
    if (!q) return;

    clear_queue(q);
    free(q->queue);
    free(q);
}

void queue(JitterBuffer *q, RTPMessage *pk)
{
    uint16_t sequnum = pk->header->sequnum;

    unsigned int num = sequnum % q->size;

    if ((uint32_t)(sequnum - q->bottom) > q->size) {
        clear_queue(q);
        q->bottom = sequnum;
        q->queue[num] = pk;
        q->top = sequnum + 1;
        return;
    }

    if (q->queue[num])
        return;

    q->queue[num] = pk;

    if ((sequnum - q->bottom) >= (q->top - q->bottom))
        q->top = sequnum + 1;
}

/* success is 0 when there is nothing to dequeue, 1 when there's a good packet, 2 when there's a lost packet */
RTPMessage *dequeue(JitterBuffer *q, int *success)
{
    if (q->top == q->bottom) {
        *success = 0;
        return NULL;
    }

    unsigned int num = q->bottom % q->size;

    if (q->queue[num]) {
        RTPMessage *ret = q->queue[num];
        q->queue[num] = NULL;
        ++q->bottom;
        *success = 1;
        return ret;
    }

    if ((uint32_t)(q->top - q->bottom) > q->capacity) {
        ++q->bottom;
        *success = 2;
        return NULL;
    }

    *success = 0;
    return NULL;
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

    cs->audio_decoder_channels = audio_channels;
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

    cs->audio_encoder_channels = audio_channels;
    return 0;
}


CodecState *codec_init_session ( uint32_t audio_bitrate,
                                 uint16_t audio_frame_duration,
                                 uint32_t audio_sample_rate,
                                 uint32_t encoder_audio_channels,
                                 uint32_t decoder_audio_channels,
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

    retu->capabilities |= ( 0 == init_audio_encoder(retu, encoder_audio_channels) ) ? a_encoding : 0;
    retu->capabilities |= ( 0 == init_audio_decoder(retu, decoder_audio_channels) ) ? a_decoding : 0;

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

static float calculate_sum_sq (int16_t *n, uint16_t k)
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
