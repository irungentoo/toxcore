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
#include "../toxcore/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <time.h>

#include "msi.h"
#include "rtp.h"
#include "codec.h"

/* Good quality encode. */
#define MAX_DECODE_TIME_US 0

// TODO this has to be exchanged in msi
#define MAX_VIDEOFRAME_SIZE 0x40000 /* 256KiB */
#define VIDEOFRAME_PIECE_SIZE 0x500 /* 1.25 KiB*/
#define VIDEOFRAME_HEADER_SIZE 0x2

/* FIXME: Might not be enough */
#define VIDEO_DECODE_BUFFER_SIZE 20

#define ARRAY(TYPE__) struct { uint16_t size; TYPE__ data[]; }

typedef ARRAY(uint8_t) Payload;

typedef struct {
    uint16_t size; /* Max size */
    uint16_t start;
    uint16_t end;
    Payload **packets;
} PayloadBuffer;

static _Bool buffer_full(const PayloadBuffer *b)
{
    return (b->end + 1) % b->size == b->start;
}

static _Bool buffer_empty(const PayloadBuffer *b)
{
    return b->end == b->start;
}

static void buffer_write(PayloadBuffer *b, Payload *p)
{
    b->packets[b->end] = p;
    b->end = (b->end + 1) % b->size;

    if (b->end == b->start) b->start = (b->start + 1) % b->size; /* full, overwrite */
}

static void buffer_read(PayloadBuffer *b, Payload **p)
{
    *p = b->packets[b->start];
    b->start = (b->start + 1) % b->size;
}

static void buffer_clear(PayloadBuffer *b)
{
    while (!buffer_empty(b)) {
        Payload *p;
        buffer_read(b, &p);
        free(p);
    }
}

static PayloadBuffer *buffer_new(int size)
{
    PayloadBuffer *buf = calloc(sizeof(PayloadBuffer), 1);

    if (!buf) return NULL;

    buf->size = size + 1; /* include empty elem */

    if (!(buf->packets = calloc(buf->size, sizeof(Payload *)))) {
        free(buf);
        return NULL;
    }

    return buf;
}

static void buffer_free(PayloadBuffer *b)
{
    if (b) {
        buffer_clear(b);
        free(b->packets);
        free(b);
    }
}

/* JITTER BUFFER WORK */
typedef struct _JitterBuffer {
    RTPMessage **queue;
    uint32_t     size;
    uint32_t     capacity;
    uint16_t     bottom;
    uint16_t     top;
} JitterBuffer;

static JitterBuffer *jbuf_new(uint32_t capacity)
{
    unsigned int size = 1;

    while (size <= (capacity * 4)) {
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

static void jbuf_clear(JitterBuffer *q)
{
    for (; q->bottom != q->top; ++q->bottom) {
        if (q->queue[q->bottom % q->size]) {
            rtp_free_msg(NULL, q->queue[q->bottom % q->size]);
            q->queue[q->bottom % q->size] = NULL;
        }
    }
}

static void jbuf_free(JitterBuffer *q)
{
    if (!q) return;

    jbuf_clear(q);
    free(q->queue);
    free(q);
}

static int jbuf_write(JitterBuffer *q, RTPMessage *m)
{
    uint16_t sequnum = m->header->sequnum;

    unsigned int num = sequnum % q->size;

    if ((uint32_t)(sequnum - q->bottom) > q->size) {
        jbuf_clear(q);
        q->bottom = sequnum - q->capacity;
        q->queue[num] = m;
        q->top = sequnum + 1;
        return 0;
    }

    if (q->queue[num])
        return -1;

    q->queue[num] = m;

    if ((sequnum - q->bottom) >= (q->top - q->bottom))
        q->top = sequnum + 1;

    return 0;
}

/* Success is 0 when there is nothing to dequeue,
 * 1 when there's a good packet,
 * 2 when there's a lost packet */
static RTPMessage *jbuf_read(JitterBuffer *q, int32_t *success)
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

static int init_video_decoder(CSSession *cs)
{
    int rc = vpx_codec_dec_init_ver(&cs->v_decoder, VIDEO_CODEC_DECODER_INTERFACE, NULL, 0, VPX_DECODER_ABI_VERSION);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Init video_decoder failed: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    return 0;
}

static int init_audio_decoder(CSSession *cs)
{
    int rc;
    cs->audio_decoder = opus_decoder_create(cs->audio_decoder_sample_rate, cs->audio_decoder_channels, &rc );

    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while starting audio decoder: %s", opus_strerror(rc));
        return -1;
    }

    return 0;
}

static int init_video_encoder(CSSession *cs, uint16_t max_width, uint16_t max_height, uint32_t video_bitrate)
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
    cfg.kf_max_dist = 48;
    cfg.kf_mode = VPX_KF_AUTO;

    rc = vpx_codec_enc_init_ver(&cs->v_encoder, VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0, VPX_ENCODER_ABI_VERSION);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    rc = vpx_codec_control(&cs->v_encoder, VP8E_SET_CPUUSED, 8);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    cs->max_width = max_width;
    cs->max_height = max_height;
    cs->video_bitrate = video_bitrate;

    return 0;
}

static int init_audio_encoder(CSSession *cs)
{
    int rc = OPUS_OK;
    cs->audio_encoder = opus_encoder_create(cs->audio_encoder_sample_rate,
                                            cs->audio_encoder_channels, OPUS_APPLICATION_AUDIO, &rc);

    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while starting audio encoder: %s", opus_strerror(rc));
        return -1;
    }

    rc = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_BITRATE(cs->audio_encoder_bitrate));

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

/* PUBLIC */
int cs_split_video_payload(CSSession *cs, const uint8_t *payload, uint16_t length)
{
    if (!cs || !length || length > cs->max_video_frame_size) {
        LOGGER_ERROR("Invalid  CodecState or video frame size: %u", length);
        return cs_ErrorSplittingVideoPayload;
    }

    cs->split_video_frame[0] = cs->frameid_out++;
    cs->split_video_frame[1] = 0;
    cs->processing_video_frame = payload;
    cs->processing_video_frame_size = length;

    return ((length - 1) / cs->video_frame_piece_size) + 1;
}

const uint8_t *cs_get_split_video_frame(CSSession *cs, uint16_t *size)
{
    if (!cs || !size) return NULL;

    if (cs->processing_video_frame_size > cs->video_frame_piece_size) {
        memcpy(cs->split_video_frame + VIDEOFRAME_HEADER_SIZE,
               cs->processing_video_frame,
               cs->video_frame_piece_size);

        cs->processing_video_frame += cs->video_frame_piece_size;
        cs->processing_video_frame_size -= cs->video_frame_piece_size;

        *size = cs->video_frame_piece_size + VIDEOFRAME_HEADER_SIZE;
    } else {
        memcpy(cs->split_video_frame + VIDEOFRAME_HEADER_SIZE,
               cs->processing_video_frame,
               cs->processing_video_frame_size);

        *size = cs->processing_video_frame_size + VIDEOFRAME_HEADER_SIZE;
    }

    cs->split_video_frame[1]++;

    return cs->split_video_frame;
}

void cs_do(CSSession *cs)
{
    /* Codec session should always be protected by call mutex so no need to check for cs validity
     */

    if (!cs) return;

    Payload *p;
    int rc;

    int success = 0;

    pthread_mutex_lock(cs->queue_mutex);
    RTPMessage *msg;

    while ((msg = jbuf_read(cs->j_buf, &success)) || success == 2) {
        pthread_mutex_unlock(cs->queue_mutex);

        uint16_t fsize = ((cs->audio_decoder_sample_rate * cs->audio_decoder_frame_duration) / 1000);
        int16_t tmp[fsize * cs->audio_decoder_channels];

        if (success == 2) {
            rc = opus_decode(cs->audio_decoder, 0, 0, tmp, fsize, 1);
        } else {
            rc = opus_decode(cs->audio_decoder, msg->data, msg->length, tmp, fsize, 0);
            rtp_free_msg(NULL, msg);
        }

        if (rc < 0) {
            LOGGER_WARNING("Decoding error: %s", opus_strerror(rc));
        } else if (cs->acb.first) {
            /* Play */
            cs->acb.first(cs->agent, cs->call_idx, tmp, rc, cs->acb.second);
        }

        pthread_mutex_lock(cs->queue_mutex);
    }

    if (cs->vbuf_raw && !buffer_empty(cs->vbuf_raw)) {
        /* Decode video */
        buffer_read(cs->vbuf_raw, &p);

        /* Leave space for (possibly) other thread to queue more data after we read it here */
        pthread_mutex_unlock(cs->queue_mutex);

        rc = vpx_codec_decode(&cs->v_decoder, p->data, p->size, NULL, MAX_DECODE_TIME_US);
        free(p);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR("Error decoding video: %s", vpx_codec_err_to_string(rc));
        } else {
            vpx_codec_iter_t iter = NULL;
            vpx_image_t *dest = vpx_codec_get_frame(&cs->v_decoder, &iter);

            /* Play decoded images */
            for (; dest; dest = vpx_codec_get_frame(&cs->v_decoder, &iter)) {
                if (cs->vcb.first)
                    cs->vcb.first(cs->agent, cs->call_idx, dest, cs->vcb.second);

                vpx_img_free(dest);
            }
        }

        return;
    }

    pthread_mutex_unlock(cs->queue_mutex);
}

int cs_set_video_encoder_resolution(CSSession *cs, uint16_t width, uint16_t height)
{
    vpx_codec_enc_cfg_t cfg = *cs->v_encoder.config.enc;

    if (cfg.g_w == width && cfg.g_h == height)
        return 0;

    if (width * height > cs->max_width * cs->max_height) {
        vpx_codec_ctx_t v_encoder = cs->v_encoder;

        if (init_video_encoder(cs, width, height, cs->video_bitrate) == -1) {
            cs->v_encoder = v_encoder;
            return cs_ErrorSettingVideoResolution;
        }

        vpx_codec_destroy(&v_encoder);
        return 0;
    }

    LOGGER_DEBUG("New video resolution: %u %u", width, height);
    cfg.g_w = width;
    cfg.g_h = height;
    int rc = vpx_codec_enc_config_set(&cs->v_encoder, &cfg);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return cs_ErrorSettingVideoResolution;
    }

    return 0;
}

int cs_set_video_encoder_bitrate(CSSession *cs, uint32_t video_bitrate)
{
    vpx_codec_enc_cfg_t cfg = *cs->v_encoder.config.enc;

    if (cfg.rc_target_bitrate == video_bitrate)
        return 0;

    LOGGER_DEBUG("New video bitrate: %u", video_bitrate);
    cfg.rc_target_bitrate = video_bitrate;
    int rc = vpx_codec_enc_config_set(&cs->v_encoder, &cfg);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return cs_ErrorSettingVideoBitrate;
    }

    cs->video_bitrate = video_bitrate;
    return 0;
}

CSSession *cs_new(const ToxAvCSettings *cs_self, const ToxAvCSettings *cs_peer, uint32_t jbuf_size, int has_video)
{
    CSSession *cs = calloc(sizeof(CSSession), 1);

    if (!cs) {
        LOGGER_WARNING("Allocation failed! Application might misbehave!");
        return NULL;
    }

    if (create_recursive_mutex(cs->queue_mutex) != 0) {
        LOGGER_WARNING("Failed to create recursive mutex!");
        free(cs);
        return NULL;
    }

    if ( !(cs->j_buf = jbuf_new(jbuf_size)) ) {
        LOGGER_WARNING("Jitter buffer creaton failed!");
        goto error;
    }

    cs->audio_encoder_bitrate        = cs_self->audio_bitrate;
    cs->audio_encoder_sample_rate    = cs_self->audio_sample_rate;
    cs->audio_encoder_channels       = cs_self->audio_channels;
    cs->audio_encoder_frame_duration = cs_self->audio_frame_duration;

    cs->audio_decoder_bitrate        = cs_peer->audio_bitrate;
    cs->audio_decoder_sample_rate    = cs_peer->audio_sample_rate;
    cs->audio_decoder_channels       = cs_peer->audio_channels;
    cs->audio_decoder_frame_duration = cs_peer->audio_frame_duration;


    cs->capabilities |= ( 0 == init_audio_encoder(cs) ) ? cs_AudioEncoding : 0;
    cs->capabilities |= ( 0 == init_audio_decoder(cs) ) ? cs_AudioDecoding : 0;

    if ( !(cs->capabilities & cs_AudioEncoding) || !(cs->capabilities & cs_AudioDecoding) ) goto error;

    if ((cs->support_video = has_video)) {
        cs->max_video_frame_size = MAX_VIDEOFRAME_SIZE;
        cs->video_frame_piece_size = VIDEOFRAME_PIECE_SIZE;

        cs->capabilities |= ( 0 == init_video_encoder(cs, cs_self->max_video_width,
                              cs_self->max_video_height, cs_self->video_bitrate) ) ? cs_VideoEncoding : 0;
        cs->capabilities |= ( 0 == init_video_decoder(cs) ) ? cs_VideoDecoding : 0;

        if ( !(cs->capabilities & cs_VideoEncoding) || !(cs->capabilities & cs_VideoDecoding) ) goto error;

        if ( !(cs->frame_buf = calloc(cs->max_video_frame_size, 1)) ) goto error;

        if ( !(cs->split_video_frame = calloc(cs->video_frame_piece_size + VIDEOFRAME_HEADER_SIZE, 1)) )
            goto error;

        if ( !(cs->vbuf_raw = buffer_new(VIDEO_DECODE_BUFFER_SIZE)) ) goto error;
    }

    return cs;

error:
    LOGGER_WARNING("Error initializing codec session! Application might misbehave!");

    pthread_mutex_destroy(cs->queue_mutex);

    if ( cs->audio_encoder ) opus_encoder_destroy(cs->audio_encoder);

    if ( cs->audio_decoder ) opus_decoder_destroy(cs->audio_decoder);


    if (has_video) {
        if ( cs->capabilities & cs_VideoDecoding ) vpx_codec_destroy(&cs->v_decoder);

        if ( cs->capabilities & cs_VideoEncoding ) vpx_codec_destroy(&cs->v_encoder);

        buffer_free(cs->vbuf_raw);

        free(cs->frame_buf);
        free(cs->split_video_frame);
    }

    jbuf_free(cs->j_buf);
    free(cs);

    return NULL;
}

void cs_kill(CSSession *cs)
{
    if (!cs) return;

    /* queue_message will not be called since it's unregistered before cs_kill is called */
    pthread_mutex_destroy(cs->queue_mutex);


    if ( cs->audio_encoder )
        opus_encoder_destroy(cs->audio_encoder);

    if ( cs->audio_decoder )
        opus_decoder_destroy(cs->audio_decoder);

    if ( cs->capabilities & cs_VideoDecoding )
        vpx_codec_destroy(&cs->v_decoder);

    if ( cs->capabilities & cs_VideoEncoding )
        vpx_codec_destroy(&cs->v_encoder);

    jbuf_free(cs->j_buf);
    buffer_free(cs->vbuf_raw);
    free(cs->frame_buf);
    free(cs->split_video_frame);

    LOGGER_DEBUG("Terminated codec state: %p", cs);
    free(cs);
}




/* Called from RTP */
void queue_message(RTPSession *session, RTPMessage *msg)
{
    /* This function is unregistered during call termination befor destroing
     * Codec session so no need to check for validity of cs
     */
    CSSession *cs = session->cs;

    if (!cs) return;

    /* Audio */
    if (session->payload_type == msi_TypeAudio % 128) {
        pthread_mutex_lock(cs->queue_mutex);
        int ret = jbuf_write(cs->j_buf, msg);
        pthread_mutex_unlock(cs->queue_mutex);

        if (ret == -1) {
            rtp_free_msg(NULL, msg);
        }
    }
    /* Video */
    else {
        uint8_t *packet = msg->data;
        uint32_t packet_size = msg->length;

        if (packet_size < VIDEOFRAME_HEADER_SIZE)
            goto end;

        uint8_t diff = packet[0] - cs->frameid_in;

        if (diff != 0) {
            if (diff < 225) { /* New frame */
                /* Flush last frames' data and get ready for this frame */
                Payload *p = malloc(sizeof(Payload) + cs->frame_size);

                if (p) {
                    pthread_mutex_lock(cs->queue_mutex);

                    if (buffer_full(cs->vbuf_raw)) {
                        LOGGER_DEBUG("Dropped video frame");
                        Payload *tp;
                        buffer_read(cs->vbuf_raw, &tp);
                        free(tp);
                    } else {
                        p->size = cs->frame_size;
                        memcpy(p->data, cs->frame_buf, cs->frame_size);
                    }

                    buffer_write(cs->vbuf_raw, p);
                    pthread_mutex_unlock(cs->queue_mutex);
                } else {
                    LOGGER_WARNING("Allocation failed! Program might misbehave!");
                    goto end;
                }

                cs->last_timestamp = msg->header->timestamp;
                cs->frameid_in = packet[0];
                memset(cs->frame_buf, 0, cs->frame_size);
                cs->frame_size = 0;

            } else { /* Old frame; drop */
                LOGGER_DEBUG("Old packet: %u", packet[0]);
                goto end;
            }
        }

        uint8_t piece_number = packet[1];

        uint32_t length_before_piece = ((piece_number - 1) * cs->video_frame_piece_size);
        uint32_t framebuf_new_length = length_before_piece + (packet_size - VIDEOFRAME_HEADER_SIZE);

        if (framebuf_new_length > cs->max_video_frame_size) {
            goto end;
        }

        /* Otherwise it's part of the frame so just process */
        /* LOGGER_DEBUG("Video Packet: %u %u", packet[0], packet[1]); */

        memcpy(cs->frame_buf + length_before_piece,
               packet + VIDEOFRAME_HEADER_SIZE,
               packet_size - VIDEOFRAME_HEADER_SIZE);

        if (framebuf_new_length > cs->frame_size) {
            cs->frame_size = framebuf_new_length;
        }

end:
        rtp_free_msg(NULL, msg);
    }
}
