/**  codec.c
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
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>
#include <assert.h>
#include <time.h>

#include "msi.h"
#include "rtp.h"
#include "codec.h"

#define DEFAULT_JBUF 6

/* Good quality encode. */
#define MAX_ENCODE_TIME_US VPX_DL_GOOD_QUALITY
#define MAX_DECODE_TIME_US 0

#define MAX_VIDEOFRAME_SIZE 0x40000 /* 256KiB */
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

static bool buffer_full(const PayloadBuffer *b)
{
    return (b->end + 1) % b->size == b->start;
}

static bool buffer_empty(const PayloadBuffer *b)
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
typedef struct JitterBuffer_s {
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

static int convert_bw_to_sampling_rate(int bw)
{
    switch(bw)
    {
    case OPUS_BANDWIDTH_NARROWBAND: return 8000;
    case OPUS_BANDWIDTH_MEDIUMBAND: return 12000;
    case OPUS_BANDWIDTH_WIDEBAND: return 16000;
    case OPUS_BANDWIDTH_SUPERWIDEBAND: return 24000;
    case OPUS_BANDWIDTH_FULLBAND: return 48000;
    default: return -1;
    }
}



/* PUBLIC */

void cs_do(CSSession *cs)
{
    /* Codec session should always be protected by call mutex so no need to check for cs validity
     */
    
    if (!cs) 
        return;
    
    Payload *p;
    int rc;
    
    int success = 0;
    
    pthread_mutex_lock(cs->queue_mutex);
    
    if (cs->audio_decoder) { /* If receiving enabled */
        RTPMessage *msg;
        
        uint16_t fsize = 5760; /* Max frame size for 48 kHz */
        int16_t tmp[fsize * 2];
        
        while ((msg = jbuf_read(cs->j_buf, &success)) || success == 2) {
            pthread_mutex_unlock(cs->queue_mutex);
            
            if (success == 2) {
                rc = opus_decode(cs->audio_decoder, 0, 0, tmp, fsize, 1);
            } else {
                /* Get values from packet and decode.
                * It also checks for validity of an opus packet
                */
                rc = convert_bw_to_sampling_rate(opus_packet_get_bandwidth(msg->data));
                if (rc != -1) {
                    cs->last_packet_sampling_rate = rc;
                    cs->last_pack_channels = opus_packet_get_nb_channels(msg->data);
                
                    cs->last_packet_frame_duration = 
                        ( opus_packet_get_samples_per_frame(msg->data, cs->last_packet_sampling_rate) * 1000 )
                        / cs->last_packet_sampling_rate;
                        
                } else {
                    LOGGER_WARNING("Failed to load packet values!");
                    rtp_free_msg(NULL, msg);
                    continue;
                }
                
                rc = opus_decode(cs->audio_decoder, msg->data, msg->length, tmp, fsize, 0);
                rtp_free_msg(NULL, msg);
            }
            
            if (rc < 0) {
                LOGGER_WARNING("Decoding error: %s", opus_strerror(rc));
            } else if (cs->acb.first) {
                /* Play */
                cs->acb.first(cs->agent, cs->friend_id, tmp, rc, 
                            cs->last_pack_channels, cs->last_packet_sampling_rate, cs->acb.second);
            }
            
            pthread_mutex_lock(cs->queue_mutex);
        }
    }
    
    if (cs->vbuf_raw && !buffer_empty(cs->vbuf_raw)) {
        /* Decode video */
        buffer_read(cs->vbuf_raw, &p);
        
        /* Leave space for (possibly) other thread to queue more data after we read it here */
        pthread_mutex_unlock(cs->queue_mutex);
        
        rc = vpx_codec_decode(cs->v_decoder, p->data, p->size, NULL, MAX_DECODE_TIME_US);
        free(p);
        
        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR("Error decoding video: %s", vpx_codec_err_to_string(rc));
        } else {
            vpx_codec_iter_t iter = NULL;
            vpx_image_t *dest = vpx_codec_get_frame(cs->v_decoder, &iter);
            
            /* Play decoded images */
            for (; dest; dest = vpx_codec_get_frame(cs->v_decoder, &iter)) {
                if (cs->vcb.first) 
                    cs->vcb.first(cs->agent, cs->friend_id, dest->d_w, dest->d_h, 
                                  (const uint8_t**)dest->planes, dest->stride, cs->vcb.second);
                
                vpx_img_free(dest);
            }
        }
        
        return;
    }
    
    pthread_mutex_unlock(cs->queue_mutex);
}

CSSession *cs_new(uint32_t peer_video_frame_piece_size)
{
    CSSession *cs = calloc(sizeof(CSSession), 1);
    
    if (!cs) {
        LOGGER_WARNING("Allocation failed! Application might misbehave!");
        return NULL;
    }
    
    cs->peer_video_frame_piece_size = peer_video_frame_piece_size;
    
    return cs;
    
    FAILURE:
    LOGGER_WARNING("Error initializing codec session! Application might misbehave!");
    
    cs_disable_audio_sending(cs);
    cs_disable_audio_receiving(cs);
    cs_disable_video_sending(cs);
    cs_disable_video_receiving(cs);
    
    free(cs);
    
    return NULL;
}

void cs_kill(CSSession *cs)
{
    if (!cs) 
        return;
    
    /* NOTE: queue_message() will not be called since 
     * the callback is unregistered before cs_kill is called.
     */
    
    cs_disable_audio_sending(cs);
    cs_disable_audio_receiving(cs);
    cs_disable_video_sending(cs);
    cs_disable_video_receiving(cs);
    
    LOGGER_DEBUG("Terminated codec state: %p", cs);
    free(cs);
}



void cs_init_video_splitter_cycle(CSSession* cs)
{
    cs->split_video_frame[0] = cs->frameid_out++;
    cs->split_video_frame[1] = 0;
}

int cs_update_video_splitter_cycle(CSSession *cs, const uint8_t *payload, uint16_t length)
{
    cs->processing_video_frame = payload;
    cs->processing_video_frame_size = length;
    
    return ((length - 1) / VIDEOFRAME_PIECE_SIZE) + 1;
}

const uint8_t *cs_iterate_split_video_frame(CSSession *cs, uint16_t *size)
{
    if (!cs || !size) return NULL;

    if (cs->processing_video_frame_size > VIDEOFRAME_PIECE_SIZE) {
        memcpy(cs->split_video_frame + VIDEOFRAME_HEADER_SIZE,
               cs->processing_video_frame,
               VIDEOFRAME_PIECE_SIZE);

        cs->processing_video_frame += VIDEOFRAME_PIECE_SIZE;
        cs->processing_video_frame_size -= VIDEOFRAME_PIECE_SIZE;

        *size = VIDEOFRAME_PIECE_SIZE + VIDEOFRAME_HEADER_SIZE;
    } else {
        memcpy(cs->split_video_frame + VIDEOFRAME_HEADER_SIZE,
               cs->processing_video_frame,
               cs->processing_video_frame_size);

        *size = cs->processing_video_frame_size + VIDEOFRAME_HEADER_SIZE;
    }

    cs->split_video_frame[1]++;

    return cs->split_video_frame;
}



int cs_set_sending_video_resolution(CSSession *cs, uint16_t width, uint16_t height)
{
    if (!cs->v_encoding)
        return -1;
    
    /* TODO FIXME reference is safe? */
    vpx_codec_enc_cfg_t cfg = *cs->v_encoder[0].config.enc;
    
    if (cfg.g_w == width && cfg.g_h == height)
        return 0;
/*
    if (width * height > cs->max_width * cs->max_height) {
        vpx_codec_ctx_t v_encoder = cs->v_encoder;

        if (init_video_encoder(cs, width, height, cs->video_bitrate) == -1) {
            cs->v_encoder = v_encoder;
            return cs_ErrorSettingVideoResolution;
        }

        vpx_codec_destroy(&v_encoder);
        return 0;
    }*/

    LOGGER_DEBUG("New video resolution: %u %u", width, height);
    cfg.g_w = width;
    cfg.g_h = height;
    int rc = vpx_codec_enc_config_set(cs->v_encoder, &cfg);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return cs_ErrorSettingVideoResolution;
    }

    return 0;
}

int cs_set_sending_video_bitrate(CSSession *cs, uint32_t bitrate)
{
    if (!cs->v_encoding)
        return -1;
    
    /* TODO FIXME reference is safe? */
    vpx_codec_enc_cfg_t cfg = *cs->v_encoder[0].config.enc;
    if (cfg.rc_target_bitrate == bitrate)
        return 0;

    LOGGER_DEBUG("New video bitrate: %u", bitrate);
    cfg.rc_target_bitrate = bitrate;
    
    int rc = vpx_codec_enc_config_set(cs->v_encoder, &cfg);
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return cs_ErrorSettingVideoBitrate;
    }

    return 0;
}

int cs_enable_video_sending(CSSession* cs, uint32_t bitrate)
{
    if (cs->v_encoding)
        return 0;
    
    vpx_codec_enc_cfg_t  cfg;
    int rc = vpx_codec_enc_config_default(VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0);
    
    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to get config: %s", vpx_codec_err_to_string(rc));
        return -1;
    }
    
    rc = vpx_codec_enc_init_ver(cs->v_encoder, VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0, 
                                VPX_ENCODER_ABI_VERSION);
    
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
        return -1;
    }
    
    /* So that we can use cs_disable_video_sending to clean up */
    cs->v_encoding = true;
    
    if ( !(cs->split_video_frame = calloc(VIDEOFRAME_PIECE_SIZE + VIDEOFRAME_HEADER_SIZE, 1)) )
        goto FAILURE;
    
    cfg.rc_target_bitrate = bitrate;
    cfg.g_w = 800;
    cfg.g_h = 600;
    cfg.g_pass = VPX_RC_ONE_PASS;
    cfg.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT | VPX_ERROR_RESILIENT_PARTITIONS;
    cfg.g_lag_in_frames = 0;
    cfg.kf_min_dist = 0;
    cfg.kf_max_dist = 48;
    cfg.kf_mode = VPX_KF_AUTO;
    
    
    rc = vpx_codec_control(cs->v_encoder, VP8E_SET_CPUUSED, 8);
    
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        goto FAILURE;
    }
    
    return 0;
    
FAILURE:
    cs_disable_video_sending(cs);
    return -1;
}

int cs_enable_video_receiving(CSSession* cs)
{
    if (cs->v_decoding)
        return 0;
        
    if (create_recursive_mutex(cs->queue_mutex) != 0) {
        LOGGER_WARNING("Failed to create recursive mutex!");
        return -1;
    }
    
    int rc = vpx_codec_dec_init_ver(cs->v_decoder, VIDEO_CODEC_DECODER_INTERFACE, 
                                    NULL, 0, VPX_DECODER_ABI_VERSION);
    
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Init video_decoder failed: %s", vpx_codec_err_to_string(rc));
        
        pthread_mutex_destroy(cs->queue_mutex);
        return -1;
    }
    
    /* So that we can use cs_disable_video_sending to clean up */
    cs->v_decoding = true;
    
    if ( !(cs->frame_buf = calloc(MAX_VIDEOFRAME_SIZE, 1)) ) 
        goto FAILURE;
    
    if ( !(cs->vbuf_raw = buffer_new(VIDEO_DECODE_BUFFER_SIZE)) ) 
        goto FAILURE;
    
    return 0;
    
FAILURE:
    cs_disable_video_receiving(cs);
    return -1;
}

void cs_disable_video_sending(CSSession* cs)
{
    if (cs->v_encoding) {
        cs->v_encoding = false;
        
        free(cs->split_video_frame);
        cs->split_video_frame = NULL;
        
        vpx_codec_destroy(cs->v_encoder);
    }
}

void cs_disable_video_receiving(CSSession* cs)
{
    if (cs->v_decoding) {
        cs->v_decoding = false;
        
        buffer_free(cs->vbuf_raw);
        cs->vbuf_raw = NULL;
        free(cs->frame_buf);
        cs->frame_buf = NULL;
        
        vpx_codec_destroy(cs->v_decoder);
        pthread_mutex_destroy(cs->queue_mutex);
    }
}



int cs_set_sending_audio_bitrate(CSSession *cs, int32_t rate)
{
    if (cs->audio_encoder == NULL)
        return -1;
    
    int rc = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_BITRATE(rate));
    
    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(rc));
        return -1;
    }
    
    return 0;
}

int cs_set_sending_audio_sampling_rate(CSSession* cs, int32_t rate)
{
    /* TODO Find a better way? */
    if (cs->audio_encoder == NULL)
        return -1;
    
    int rc = OPUS_OK;
    int bitrate = 0;
    int channels = cs->encoder_channels;
    
    rc = opus_encoder_ctl(cs->audio_encoder, OPUS_GET_BITRATE(&bitrate));
    
    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while getting encoder ctl: %s", opus_strerror(rc));
        return -1;
    }
    
    cs_disable_audio_sending(cs);
    return cs_enable_audio_sending(cs, bitrate, channels);
}

int cs_set_sending_audio_channels(CSSession* cs, int32_t count)
{
    /* TODO Find a better way? */
    if (cs->audio_encoder == NULL)
        return -1;
    
    if (cs->encoder_channels == count)
        return 0;
    
    int rc = OPUS_OK;
    int bitrate = 0;
    
    rc = opus_encoder_ctl(cs->audio_encoder, OPUS_GET_BITRATE(&bitrate));
    
    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while getting encoder ctl: %s", opus_strerror(rc));
        return -1;
    }
    
    cs_disable_audio_sending(cs);
    return cs_enable_audio_sending(cs, bitrate, count);
}

void cs_disable_audio_sending(CSSession* cs)
{
    if ( cs->audio_encoder ) {
        opus_encoder_destroy(cs->audio_encoder);
        cs->audio_encoder = NULL;
        cs->encoder_channels = 0;
    }
}

void cs_disable_audio_receiving(CSSession* cs)
{
    if ( cs->audio_decoder ) {
        opus_decoder_destroy(cs->audio_decoder);
        cs->audio_decoder = NULL;
        jbuf_free(cs->j_buf);
        cs->j_buf = NULL;
        
        /* It's used for measuring iteration interval so this has to be some value.
         * To avoid unecessary checking we set this to 500
         */
        cs->last_packet_frame_duration = 500;
    }
}

int cs_enable_audio_sending(CSSession* cs, uint32_t bitrate, int channels)
{
    if (cs->audio_encoder)
        return 0;
    
    int rc = OPUS_OK;
    cs->audio_encoder = opus_encoder_create(48000, channels, OPUS_APPLICATION_AUDIO, &rc);
    
    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while starting audio encoder: %s", opus_strerror(rc));
        return -1;
    }
    
    rc = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_BITRATE(bitrate));
    
    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(rc));
        goto FAILURE;
    }
    
    rc = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_COMPLEXITY(10));
    
    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(rc));
        goto FAILURE;
    }
    
    cs->encoder_channels = channels;
    return 0;
    
FAILURE:
    cs_disable_audio_sending(cs);
    return -1;
}

int cs_enable_audio_receiving(CSSession* cs)
{
    if (cs->audio_decoder)
        return 0;
        
    int rc;
    cs->audio_decoder = opus_decoder_create(48000, 2, &rc );
    
    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while starting audio decoder: %s", opus_strerror(rc));
        return -1;
    }
    
    
    if ( !(cs->j_buf = jbuf_new(DEFAULT_JBUF)) ) {
        LOGGER_WARNING("Jitter buffer creaton failed!");
        opus_decoder_destroy(cs->audio_decoder);
        cs->audio_decoder = NULL;
        return -1;
    }
    
    /* It's used for measuring iteration interval so this has to be some value.
     * To avoid unecessary checking we set this to 500
     */
    cs->last_packet_frame_duration = 500;
    return 0;
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
    if (session->payload_type == rtp_TypeAudio % 128) {
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

        uint32_t length_before_piece = ((piece_number - 1) * cs->peer_video_frame_piece_size);
        uint32_t framebuf_new_length = length_before_piece + (packet_size - VIDEOFRAME_HEADER_SIZE);

        if (framebuf_new_length > MAX_VIDEOFRAME_SIZE) {
            goto end;
        }

        /* Otherwise it's part of the frame so just process */
        /* LOGGER_DEBUG("Video Packet: %u %u", packet[0], packet[1]); */

        memcpy(cs->frame_buf + length_before_piece,
               packet + VIDEOFRAME_HEADER_SIZE,
               packet_size - VIDEOFRAME_HEADER_SIZE);

        if (framebuf_new_length > cs->frame_size)
            cs->frame_size = framebuf_new_length;

end:
        rtp_free_msg(NULL, msg);
    }
}
