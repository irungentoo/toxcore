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
#include <time.h>

#include "msi.h"
#include "rtp.h"
#include "codec.h"
#include "toxav.h"

/* Assume 24 fps*/
#define MAX_ENCODE_TIME_US ((1000 / 24) * 1000)
#define MAX_DECODE_TIME_US 0

#define MAX_VIDEOFRAME_SIZE 0x40000 /* 256KiB */
#define VIDEOFRAME_PIECE_SIZE 0x500 /* 1.25 KiB*/
#define VIDEOFRAME_HEADER_SIZE 0x2

typedef struct _Payload {
    uint16_t size;
    uint8_t *data;
} Payload;

typedef struct _PayloadBuffer {
    uint16_t  size; /* Max size */
    uint16_t  start;
    uint16_t  end;
    Payload **packets;
} PayloadBuffer;

static _Bool buffer_full(const PayloadBuffer* b) 
{
    return (b->end + 1) % b->size == b->start;
}

static _Bool buffer_empty(const PayloadBuffer* b) 
{
    return b->end == b->start;
}

static void buffer_write(PayloadBuffer* b, Payload* p)
{
    b->packets[b->end] = p;
    b->end = (b->end + 1) % b->size;
    if (b->end == b->start)
        b->start = (b->start + 1) % b->size; /* full, overwrite */
}

static void buffer_read(PayloadBuffer* b, Payload** p)
{
    *p = b->packets[b->start];
    b->start = (b->start + 1) % b->size;
}

static PayloadBuffer* buffer_new(int size) 
{
    PayloadBuffer *buf = calloc(sizeof(PayloadBuffer), 1);
    if (!buf) return NULL;
    
    buf->size  = size + 1; /* include empty elem */
    if (!(buf->packets = calloc(buf->size, sizeof(Payload)))) {
        free(buf);
        return NULL;
    }
}

static void buffer_free(PayloadBuffer *buf) 
{
    if (buf) {
        while (!buffer_empty(buf)) {
            Payload* p;
            buffer_read(buf, &p);
            free(p);
        }
        free(buf->packets);
        free(buf);
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

JitterBuffer *jbuf_new(uint32_t capacity)
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

static void jbuf_clear(JitterBuffer *q)
{
    for (; q->bottom != q->top; ++q->bottom) {
        if (q->queue[q->bottom % q->size]) {
            rtp_free_msg(NULL, q->queue[q->bottom % q->size]);
            q->queue[q->bottom % q->size] = NULL;
        }
    }
}

void jbuf_free(JitterBuffer *q)
{
    if (!q) return;
    
    jbuf_clear(q);
    free(q->queue);
    free(q);
}

void jbuf_write(JitterBuffer *q, RTPMessage *m)
{
    uint16_t sequnum = m->header->sequnum;
    
    unsigned int num = sequnum % q->size;
    
    if ((uint32_t)(sequnum - q->bottom) > q->size) {
        jbuf_clear(q);
        q->bottom = sequnum;
        q->queue[num] = m;
        q->top = sequnum + 1;
        return;
    }
    
    if (q->queue[num])
        return;
    
    q->queue[num] = m;
    
    if ((sequnum - q->bottom) >= (q->top - q->bottom))
        q->top = sequnum + 1;
}

/* Success is 0 when there is nothing to dequeue, 
 * 1 when there's a good packet, 
 * 2 when there's a lost packet */
RTPMessage *jbuf_read(JitterBuffer *q, int32_t *success)
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




int split_video_payload(CodecState* cs, uint8_t* payload, uint16_t length)
{
    if (!cs || !length || length > cs->max_video_frame_size) {
        LOGGER_ERROR("Invalid  CodecState or video frame size: %u\n", length);
        return -1;
    }
    
    cs->split_video_frame[0] = cs->frameid_out++;
    cs->split_video_frame[1] = 0;
    cs->processing_video_frame = payload;
    cs->processing_video_frame_size = length;

    return ((length - 1) / cs->video_frame_piece_size) + 1;
}

const uint8_t* get_split_video_frame(CodecState* cs, uint16_t* size)
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



int recv_decoded_video(CodecState* cs, vpx_image_t** dest, uint16_t max_images, int32_t wait)
{
    if (!cs || !cs->active || !max_images) return -1;
    
    pthread_mutex_lock(cs->vbuf_mutex);
    
    if (buffer_empty(cs->vbuf)) {
        switch (wait) {
            case -1: /* Indefinite */
            {
                pthread_cond_wait(cs->vbuf_cond, cs->vbuf_mutex);
                
                if (buffer_empty(cs->vbuf)) goto error; /* Some data should be in buffer */
            } break;
            
            case 0: /* Poll */
            {
                pthread_mutex_unlock(cs->vbuf_mutex);
                return 0;
            } break;
            
            default: /* Wait for 'wait' millis */
            {
                struct timespec ts;
                if (!wait) goto error; /* if the fool passed negative */
                    
                ts.tv_sec=  (time_t)(wait/1000);
                ts.tv_nsec = (wait % 1000) * 1000000;
                
                if (pthread_cond_timedwait(cs->vbuf_cond, cs->vbuf_mutex, &ts) == ETIMEDOUT) {
                    /* No signal in specified time */
                    pthread_mutex_unlock(cs->vbuf_mutex);
                    return 0;
                }
                
                if (buffer_empty(cs->vbuf)) goto error; /* Some data should be in buffer */
            } break;
        };
    }
    
    Payload* p;
    buffer_read(cs->vbuf, &p);
    pthread_mutex_unlock(cs->vbuf_mutex);
    int rc = vpx_codec_decode(&cs->v_decoder, p->data, p->size, NULL, MAX_DECODE_TIME_US);
    free(p);
    
    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Error decoding video: %s\n", vpx_codec_err_to_string(rc));
        return -1;
    }
    
    vpx_codec_iter_t iter = NULL;
    dest[0] = vpx_codec_get_frame(&cs->v_decoder, &iter);
    
    for (rc = 1; 
         dest[rc - 1] && max_images > rc; 
         dest[rc - 1] = vpx_codec_get_frame(&cs->v_decoder, &iter))
        rc++;
    
    if (rc == max_images) { /* Don't allow this behavoiur and return error */
        for (rc = 0; rc < max_images; rc++) vpx_img_free(dest[rc]);
        LOGGER_DEBUG("Image overflow!");
        return -1;
    }
    
    /* Fresh pack of images of soulless, ugly people of size: rc lmao */
    return rc;
error:
    LOGGER_DEBUG("Error getting video data!");
    pthread_mutex_unlock(cs->vbuf_mutex);
    return -1;
}

int recv_decoded_audio(CodecState* cs, int16_t* dest, uint16_t max_size, int32_t wait)
{
    if (!cs) return -1;
    
    pthread_mutex_lock(cs->abuf_mutex);
    
    if (buffer_empty(cs->abuf)) {
        switch (wait) {
            case -1: /* Indefinite */
            {
                pthread_cond_wait(cs->abuf_cond, cs->abuf_mutex);
                
                if (buffer_empty(cs->abuf)) goto error; /* Some data should be in buffer */
            } break;
            
            case 0: /* Poll */
            {
                pthread_mutex_unlock(cs->abuf_mutex);
                return 0;
            } break;
            
            default: /* Wait for 'wait' millis */
            {
                struct timespec ts;
                if (!wait) goto error; /* if the fool passed negative */
                
                ts.tv_sec=  (time_t)(wait/1000);
                ts.tv_nsec = (wait % 1000) * 1000000;
                
                if (pthread_cond_timedwait(cs->abuf_cond, cs->abuf_mutex, &ts) == ETIMEDOUT) {
                    /* No signal in specified time */
                    pthread_mutex_unlock(cs->abuf_mutex);
                    return 0;
                }
                
                if (buffer_empty(cs->abuf)) goto error; /* Some data should be in buffer */
            } break;
        };
    }
    
    Payload* p;
    buffer_read(cs->abuf, &p);
    int dec_size = opus_decode(cs->audio_decoder, p->data, p->size, dest, max_size, (p->size == 0));
    free(p);
    
    pthread_mutex_unlock(cs->abuf_mutex);
    
    if (dec_size < 0) {
        LOGGER_WARNING("Decoding error: %s", opus_strerror(dec_size));
        return - 1;
    }
    
    return dec_size;
    
error:
    LOGGER_DEBUG("Error getting audio data!");
    pthread_mutex_unlock(cs->abuf_mutex);
    return -1;
}

void queue_message(RTPSession *session, RTPMessage *msg)
{
    CodecState *cs = session->cs;
    if (!cs) return;
    
    /* Audio */
    if (session->payload_type == type_audio % 128) {
        pthread_mutex_lock(cs->abuf_mutex);
        jbuf_write(cs->j_buf, msg);
        
        int success = 0;
        
        while ((msg = jbuf_read(cs->j_buf, &success)) || success == 2) {
            Payload* p;
            
            if (success == 2) {
                p = malloc(sizeof(Payload));
                
                if (p) p->size = 0;
                
            } else {
                p = malloc(sizeof(Payload) + msg->length);
                
                if (p) {
                    p->size = msg->length;
                    memcpy(p->data, msg->data, msg->length);
                }
                
                rtp_free_msg(NULL, msg);
            }
            
            if (p) {
                buffer_write(cs->abuf, p);
            } else {
                LOGGER_WARNING("Allocation failed! Program might misbehave!");
            }
        }
        
        if (!buffer_empty(cs->abuf))
            pthread_cond_signal(cs->abuf_cond);
        pthread_mutex_unlock(cs->abuf_mutex);
    }
    /* Video */
    else {
        uint8_t *packet = msg->data;
        uint32_t recved_size = msg->length;
        
        if (recved_size < VIDEOFRAME_HEADER_SIZE)
            goto end;
        
        if (packet[0] > cs->frameid_in) {/* New frame */
            /* Flush last frames' data and get ready for this frame */
            Payload* p = malloc(sizeof(Payload) + cs->frame_size);
            
            if (p) {
                /* Schedule the decoding on another thread */
                pthread_mutex_lock(cs->vbuf_mutex);
                
                if (buffer_full(cs->vbuf)) {
                    LOGGER_DEBUG("Dropped video frame\n");
                    free(p);
                }
                else {
                    p->size = cs->frame_size;
                    memcpy(p->data, cs->frame_buf, cs->frame_size);
                    
                    buffer_write(cs->vbuf, p);
                    pthread_cond_signal(cs->vbuf_cond);
                }
                /*uint8_t w = cs->video_decode_write;
                
                if (cs->video_decode_queue[w] == NULL) {
                    cs->video_decode_queue[w] = p;
                    cs->video_decode_write = (w + 1) % VIDEO_DECODE_QUEUE_SIZE;
                    pthread_cond_signal(&cs->decode_cond);
                } else {
                    LOGGER_DEBUG("Dropped video frame\n");
                    free(p);
                }*/
                
                pthread_mutex_unlock(cs->vbuf_mutex);
            } else {
                LOGGER_WARNING("Allocation failed! Program might misbehave!");
                goto end;
            }
            
            cs->frameid_in = packet[0];
            memset(cs->frame_buf, 0, cs->frame_size);
            cs->frame_size = 0;
            
        } else if (packet[0] < cs->frameid_in) { /* Old frame; drop TODO: handle new cycle */
            LOGGER_DEBUG("Old packet: %u\n", packet[0]);
            goto end;
        }
        /* else it's the same frame so just process */
        
        LOGGER_DEBUG("Video Packet: %u %u\n", packet[0], packet[1]);
        memcpy(cs->frame_buf + cs->frame_size,
               packet + VIDEOFRAME_HEADER_SIZE,
               recved_size - VIDEOFRAME_HEADER_SIZE);
        
        cs->frame_size += recved_size - VIDEOFRAME_HEADER_SIZE;
        
        end:
        rtp_free_msg(NULL, msg);
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
    cfg.kf_max_dist = 5;
    cfg.kf_mode = VPX_KF_AUTO;

    cs->max_width = max_width;
    cs->max_height = max_height;

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


CodecState *codec_init_session ( const ToxAvCSettings *cs_self,
                                 const ToxAvCSettings *cs_peer,
                                 uint32_t jbuf_size,
                                 uint32_t audio_VAD_tolerance_ms )
{
    CodecState *cs = calloc(sizeof(CodecState), 1);

    if (!cs) {
        LOGGER_WARNING("Allocation failed! Application might misbehave!");
        return NULL;
    }
    
    if ( !(cs->j_buf = jbuf_new(jbuf_size)) ) {
        LOGGER_WARNING("Jitter buffer creaton failed!");
        goto error;
    }
    
    cs->max_video_frame_size = MAX_VIDEOFRAME_SIZE;
    cs->video_frame_piece_size = VIDEOFRAME_PIECE_SIZE;
    
    cs->audio_bitrate = cs_self->audio_bitrate;
    cs->audio_sample_rate = cs_self->audio_sample_rate;

    /* Encoders */
    if (!cs_self->max_video_width || !cs_self->max_video_height) { /* Disable video */
        /*video_width = 320;
        video_height = 240; */
    } else {
        cs->capabilities |= ( 0 == init_video_encoder(cs, cs_self->max_video_width, 
                    cs_self->max_video_height, cs_self->video_bitrate) ) ? v_encoding : 0;
        cs->capabilities |= ( 0 == init_video_decoder(cs) ) ? v_decoding : 0;
    }

    cs->capabilities |= ( 0 == init_audio_encoder(cs, cs_self->audio_channels) ) ? a_encoding : 0;
    cs->capabilities |= ( 0 == init_audio_decoder(cs, cs_peer->audio_channels) ) ? a_decoding : 0;

    if ( cs->capabilities == 0  ) { /* everything failed */
        free (cs);
        return NULL;
    }

    
    if ( !(cs->frame_buf = calloc(cs->max_video_frame_size)) ) 
        goto error;
    
    
    if (!(cs->split_video_frame = calloc(cs->video_frame_piece_size + VIDEOFRAME_HEADER_SIZE))) 
        goto error;

    if ( !(cs->abuf = buffer_new(AUDIO_DECODE_BUFFER_SIZE)) ) goto error;
    if ( !(cs->vbuf = buffer_new(VIDEO_DECODE_BUFFER_SIZE)) ) goto error;
    
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0 
     || pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0
     || pthread_mutex_init(cs->abuf_mutex, &attr) != 0 
     || pthread_mutex_init(cs->vbuf_mutex, &attr) != 0
     || pthread_attr_destroy(&attr)) goto error;
    
    if (pthread_cond_init(cs->abuf_cond) != 0 || pthread_cond_init(cs->vbuf_cond) != 0)
        goto error;
    
    cs->EVAD_tolerance = audio_VAD_tolerance_ms > cs_self->audio_frame_duration ?
        audio_VAD_tolerance_ms / cs_self->audio_frame_duration : cs_self->audio_frame_duration;
    
    cs->active = 1;
    return cs;
    
error:
    LOGGER_ERROR("Error initializing codec session! Application might misbehave!");
    pthread_mutex_destroy(cs->abuf_mutex);
    pthread_mutex_destroy(cs->vbuf_mutex);
    pthread_cond_destroy(cs->abuf_cond);
    pthread_cond_destroy(cs->vbuf_cond);
    pthread_attr_destroy(&attr);
    jbuf_free(cs->j_buf);
    buffer_free(cs->abuf);
    buffer_free(cs->vbuf);
    free(cs->frame_buf);
    free(cs);
    return NULL;
}

void codec_terminate_session ( CodecState *cs )
{
    if (!cs) return;

    if ( cs->audio_encoder )
        opus_encoder_destroy(cs->audio_encoder);

    if ( cs->audio_decoder )
        opus_decoder_destroy(cs->audio_decoder);

    if ( cs->v_decoder )
        vpx_codec_destroy(&cs->v_decoder);

    if ( cs->v_encoder )
        vpx_codec_destroy(&cs->v_encoder);

    cs->active = 0;
    pthread_cond_signal(cs->abuf_cond);
    pthread_cond_signal(cs->vbuf_cond);
    pthread_mutex_lock(cs->abuf_mutex);
    pthread_mutex_lock(cs->vbuf_mutex);
    pthread_mutex_unlock(cs->abuf_mutex);
    pthread_mutex_unlock(cs->vbuf_mutex);
    
    pthread_mutex_destroy(cs->abuf_mutex);
    pthread_mutex_destroy(cs->vbuf_mutex);
    pthread_cond_destroy(cs->abuf_cond);
    pthread_cond_destroy(cs->vbuf_cond);
    
    jbuf_free(cs->j_buf);
    buffer_free(cs->abuf);
    buffer_free(cs->vbuf);
    free(cs->frame_buf);
    free(cs);
    
    LOGGER_DEBUG("Terminated codec state: %p", cs);
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
