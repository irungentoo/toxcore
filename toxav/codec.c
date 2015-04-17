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

#define DEFAULT_JBUF 3

/* Good quality encode. */
#define MAX_DECODE_TIME_US 0

#define MAX_VIDEOFRAME_SIZE 0x40000 /* 256KiB */
#define VIDEOFRAME_HEADER_SIZE 0x2

/* FIXME: Might not be enough? NOTE: I think it is enough */
#define VIDEO_DECODE_BUFFER_SIZE 20

#define ARRAY(TYPE__) struct { uint16_t size; TYPE__ data[]; }

typedef ARRAY(uint8_t) Payload;

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
        LOGGER_DEBUG("Clearing filled jitter buffer: %p", q);
        
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

/* success is set to 0 when there is nothing to dequeue,
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

OpusEncoder* create_audio_encoder (int32_t bitrate, int32_t sampling_rate, int32_t channel_count)
{
    int status = OPUS_OK;
    OpusEncoder* rc = opus_encoder_create(sampling_rate, channel_count, OPUS_APPLICATION_AUDIO, &status);
    
    if ( status != OPUS_OK ) {
        LOGGER_ERROR("Error while starting audio encoder: %s", opus_strerror(status));
        return NULL;
    }
    
    status = opus_encoder_ctl(rc, OPUS_SET_BITRATE(bitrate));
    
    if ( status != OPUS_OK ) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }
    
    status = opus_encoder_ctl(rc, OPUS_SET_COMPLEXITY(10));
    
    if ( status != OPUS_OK ) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }
    
    return rc;
    
FAILURE:
    opus_encoder_destroy(rc);
    return NULL;
}

bool create_video_encoder (vpx_codec_ctx_t* dest, int32_t bitrate)
{
    assert(dest);
    
    vpx_codec_enc_cfg_t  cfg;
    int rc = vpx_codec_enc_config_default(VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0);
    
    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to get config: %s", vpx_codec_err_to_string(rc));
        return false;
    }
    
    rc = vpx_codec_enc_init_ver(dest, VIDEO_CODEC_ENCODER_INTERFACE, &cfg, 0, 
                                VPX_ENCODER_ABI_VERSION);
    
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
        return false;
    }
    
    cfg.rc_target_bitrate = bitrate;
    cfg.g_w = 800;
    cfg.g_h = 600;
    cfg.g_pass = VPX_RC_ONE_PASS;
    cfg.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT | VPX_ERROR_RESILIENT_PARTITIONS;
    cfg.g_lag_in_frames = 0;
    cfg.kf_min_dist = 0;
    cfg.kf_max_dist = 48;
    cfg.kf_mode = VPX_KF_AUTO;
    
    rc = vpx_codec_control(dest, VP8E_SET_CPUUSED, 8);
    
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        vpx_codec_destroy(dest);
    }
    
    return true;
}

bool reconfigure_audio_decoder(CSession* cs, int32_t sampling_rate, int8_t channels)
{
    if (sampling_rate != cs->last_decoding_sampling_rate || channels != cs->last_decoding_channel_count) {
        if (current_time_monotonic() - cs->last_decoder_reconfiguration < 500)
            return false;
        
        int status;
        OpusDecoder* new_dec = opus_decoder_create(sampling_rate, channels, &status );
        if ( status != OPUS_OK ) {
            LOGGER_ERROR("Error while starting audio decoder(%d %d): %s", sampling_rate, channels, opus_strerror(status));
            return false;
        }
        
        cs->last_decoding_sampling_rate = sampling_rate;
        cs->last_decoding_channel_count = channels;
        cs->last_decoder_reconfiguration = current_time_monotonic();
        
        opus_decoder_destroy(cs->audio_decoder);
        cs->audio_decoder = new_dec;
        
        LOGGER_DEBUG("Reconfigured audio decoder sr: %d cc: %d", sampling_rate, channels);
    }
    
    return true;
}

/* PUBLIC */
void cs_do(CSession *cs)
{
    /* Codec session should always be protected by call mutex so no need to check for cs validity
     */
    
    if (!cs)
        return;
    
    Payload *p;
    int rc;
    
    int success = 0;
    
    LOGGED_LOCK(cs->queue_mutex);
    
    /********************* AUDIO *********************/
    if (cs->audio_decoder) {
        RTPMessage *msg;
        
        /* The maximum for 120 ms 48 KHz audio */
        int16_t tmp[5760];
        
        while ((msg = jbuf_read(cs->j_buf, &success)) || success == 2) {
            LOGGED_UNLOCK(cs->queue_mutex);
            
            if (success == 2) {
                LOGGER_DEBUG("OPUS correction");
                rc = opus_decode(cs->audio_decoder, NULL, 0, tmp,
                                (cs->last_packet_sampling_rate * cs->last_packet_frame_duration / 1000) /
                                 cs->last_packet_channel_count, 1);
            } else {
                /* Get values from packet and decode. */
                /* NOTE: This didn't work very well
                rc = convert_bw_to_sampling_rate(opus_packet_get_bandwidth(msg->data));
                if (rc != -1) {
                    cs->last_packet_sampling_rate = rc;
                } else {
                    LOGGER_WARNING("Failed to load packet values!");
                    rtp_free_msg(NULL, msg);
                    continue;
                }*/
                
                
                /* Pick up sampling rate from packet */
                memcpy(&cs->last_packet_sampling_rate, msg->data, 4);
                cs->last_packet_sampling_rate = ntohl(cs->last_packet_sampling_rate);
                
                cs->last_packet_channel_count = opus_packet_get_nb_channels(msg->data + 4);
                
                /* 
                 * NOTE: even though OPUS supports decoding mono frames with stereo decoder and vice versa,
                 * it didn't work quite well.
                 */
                if (!reconfigure_audio_decoder(cs, cs->last_packet_sampling_rate, cs->last_packet_channel_count)) {
                    LOGGER_WARNING("Failed to reconfigure decoder!");
                    rtp_free_msg(NULL, msg);
                    continue;
//                     goto DONE;
                }
                
                rc = opus_decode(cs->audio_decoder, msg->data + 4, msg->length - 4, tmp, 5760, 0);
                rtp_free_msg(NULL, msg);
            }
            
            if (rc < 0) {
                LOGGER_WARNING("Decoding error: %s", opus_strerror(rc));
            } else if (cs->acb.first) {
                cs->last_packet_frame_duration = (rc * 1000) / cs->last_packet_sampling_rate * cs->last_packet_channel_count;
                
                cs->acb.first(cs->av, cs->friend_id, tmp, rc * cs->last_packet_channel_count,
                            cs->last_packet_channel_count, cs->last_packet_sampling_rate, cs->acb.second);
                
            }
            
            LOGGED_LOCK(cs->queue_mutex);
        }
//         DONE:;
    }
    
    /********************* VIDEO *********************/
    if (cs->vbuf_raw && !rb_empty(cs->vbuf_raw)) {
        /* Decode video */
        rb_read(cs->vbuf_raw, (void**)&p);
        
        /* Leave space for (possibly) other thread to queue more data after we read it here */
        LOGGED_UNLOCK(cs->queue_mutex);
        
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
                    cs->vcb.first(cs->av, cs->friend_id, dest->d_w, dest->d_h, 
                                  (const uint8_t**)dest->planes, dest->stride, cs->vcb.second);
                
                vpx_img_free(dest);
            }
        }
        
        return;
    }
    
    LOGGED_UNLOCK(cs->queue_mutex);
}
CSession *cs_new(uint32_t peer_video_frame_piece_size)
{
    CSession *cs = calloc(sizeof(CSession), 1);
    
    if (!cs) {
        LOGGER_WARNING("Allocation failed! Application might misbehave!");
        return NULL;
    }
    
    if (create_recursive_mutex(cs->queue_mutex) != 0) {
        LOGGER_WARNING("Failed to create recursive mutex!");
        free(cs);
        return NULL;
    }
    
    /*++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    /* Create decoders and set up their values
     */
    
    /*
     * AUDIO
     */
    
    int status;
    cs->audio_decoder = opus_decoder_create(48000, 2, &status );
    
    if ( status != OPUS_OK ) {
        LOGGER_ERROR("Error while starting audio decoder: %s", opus_strerror(status));
        goto FAILURE;
    }
    
    cs->last_decoding_channel_count = 2;
    cs->last_decoding_sampling_rate = 48000;
    cs->last_decoder_reconfiguration = 0; /* Make it possible to reconfigure straight away */
    
    /* These need to be set in order to properly
     * do error correction with opus */
    cs->last_packet_frame_duration = 120;
    cs->last_packet_sampling_rate = 48000;
    
    if ( !(cs->j_buf = jbuf_new(DEFAULT_JBUF)) ) {
        LOGGER_WARNING("Jitter buffer creaton failed!");
        opus_decoder_destroy(cs->audio_decoder);
        goto FAILURE;
    }
    
    /*
     * VIDEO
     */
    int rc = vpx_codec_dec_init_ver(cs->v_decoder, VIDEO_CODEC_DECODER_INTERFACE, 
                                    NULL, 0, VPX_DECODER_ABI_VERSION);
    
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Init video_decoder failed: %s", vpx_codec_err_to_string(rc));
        goto AUDIO_DECODER_CLEANUP;
    }
    
    if ( !(cs->frame_buf = calloc(MAX_VIDEOFRAME_SIZE, 1)) ) {
        vpx_codec_destroy(cs->v_decoder);
        goto AUDIO_DECODER_CLEANUP;
    }
    
    if ( !(cs->vbuf_raw = rb_new(VIDEO_DECODE_BUFFER_SIZE)) ) {
        free(cs->frame_buf);
        vpx_codec_destroy(cs->v_decoder);
        goto AUDIO_DECODER_CLEANUP;
    }
    
    if ( !(cs->split_video_frame = calloc(VIDEOFRAME_PIECE_SIZE + VIDEOFRAME_HEADER_SIZE, 1)) )
        goto FAILURE;
    
    cs->linfts = current_time_monotonic();
    cs->lcfd = 60;
    /*++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
    
    /* Initialize encoders with default values */
    cs->audio_encoder = create_audio_encoder(48000, 48000, 2);
    if (cs->audio_encoder == NULL)
        goto VIDEO_DECODER_CLEANUP;
    
    cs->last_encoding_bitrate = 48000;
    cs->last_encoding_sampling_rate = 48000;
    cs->last_encoding_channel_count = 2;
    
    if (!create_video_encoder(cs->v_encoder, 500000)) {
        opus_encoder_destroy(cs->audio_encoder);
        goto VIDEO_DECODER_CLEANUP;
    }
    
    cs->peer_video_frame_piece_size = peer_video_frame_piece_size;
    
    return cs;

VIDEO_DECODER_CLEANUP:
    rb_free(cs->vbuf_raw);
    free(cs->frame_buf);
    vpx_codec_destroy(cs->v_decoder);
AUDIO_DECODER_CLEANUP:
    opus_decoder_destroy(cs->audio_decoder);
    jbuf_free(cs->j_buf);
FAILURE:
    pthread_mutex_destroy(cs->queue_mutex);
    free(cs);
    return NULL;
}
void cs_kill(CSession *cs)
{
    if (!cs) 
        return;
    
    /* NOTE: queue_message() will not be called since 
     * the callback is unregistered before cs_kill is called.
     */
    
    vpx_codec_destroy(cs->v_encoder);
    vpx_codec_destroy(cs->v_decoder);
    opus_encoder_destroy(cs->audio_encoder);
    opus_decoder_destroy(cs->audio_decoder);
    rb_free(cs->vbuf_raw);
    jbuf_free(cs->j_buf);
    free(cs->frame_buf);
    free(cs->split_video_frame);
    
    pthread_mutex_destroy(cs->queue_mutex);
    
    LOGGER_DEBUG("Terminated codec state: %p", cs);
    free(cs);
}
void cs_init_video_splitter_cycle(CSession* cs)
{
    cs->split_video_frame[0] = cs->frameid_out++;
    cs->split_video_frame[1] = 0;
}
int cs_update_video_splitter_cycle(CSession *cs, const uint8_t *payload, uint16_t length)
{
    cs->processing_video_frame = payload;
    cs->processing_video_frame_size = length;
    
    return ((length - 1) / VIDEOFRAME_PIECE_SIZE) + 1;
}
const uint8_t *cs_iterate_split_video_frame(CSession *cs, uint16_t *size)
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
int cs_reconfigure_video_encoder(CSession* cs, int32_t bitrate, uint16_t width, uint16_t height)
{
    vpx_codec_enc_cfg_t cfg = *cs->v_encoder[0].config.enc;
    if (cfg.rc_target_bitrate == bitrate && cfg.g_w == width && cfg.g_h == height)
        return 0; /* Nothing changed */
    
    cfg.rc_target_bitrate = bitrate;
    cfg.g_w = width;
    cfg.g_h = height;
    
    int rc = vpx_codec_enc_config_set(cs->v_encoder, &cfg);
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    return 0;
}
int cs_reconfigure_audio_encoder(CSession* cs, int32_t bitrate, int32_t sampling_rate, uint8_t channels)
{
    /* Values are checked in toxav.c */
    
    if (cs->last_encoding_sampling_rate != sampling_rate || cs->last_encoding_channel_count != channels) {
        OpusEncoder* new_encoder = create_audio_encoder(bitrate, sampling_rate, channels);
        if (new_encoder == NULL)
            return -1;
        
        opus_encoder_destroy(cs->audio_encoder);
        cs->audio_encoder = new_encoder;
    } else if (cs->last_encoding_bitrate == bitrate)
        return 0; /* Nothing changed */
    else {
        int status = opus_encoder_ctl(cs->audio_encoder, OPUS_SET_BITRATE(bitrate));
        
        if ( status != OPUS_OK ) {
            LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(status));
            return -1;
        }
    }

    cs->last_encoding_bitrate = bitrate;
    cs->last_encoding_sampling_rate = sampling_rate;
    cs->last_encoding_channel_count = channels;
    
    LOGGER_DEBUG ("Reconfigured audio encoder br: %d sr: %d cc:%d", bitrate, sampling_rate, channels);
    return 0;
}
/* Called from RTP */
void queue_message(RTPSession *session, RTPMessage *msg)
{
    CSession *cs = session->cs;

    if (!cs) 
		return;
	
    /* Audio */
    if (session->payload_type == rtp_TypeAudio % 128) {
        LOGGED_LOCK(cs->queue_mutex);
        int ret = jbuf_write(cs->j_buf, msg);
        LOGGED_UNLOCK(cs->queue_mutex);

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
                    LOGGED_LOCK(cs->queue_mutex);

                    if (rb_full(cs->vbuf_raw)) {
                        LOGGER_DEBUG("Dropped video frame");
                        Payload *tp;
                        rb_read(cs->vbuf_raw, (void**)&tp);
                        free(tp);
                    } else {
                        p->size = cs->frame_size;
                        memcpy(p->data, cs->frame_buf, cs->frame_size);
                    }
                    
                    /* Calculate time took for peer to send us this frame */
                    uint32_t t_lcfd = current_time_monotonic() - cs->linfts;
                    cs->lcfd = t_lcfd > 100 ? cs->lcfd : t_lcfd;
                    cs->linfts = current_time_monotonic();
                    
                    rb_write(cs->vbuf_raw, p);
                    LOGGED_UNLOCK(cs->queue_mutex);
                } else {
                    LOGGER_WARNING("Allocation failed! Program might misbehave!");
                    goto end;
                }

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
