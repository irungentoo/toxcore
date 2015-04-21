/**  video.c
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

#include <stdlib.h>
#include <assert.h>

#include "video.h"
#include "msi.h"

#include "../toxcore/logger.h"
#include "../toxcore/network.h"

/* Good quality encode. */
#define MAX_DECODE_TIME_US 0

#define MAX_VIDEOFRAME_SIZE 0x40000 /* 256KiB */
#define VIDEOFRAME_HEADER_SIZE 0x2

/* FIXME: Might not be enough? NOTE: I think it is enough */
#define VIDEO_DECODE_BUFFER_SIZE 20

typedef struct { uint16_t size; uint8_t data[]; } Payload;

bool create_video_encoder (vpx_codec_ctx_t* dest, int32_t bitrate);


VCSession* vc_new(ToxAV* av, uint32_t friend_id, toxav_receive_video_frame_cb* cb, void* cb_data, uint32_t mvfpsz)
{
    VCSession *vc = calloc(sizeof(VCSession), 1);
    
    if (!vc) {
        LOGGER_WARNING("Allocation failed! Application might misbehave!");
        return NULL;
    }
    
    if (create_recursive_mutex(vc->queue_mutex) != 0) {
        LOGGER_WARNING("Failed to create recursive mutex!");
        free(vc);
        return NULL;
    }
    
    if ( !(vc->frame_buf = calloc(MAX_VIDEOFRAME_SIZE, 1)) )
        goto BASE_CLEANUP;
    if ( !(vc->split_video_frame = calloc(VIDEOFRAME_PIECE_SIZE + VIDEOFRAME_HEADER_SIZE, 1)) )
        goto BASE_CLEANUP;
    if ( !(vc->vbuf_raw = rb_new(VIDEO_DECODE_BUFFER_SIZE)) )
        goto BASE_CLEANUP;
    
    int rc = vpx_codec_dec_init_ver(vc->v_decoder, VIDEO_CODEC_DECODER_INTERFACE, 
                                    NULL, 0, VPX_DECODER_ABI_VERSION);
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Init video_decoder failed: %s", vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP;
    }
    
    if (!create_video_encoder(vc->v_encoder, 500000)) {
        vpx_codec_destroy(vc->v_decoder);
        goto BASE_CLEANUP;
    }
    
    vc->linfts = current_time_monotonic();
    vc->lcfd = 60;
    
    vc->peer_video_frame_piece_size = mvfpsz;
    
    return vc;
    
BASE_CLEANUP:
    pthread_mutex_destroy(vc->queue_mutex);
    rb_free(vc->vbuf_raw);
    free(vc->split_video_frame);
    free(vc->frame_buf);
    free(vc);
    return NULL;
}
void vc_kill(VCSession* vc)
{
    if (!vc)
        return;
    
    vpx_codec_destroy(vc->v_encoder);
    vpx_codec_destroy(vc->v_decoder);
    rb_free(vc->vbuf_raw);
    free(vc->split_video_frame);
    free(vc->frame_buf);
    
    pthread_mutex_destroy(vc->queue_mutex);
    
    LOGGER_DEBUG("Terminated video handler: %p", vc);
    free(vc);
}
void vc_do(VCSession* vc)
{
    if (!vc)
        return;
    
    Payload *p;
    int rc;
    
    pthread_mutex_lock(vc->queue_mutex);
    if (rb_read(vc->vbuf_raw, (void**)&p)) {
        pthread_mutex_unlock(vc->queue_mutex);
        
        rc = vpx_codec_decode(vc->v_decoder, p->data, p->size, NULL, MAX_DECODE_TIME_US);
        free(p);
        
        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR("Error decoding video: %s", vpx_codec_err_to_string(rc));
        } else {
            vpx_codec_iter_t iter = NULL;
            vpx_image_t *dest = vpx_codec_get_frame(vc->v_decoder, &iter);
            
            /* Play decoded images */
            for (; dest; dest = vpx_codec_get_frame(vc->v_decoder, &iter)) {
                if (vc->vcb.first) 
                    vc->vcb.first(vc->av, vc->friend_id, dest->d_w, dest->d_h, 
                                  (const uint8_t*)dest->planes[0], (const uint8_t*)dest->planes[1], (const uint8_t*)dest->planes[2],
                                  dest->stride[0], dest->stride[1], dest->stride[2], vc->vcb.second);
                
                vpx_img_free(dest);
            }
        }
        
        return;
    }
    pthread_mutex_unlock(vc->queue_mutex);
}
void vc_init_video_splitter_cycle(VCSession* vc)
{
    if (!vc)
        return;
    
    vc->split_video_frame[0] = vc->frameid_out++;
    vc->split_video_frame[1] = 0;
}
int vc_update_video_splitter_cycle(VCSession* vc, const uint8_t* payload, uint16_t length)
{
    if (!vc)
        return;

    vc->processing_video_frame = payload;
    vc->processing_video_frame_size = length;
    
    return ((length - 1) / VIDEOFRAME_PIECE_SIZE) + 1;
}
const uint8_t* vc_iterate_split_video_frame(VCSession* vc, uint16_t* size)
{
    if (!vc || !size) 
        return NULL;

    if (vc->processing_video_frame_size > VIDEOFRAME_PIECE_SIZE) {
        memcpy(vc->split_video_frame + VIDEOFRAME_HEADER_SIZE,
               vc->processing_video_frame,
               VIDEOFRAME_PIECE_SIZE);

        vc->processing_video_frame += VIDEOFRAME_PIECE_SIZE;
        vc->processing_video_frame_size -= VIDEOFRAME_PIECE_SIZE;

        *size = VIDEOFRAME_PIECE_SIZE + VIDEOFRAME_HEADER_SIZE;
    } else {
        memcpy(vc->split_video_frame + VIDEOFRAME_HEADER_SIZE,
               vc->processing_video_frame,
               vc->processing_video_frame_size);

        *size = vc->processing_video_frame_size + VIDEOFRAME_HEADER_SIZE;
    }

    vc->split_video_frame[1]++;

    return vc->split_video_frame;
}
int vc_reconfigure_encoder(VCSession* vc, int32_t bitrate, uint16_t width, uint16_t height)
{
    if (!vc)
        return;
    
    vpx_codec_enc_cfg_t cfg = *vc->v_encoder[0].config.enc;
    if (cfg.rc_target_bitrate == bitrate && cfg.g_w == width && cfg.g_h == height)
        return 0; /* Nothing changed */
    
    cfg.rc_target_bitrate = bitrate;
    cfg.g_w = width;
    cfg.g_h = height;
    
    int rc = vpx_codec_enc_config_set(vc->v_encoder, &cfg);
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        return -1;
    }

    return 0;
}
/* Called from RTP */
void vc_queue_message(void* vcp, RTPMessage *msg)
{
    /* This function does the reconstruction of video packets. 
     * See more info about video splitting in docs
     */
    if (!vcp || !msg)
        return;
    
    VCSession* vc = vcp;
    
    uint8_t *packet = msg->data;
    uint32_t packet_size = msg->length;

    if (packet_size < VIDEOFRAME_HEADER_SIZE)
        goto end;

    uint8_t diff = packet[0] - vc->frameid_in;

    if (diff != 0) {
        if (diff < 225) { /* New frame */
            /* Flush last frames' data and get ready for this frame */
            Payload *p = malloc(sizeof(Payload) + vc->frame_size);

            if (p) {
                LOGGED_LOCK(vc->queue_mutex);

                if (rb_full(vc->vbuf_raw)) {
                    LOGGER_DEBUG("Dropped video frame");
                    Payload *tp;
                    rb_read(vc->vbuf_raw, (void**)&tp);
                    free(tp);
                } else {
                    p->size = vc->frame_size;
                    memcpy(p->data, vc->frame_buf, vc->frame_size);
                }
                
                /* Calculate time took for peer to send us this frame */
                uint32_t t_lcfd = current_time_monotonic() - vc->linfts;
                vc->lcfd = t_lcfd > 100 ? vc->lcfd : t_lcfd;
                vc->linfts = current_time_monotonic();
                
                rb_write(vc->vbuf_raw, p);
                LOGGED_UNLOCK(vc->queue_mutex);
            } else {
                LOGGER_WARNING("Allocation failed! Program might misbehave!");
                goto end;
            }

            vc->frameid_in = packet[0];
            memset(vc->frame_buf, 0, vc->frame_size);
            vc->frame_size = 0;

        } else { /* Old frame; drop */
            LOGGER_DEBUG("Old packet: %u", packet[0]);
            goto end;
        }
    }

    uint8_t piece_number = packet[1];

    uint32_t length_before_piece = ((piece_number - 1) * vc->peer_video_frame_piece_size);
    uint32_t framebuf_new_length = length_before_piece + (packet_size - VIDEOFRAME_HEADER_SIZE);

    if (framebuf_new_length > MAX_VIDEOFRAME_SIZE)
        goto end;
    

    /* Otherwise it's part of the frame so just process */
    /* LOGGER_DEBUG("Video Packet: %u %u", packet[0], packet[1]); */

    memcpy(vc->frame_buf + length_before_piece,
           packet + VIDEOFRAME_HEADER_SIZE,
           packet_size - VIDEOFRAME_HEADER_SIZE);

    if (framebuf_new_length > vc->frame_size)
        vc->frame_size = framebuf_new_length;

end:
    rtp_free_msg(NULL, msg);
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