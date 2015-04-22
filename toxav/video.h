/**  video.h
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

#ifndef VIDEO_H
#define VIDEO_H

#include <vpx/vpx_decoder.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_image.h>
#define VIDEO_CODEC_DECODER_INTERFACE (vpx_codec_vp8_dx())
#define VIDEO_CODEC_ENCODER_INTERFACE (vpx_codec_vp8_cx())

#include <pthread.h>

#include "toxav.h"

#include "../toxcore/util.h"

struct RTPMessage_s;

typedef struct VCSession_s {
    
    /* encoding */
    vpx_codec_ctx_t v_encoder[1];
    uint32_t frame_counter;

    /* decoding */
    vpx_codec_ctx_t v_decoder[1];
    void *vbuf_raw; /* Un-decoded data */    

    /* Data handling */
    uint8_t *frame_buf; /* buffer for split video payloads */
    uint32_t frame_size; /* largest address written to in frame_buf for current input frame */
    uint8_t  frameid_in, frameid_out; /* id of input and output video frame */
    uint64_t linfts; /* Last received frame time stamp */
    uint32_t lcfd; /* Last calculated frame duration for incoming video payload */
    
    /* Limits */
    uint32_t peer_video_frame_piece_size;

    /* Splitting */
    uint8_t *split_video_frame;
    const uint8_t *processing_video_frame;
    uint16_t processing_video_frame_size;
    
    
    ToxAV *av;
    int32_t friend_id;
    
    PAIR(toxav_receive_video_frame_cb *, void *) vcb; /* Video frame receive callback */
    
    pthread_mutex_t queue_mutex[1];
} VCSession;

VCSession* vc_new(ToxAV* av, uint32_t friend_id, toxav_receive_video_frame_cb *cb, void *cb_data, uint32_t mvfpsz);
void vc_kill(VCSession* vc);
void vc_do(VCSession* vc);
void vc_init_video_splitter_cycle(VCSession* vc);
int vc_update_video_splitter_cycle(VCSession* vc, const uint8_t* payload, uint16_t length);
const uint8_t *vc_iterate_split_video_frame(VCSession* vc, uint16_t *size);
int vc_queue_message(void *vcp, struct RTPMessage_s *msg);
int vc_reconfigure_encoder(VCSession* vc, int32_t bitrate, uint16_t width, uint16_t height);

#endif /* VIDEO_H */