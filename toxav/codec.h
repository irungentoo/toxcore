/**  codec.h
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

#ifndef CODEC_H
#define CODEC_H

#include "toxav.h"
#include "rtp.h"

#include "../toxcore/util.h"

#include <stdio.h>
#include <math.h>
#include <pthread.h>

#include <vpx/vpx_decoder.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#include <vpx/vpx_image.h>
#define VIDEO_CODEC_DECODER_INTERFACE (vpx_codec_vp8_dx())
#define VIDEO_CODEC_ENCODER_INTERFACE (vpx_codec_vp8_cx())

/* Audio encoding/decoding */
#include <opus.h>

#define PACKED_AUDIO_SIZE(x) (x + 5)
#define UNPACKED_AUDIO_SIZE(x) (x - 5)

typedef struct CSession_s {

    /* VIDEO
        *
        *
        */

    /* video encoding */
    vpx_codec_ctx_t v_encoder[1];
    uint32_t frame_counter;

    /* video decoding */
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



    /* AUDIO
        *
        *
        */

    /* audio encoding */
    OpusEncoder *audio_encoder;
    int32_t last_encoding_sampling_rate;
    int32_t last_encoding_channel_count;
    int32_t last_encoding_bitrate;
    
    /* audio decoding */
    OpusDecoder *audio_decoder;
    int32_t last_packet_channel_count;
    int32_t last_packet_sampling_rate;
    int32_t last_packet_frame_duration;
    int32_t last_decoding_sampling_rate;
    int32_t last_decoding_channel_count;
    uint64_t last_decoder_reconfiguration;
    struct JitterBuffer_s *j_buf;


    /* OTHER
        *
        *
        */
    ToxAV *av;
    int32_t friend_id;
    
    PAIR(toxav_receive_audio_frame_cb *, void *) acb; /* Audio frame receive callback */
    PAIR(toxav_receive_video_frame_cb *, void *) vcb; /* Video frame receive callback */
    
    pthread_mutex_t queue_mutex[1];
} CSession;


void cs_do(CSession *cs);
/* Make sure to be called BEFORE corresponding rtp_new */
CSession *cs_new(uint32_t peer_mvfpsz);
/* Make sure to be called AFTER corresponding rtp_kill */
void cs_kill(CSession *cs);

void cs_init_video_splitter_cycle(CSession *cs);
int cs_update_video_splitter_cycle(CSession* cs, const uint8_t* payload, uint16_t length);
const uint8_t *cs_iterate_split_video_frame(CSession *cs, uint16_t *size);

int cs_reconfigure_video_encoder(CSession* cs, int32_t bitrate, uint16_t width, uint16_t height);
int cs_reconfigure_audio_encoder(CSession* cs, int32_t bitrate, int32_t sampling_rate, uint8_t channels);
#endif /* CODEC_H */
