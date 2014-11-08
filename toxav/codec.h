/**  codec.h
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

#ifndef _CODEC_H_
#define _CODEC_H_

#include "toxav.h"
#include "rtp.h"

#include <stdio.h>
#include <math.h>
#include <pthread.h>

#include <vpx/vpx_decoder.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vp8dx.h>
#include <vpx/vp8cx.h>
#define VIDEO_CODEC_DECODER_INTERFACE (vpx_codec_vp8_dx())
#define VIDEO_CODEC_ENCODER_INTERFACE (vpx_codec_vp8_cx())

/* Audio encoding/decoding */
#include <opus.h>

typedef enum _CsCapabilities {
    none,
    a_encoding = 1 << 0,
    a_decoding = 1 << 1,
    v_encoding = 1 << 2,
    v_decoding = 1 << 3
} CsCapabilities;

extern const uint16_t min_jbuf_size;

#define VIDEO_DECODE_BUFFER_SIZE 4
#define AUDIO_DECODE_BUFFER_SIZE 16

typedef struct _CodecState {

/* VIDEO 
    * 
    * 
    */
    int support_video;
    
    /* video encoding */
    vpx_codec_ctx_t  v_encoder;
    uint32_t frame_counter;

    /* video decoding */
    vpx_codec_ctx_t  v_decoder;
    int max_width;
    int max_height;

    
    /* Data handling */    
    uint8_t *frame_buf; /* buffer for split video payloads */
    uint32_t frame_size; /* largest address written to in frame_buf for current input frame*/
    uint8_t  frameid_in, frameid_out; /* id of input and output video frame */
    uint32_t last_timestamp; /* calculating cycles */
    
    /* Limits */
    uint32_t video_frame_piece_size;
    uint32_t max_video_frame_size;
    
    /* Reassembling */
    uint8_t *split_video_frame;
    const uint8_t *processing_video_frame;
    uint16_t processing_video_frame_size;

    
    
/* AUDIO 
    * 
    * 
    */

    /* audio encoding */
    OpusEncoder *audio_encoder;
    int audio_bitrate;
    int audio_sample_rate;
    int audio_encoder_channels;

    /* audio decoding */
    OpusDecoder *audio_decoder;
    int audio_decoder_channels;

    struct _JitterBuffer* j_buf;
    

    /* Voice activity detection */
    uint32_t EVAD_tolerance; /* In frames */
    uint32_t EVAD_tolerance_cr;
    
    
    
/* MISC
    * 
    * 
    */
    
    uint64_t capabilities; /* supports*/
    
    /* Buffering */
    void* abuf, *vbuf;
    pthread_mutex_t abuf_mutex[1], vbuf_mutex[1];
    pthread_cond_t abuf_cond[1], vbuf_cond[1];
    _Bool active;
    
} CodecState;


int cs_split_video_payload(CodecState* cs, const uint8_t* payload, uint16_t length);
/* Warning: Not thread safe! */
const uint8_t* cs_get_split_video_frame(CodecState* cs, uint16_t* size);

/**
 * Set wait = 0 to poll; -1 forevaaa; otherwise time to wait in ms.
 */
int cs_recv_decoded_video(CodecState* cs, vpx_image_t** dest, uint16_t max_images, int32_t wait);
int cs_recv_decoded_audio(CodecState* cs, int16_t* dest, uint16_t max_size, int32_t wait);

CodecState *cs_init_session ( const ToxAvCSettings *cs_self,
                                 const ToxAvCSettings *cs_peer,
                                 uint32_t jbuf_size,
                                 uint32_t audio_VAD_tolerance_ms, 
                                 int support_video);

void cs_terminate_session (CodecState *cs);

/* Reconfigure video encoder
   return 0 on success.
   return -1 on failure. */
int cs_reconfigure_video_encoder_resolution(CodecState *cs, uint16_t width, uint16_t height);
int cs_reconfigure_video_encoder_bitrate(CodecState *cs, uint32_t video_bitrate);

/* Calculate energy and return 1 if has voice, 0 if not */
int cs_calculate_energy_VAD(CodecState *cs, int16_t *PCM, uint16_t frame_size, float energy);




/* Internal. Called from rtp_handle_message */
void queue_message(RTPSession *session, RTPMessage *msg);
#endif /* _CODEC_H_ */
