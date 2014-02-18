/**  media.h
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

#ifndef _AVCODEC_H_
#define _AVCODEC_H_

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
#include <opus/opus.h>


typedef struct _CodecState {

    /* video encoding */
    vpx_codec_ctx_t  v_encoder;
    uint32_t frame_counter;

    /* video decoding */
    vpx_codec_ctx_t  v_decoder;

    /* audio encoding */
    OpusEncoder *audio_encoder;
    int audio_bitrate;
    int audio_sample_rate;

    /* audio decoding */
    OpusDecoder *audio_decoder;

} CodecState;

typedef struct _RTPMessage RTPMessage;

struct jitter_buffer *create_queue(int capacity);
int empty_queue(struct jitter_buffer *q);

int queue(struct jitter_buffer *q, RTPMessage *pk);
RTPMessage *dequeue(struct jitter_buffer *q, int *success);


CodecState *codec_init_session ( uint32_t audio_bitrate,
                                 uint16_t audio_frame_duration,
                                 uint32_t audio_sample_rate,
                                 uint32_t audio_channels,
                                 uint16_t video_width,
                                 uint16_t video_height,
                                 uint32_t video_bitrate );

void codec_terminate_session(CodecState *cs);

#endif
