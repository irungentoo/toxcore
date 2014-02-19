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
    size_t frame_counter;

    /* video decoding */
    vpx_codec_ctx_t  v_decoder;

    /* audio encoding */
    OpusEncoder *audio_encoder;
    ptrdiff_t audio_bitrate;
    ptrdiff_t audio_sample_rate;

    /* audio decoding */
    OpusDecoder *audio_decoder;

} CodecState;

typedef struct _RTPMessage RTPMessage;

struct jitter_buffer *create_queue(ptrdiff_t capacity);
ptrdiff_t empty_queue(struct jitter_buffer *q);

ptrdiff_t queue(struct jitter_buffer *q, RTPMessage *pk);
RTPMessage *dequeue(struct jitter_buffer *q, ptrdiff_t *success);


CodecState *codec_init_session ( size_t audio_bitrate,
                                 size_t audio_frame_duration,
                                 size_t audio_sample_rate,
                                 size_t audio_channels,
                                 size_t video_width,
                                 size_t video_height,
                                 size_t video_bitrate );

void codec_terminate_session(CodecState *cs);

#endif
