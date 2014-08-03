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

typedef enum _Capabilities {
    none,
    a_encoding = 1 << 0,
    a_decoding = 1 << 1,
    v_encoding = 1 << 2,
    v_decoding = 1 << 3
} Capabilities;

extern const uint16_t min_jbuf_size;

typedef struct _CodecState {

    /* video encoding */
    vpx_codec_ctx_t  v_encoder;
    uint32_t frame_counter;

    /* video decoding */
    vpx_codec_ctx_t  v_decoder;
    int bitrate;
    int max_width;
    int max_height;

    /* audio encoding */
    OpusEncoder *audio_encoder;
    int audio_bitrate;
    int audio_sample_rate;
    int audio_encoder_channels;

    /* audio decoding */
    OpusDecoder *audio_decoder;
    int audio_decoder_channels;

    uint64_t capabilities; /* supports*/

    /* Voice activity detection */
    uint32_t EVAD_tolerance; /* In frames */
    uint32_t EVAD_tolerance_cr;
} CodecState;


typedef struct _JitterBuffer {
    RTPMessage **queue;
    uint32_t size;
    uint32_t capacity;
    uint16_t bottom;
    uint16_t top;
} JitterBuffer;

JitterBuffer *create_queue(unsigned int capacity);
void terminate_queue(JitterBuffer *q);
void queue(JitterBuffer *q, RTPMessage *pk);
RTPMessage *dequeue(JitterBuffer *q, int *success);


CodecState *codec_init_session ( uint32_t audio_bitrate,
                                 uint16_t audio_frame_duration,
                                 uint32_t audio_sample_rate,
                                 uint32_t encoder_audio_channels,
                                 uint32_t decoder_audio_channels,
                                 uint32_t audio_VAD_tolerance_ms,
                                 uint16_t max_video_width,
                                 uint16_t max_video_height,
                                 uint32_t video_bitrate );

void codec_terminate_session(CodecState *cs);

/* Reconfigure video encoder
   return 0 on success.
   return -1 on failure. */
int reconfigure_video_encoder_resolution(CodecState *cs, uint16_t width, uint16_t height);
int reconfigure_video_encoder_bitrate(CodecState *cs, uint32_t video_bitrate);

/* Calculate energy and return 1 if has voice, 0 if not */
int energy_VAD(CodecState *cs, int16_t *PCM, uint16_t frame_size, float energy);

#endif /* _CODEC_H_ */
