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
#include <vpx/vpx_image.h>
#define VIDEO_CODEC_DECODER_INTERFACE (vpx_codec_vp8_dx())
#define VIDEO_CODEC_ENCODER_INTERFACE (vpx_codec_vp8_cx())

/* Audio encoding/decoding */
#include <opus.h>

#define PAIR(TYPE1__, TYPE2__) struct { TYPE1__ first; TYPE2__ second; }

typedef void (*CSAudioCallback) (void *agent, int32_t call_idx, const int16_t *PCM, uint16_t size, void *data);
typedef void (*CSVideoCallback) (void *agent, int32_t call_idx, const vpx_image_t *img, void *data);

/**
 * Codec capabilities
 */
typedef enum {
    cs_AudioEncoding = 1 << 0,
    cs_AudioDecoding = 1 << 1,
    cs_VideoEncoding = 1 << 2,
    cs_VideoDecoding = 1 << 3
} CSCapabilities;

/**
 * Codec errors.
 */
typedef enum {
    cs_ErrorSettingVideoResolution = -30,
    cs_ErrorSettingVideoBitrate = -31,
    cs_ErrorSplittingVideoPayload = -32,
} CSError;

/**
 * Codec session - controling codec
 */
typedef struct _CSSession {

    /* VIDEO
        *
        *
        */

    /* video encoding */
    vpx_codec_ctx_t v_encoder[1];
    bool v_encoding;
    uint32_t frame_counter;

    /* video decoding */
    vpx_codec_ctx_t v_decoder[1];
    bool v_decoding;
    void *vbuf_raw; /* Un-decoded data */    

    /* Data handling */
    uint8_t *frame_buf; /* buffer for split video payloads */
    uint32_t frame_size; /* largest address written to in frame_buf for current input frame*/
    uint8_t  frameid_in, frameid_out; /* id of input and output video frame */
    uint32_t last_timestamp; /* calculating cycles */

    /* Limits */
    uint32_t video_frame_piece_size;
    uint32_t max_video_frame_size;

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
    int32_t encoder_channels;
    
    /* audio decoding */
    OpusDecoder *audio_decoder;
    int32_t last_pack_channels;
    int32_t last_packet_sampling_rate;
    int32_t last_packet_frame_duration;
    struct _JitterBuffer *j_buf;


    /* Voice activity detection */
    uint32_t EVAD_tolerance; /* In frames */
    uint32_t EVAD_tolerance_cr;



    /* OTHER
        *
        *
        */
    void *agent; /* Pointer to ToxAV TODO make this pointer to ToxAV*/
    int32_t call_idx;
    
    pthread_mutex_t queue_mutex[1];
} CSSession;


/**
 * Generic
 */
void cs_do(CSSession *cs);

/* Make sure to be called BEFORE corresponding rtp_new */
CSSession *cs_new(uint32_t s_audio_b, uint32_t p_audio_b, uint32_t s_video_b, uint32_t p_video_b);
/* Make sure to be called AFTER corresponding rtp_kill */
void cs_kill(CSSession *cs);


/**
 * VIDEO HANDLING
 */
void cs_init_video_splitter_cycle(CSSession *cs);
int cs_update_video_splitter_cycle(CSSession* cs, const uint8_t* payload, uint16_t length);
const uint8_t *cs_iterate_split_video_frame(CSSession *cs, uint16_t *size);

int cs_set_sending_video_resolution(CSSession *cs, uint16_t width, uint16_t height);
int cs_set_sending_video_bitrate(CSSession *cs, uint32_t bitrate);

int cs_enable_video_sending(CSSession* cs, uint32_t bitrate);
int cs_enable_video_receiving(CSSession* cs);

void cs_disable_video_sending(CSSession* cs);
void cs_disable_video_receiving(CSSession* cs);

/**
 * AUDIO HANDLING
 */
int cs_set_sending_audio_bitrate(CSSession* cs, int32_t rate);
int cs_set_sending_audio_sampling_rate(CSSession* cs, int32_t rate);
int cs_set_sending_audio_channels(CSSession* cs, int32_t count);

int cs_enable_audio_sending(CSSession* cs, uint32_t bitrate, int channels);
int cs_enable_audio_receiving(CSSession* cs);

void cs_disable_audio_sending(CSSession* cs);
void cs_disable_audio_receiving(CSSession* cs);




/* Internal. Called from rtp_handle_message */
void queue_message(RTPSession *session, RTPMessage *msg);
#endif /* _CODEC_H_ */
