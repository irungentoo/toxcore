/* AV_codec.h
 *
 * Audio and video codec intitialisation, encoding/decoding and playback
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*----------------------------------------------------------------------------------*/
#ifndef _AVCODEC_H_
#define _AVCODEC_H_

#include <stdio.h>
#include <math.h>
#include "toxrtp.h"
#include "toxmsi.h"
#include "../toxcore/tox.h"

/* Video encoding/decoding */
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>
#include <libavdevice/avdevice.h>
#include <libavutil/opt.h>

/* Audio encoding/decoding */
#include <opus/opus.h>

/* ffmpeg VP8 codec ID */
#define VIDEO_CODEC AV_CODEC_ID_VP8

/* ffmpeg Opus codec ID */
#define AUDIO_CODEC AV_CODEC_ID_OPUS

/* default video bitrate in bytes/s */
#define VIDEO_BITRATE   10*1000

/* default audio bitrate in bytes/s */
#define AUDIO_BITRATE   64000

/* audio frame duration in miliseconds */
#define AUDIO_FRAME_DURATION    20

/* audio sample rate recommended to be 48kHz for Opus */
#define AUDIO_SAMPLE_RATE   48000

/* the amount of samples in one audio frame */
#define AUDIO_FRAME_SIZE    AUDIO_SAMPLE_RATE*AUDIO_FRAME_DURATION/1000

/* the quit event for SDL */
#define FF_QUIT_EVENT (SDL_USEREVENT + 2)

#ifdef __linux__
#define VIDEO_DRIVER "video4linux2"
#define DEFAULT_WEBCAM "/dev/video0"
#endif

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define VIDEO_DRIVER "vfwcap"
#define DEFAULT_WEBCAM "0"
#endif

typedef struct {
    uint8_t send_audio;
    uint8_t receive_audio;
    uint8_t send_video;
    uint8_t receive_video;

    uint8_t support_send_audio;
    uint8_t support_send_video;
    uint8_t support_receive_audio;
    uint8_t support_receive_video;

    /* video encoding */
    AVInputFormat *video_input_format;
    AVFormatContext *video_format_ctx;
    uint8_t video_stream;
    AVCodecContext *webcam_decoder_ctx;
    AVCodec *webcam_decoder;
    AVCodecContext *video_encoder_ctx;
    AVCodec *video_encoder;

    /* video decoding */
    AVCodecContext *video_decoder_ctx;
    AVCodec *video_decoder;

    /* audio encoding */
    OpusEncoder *audio_encoder;
    int audio_bitrate;

    /* audio decoding */
    OpusDecoder *audio_decoder;

    uint8_t req_video_refresh;
    
    pthread_mutex_t rtp_msg_mutex_lock;
    pthread_mutex_t avcodec_mutex_lock;
    
    uint8_t quit;
    
    uint32_t frame_rate;

} codec_state;


struct jitter_buffer *create_queue(int capacity);
int empty_queue(struct jitter_buffer *q);

int queue(struct jitter_buffer *q, RTPMessage *pk);
RTPMessage *dequeue(struct jitter_buffer *q, int *success);


int init_encoder(codec_state *cs);
int init_decoder(codec_state *cs);


#endif
