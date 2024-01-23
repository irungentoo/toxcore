/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_AUDIO_H
#define C_TOXCORE_TOXAV_AUDIO_H

#include <opus.h>
#include <pthread.h>

#include "toxav.h"

#include "../toxcore/logger.h"
#include "../toxcore/util.h"
#include "rtp.h"

#define AUDIO_JITTERBUFFER_COUNT 3
#define AUDIO_MAX_SAMPLE_RATE 48000
#define AUDIO_MAX_CHANNEL_COUNT 2

#define AUDIO_START_SAMPLE_RATE 48000
#define AUDIO_START_BITRATE 48000
#define AUDIO_START_CHANNEL_COUNT 2
#define AUDIO_OPUS_PACKET_LOSS_PERC 10
#define AUDIO_OPUS_COMPLEXITY 10

#define AUDIO_DECODER_START_SAMPLE_RATE 48000
#define AUDIO_DECODER_START_CHANNEL_COUNT 1

#define AUDIO_MAX_FRAME_DURATION_MS 120

// ((sampling_rate_in_hz * frame_duration_in_ms) / 1000) * 2 // because PCM16 needs 2 bytes for 1 sample
// These are per frame and per channel.
#define AUDIO_MAX_BUFFER_SIZE_PCM16 ((AUDIO_MAX_SAMPLE_RATE * AUDIO_MAX_FRAME_DURATION_MS) / 1000)
#define AUDIO_MAX_BUFFER_SIZE_BYTES (AUDIO_MAX_BUFFER_SIZE_PCM16 * 2)

typedef struct ACSession {
    Mono_Time *mono_time;
    const Logger *log;

    /* encoding */
    OpusEncoder *encoder;
    uint32_t le_sample_rate; /* Last encoder sample rate */
    uint8_t le_channel_count; /* Last encoder channel count */
    uint32_t le_bit_rate; /* Last encoder bit rate */

    /* decoding */
    OpusDecoder *decoder;
    uint8_t lp_channel_count; /* Last packet channel count */
    uint32_t lp_sampling_rate; /* Last packet sample rate */
    uint32_t lp_frame_duration; /* Last packet frame duration */
    uint32_t ld_sample_rate; /* Last decoder sample rate */
    uint8_t ld_channel_count; /* Last decoder channel count */
    uint64_t ldrts; /* Last decoder reconfiguration time stamp */
    void *j_buf;

    pthread_mutex_t queue_mutex[1];

    ToxAV *av;
    uint32_t friend_number;
    /* Audio frame receive callback */
    toxav_audio_receive_frame_cb *acb;
    void *acb_user_data;
} ACSession;

ACSession *ac_new(Mono_Time *mono_time, const Logger *log, ToxAV *av, uint32_t friend_number,
                  toxav_audio_receive_frame_cb *cb, void *cb_data);
void ac_kill(ACSession *ac);
void ac_iterate(ACSession *ac);
int ac_queue_message(Mono_Time *mono_time, void *cs, struct RTPMessage *msg);
int ac_reconfigure_encoder(ACSession *ac, uint32_t bit_rate, uint32_t sampling_rate, uint8_t channels);

#endif /* C_TOXCORE_TOXAV_AUDIO_H */
