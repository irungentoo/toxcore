/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_AUDIO_H
#define C_TOXCORE_TOXAV_AUDIO_H

#include <stddef.h>
#include <stdint.h>

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

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

typedef void ac_audio_receive_frame_cb(uint32_t friend_number, const int16_t *_Nonnull pcm, size_t sample_count,
                                       uint8_t channels, uint32_t sampling_rate, void *_Nullable user_data);

typedef struct ACSession ACSession;

struct RTPMessage;

ACSession *_Nullable ac_new(Mono_Time *_Nonnull mono_time, const Logger *_Nonnull log, uint32_t friend_number,
                            ac_audio_receive_frame_cb *_Nullable cb, void *_Nullable user_data);
void ac_kill(ACSession *_Nullable ac);
void ac_iterate(ACSession *_Nullable ac);
int ac_queue_message(const Mono_Time *_Nonnull mono_time, void *_Nullable cs, struct RTPMessage *_Nullable msg);
int ac_reconfigure_encoder(ACSession *_Nullable ac, uint32_t bit_rate, uint32_t sampling_rate, uint8_t channels);

uint32_t ac_get_lp_frame_duration(const ACSession *_Nonnull ac);

int ac_encode(ACSession *_Nonnull ac, const int16_t *_Nonnull pcm, size_t sample_count, uint8_t *_Nonnull dest, size_t dest_max);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_AUDIO_H */
