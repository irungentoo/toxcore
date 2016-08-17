/**  audio.h
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

#ifndef AUDIO_H
#define AUDIO_H

#include <opus.h>
#include <pthread.h>

#include "toxav.h"

#include "../toxcore/util.h"

struct RTPMessage;

typedef struct ACSession_s {
    /* encoding */
    OpusEncoder *encoder;
    int32_t le_sample_rate; /* Last encoder sample rate */
    int32_t le_channel_count; /* Last encoder channel count */
    int32_t le_bit_rate; /* Last encoder bit rate */

    /* decoding */
    OpusDecoder *decoder;
    int32_t lp_channel_count; /* Last packet channel count */
    int32_t lp_sampling_rate; /* Last packet sample rate */
    int32_t lp_frame_duration; /* Last packet frame duration */
    int32_t ld_sample_rate; /* Last decoder sample rate */
    int32_t ld_channel_count; /* Last decoder channel count */
    uint64_t ldrts; /* Last decoder reconfiguration time stamp */
    void *j_buf;

    pthread_mutex_t queue_mutex[1];

    ToxAV *av;
    uint32_t friend_number;
    PAIR(toxav_audio_receive_frame_cb *, void *) acb; /* Audio frame receive callback */
} ACSession;

ACSession *ac_new(ToxAV *av, uint32_t friend_number, toxav_audio_receive_frame_cb *cb, void *cb_data);
void ac_kill(ACSession *ac);
void ac_iterate(ACSession *ac);
int ac_queue_message(void *acp, struct RTPMessage *msg);
int ac_reconfigure_encoder(ACSession *ac, int32_t bit_rate, int32_t sampling_rate, uint8_t channels);

#endif /* AUDIO_H */
