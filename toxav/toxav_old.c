/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */

/**
 * This file contains the group chats code for the backwards compatibility.
 */

#include "toxav.h"

#include "groupav.h"

/* Create a new toxav group.
 *
 * return group number on success.
 * return -1 on failure.
 *
 * Audio data callback format:
 *   `audio_callback(Tox *tox, int groupnumber, int peernumber, const int16_t *pcm, unsigned int samples, uint8_t channels, unsigned int sample_rate, void *userdata)`
 *
 * Note that total size of pcm in bytes is equal to `(samples * channels * sizeof(int16_t))`.
 */
int toxav_add_av_groupchat(Tox *tox, audio_data_cb *audio_callback, void *userdata)
{
    // TODO(iphydf): Don't rely on toxcore internals.
    //!TOKSTYLE-
    Messenger *m = *(Messenger **)tox;
    //!TOKSTYLE+
    return add_av_groupchat(m->log, tox, m->conferences_object, audio_callback, userdata);
}

/* Join a AV group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 *
 * Audio data callback format (same as the one for `toxav_add_av_groupchat()`):
 *   `audio_callback(Tox *tox, int groupnumber, int peernumber, const int16_t *pcm, unsigned int samples, uint8_t channels, unsigned int sample_rate, void *userdata)`
 *
 * Note that total size of pcm in bytes is equal to `(samples * channels * sizeof(int16_t))`.
 */
int toxav_join_av_groupchat(Tox *tox, uint32_t friendnumber, const uint8_t *data, uint16_t length,
                            audio_data_cb *audio_callback, void *userdata)
{
    // TODO(iphydf): Don't rely on toxcore internals.
    //!TOKSTYLE-
    Messenger *m = *(Messenger **)tox;
    //!TOKSTYLE+
    return join_av_groupchat(m->log, tox, m->conferences_object, friendnumber, data, length, audio_callback, userdata);
}

/* Send audio to the group chat.
 *
 * return 0 on success.
 * return -1 on failure.
 *
 * Note that total size of pcm in bytes is equal to `(samples * channels * sizeof(int16_t))`.
 *
 * Valid number of samples are `((sample rate) * (audio length) / 1000)` (Valid values for audio length: 2.5, 5, 10, 20, 40 or 60 ms)
 * Valid number of channels are 1 or 2.
 * Valid sample rates are 8000, 12000, 16000, 24000, or 48000.
 *
 * Recommended values are: samples = 960, channels = 1, sample_rate = 48000
 */
int toxav_group_send_audio(Tox *tox, uint32_t groupnumber, const int16_t *pcm, unsigned int samples, uint8_t channels,
                           uint32_t sample_rate)
{
    // TODO(iphydf): Don't rely on toxcore internals.
    //!TOKSTYLE-
    Messenger *m = *(Messenger **)tox;
    //!TOKSTYLE+
    return group_send_audio(m->conferences_object, groupnumber, pcm, samples, channels, sample_rate);
}

/* Enable A/V in a groupchat.
 *
 * A/V must be enabled on a groupchat for audio to be sent to it and for
 * received audio to be handled.
 *
 * An A/V group created with toxav_add_av_groupchat or toxav_join_av_groupchat
 * will start with A/V enabled.
 *
 * An A/V group loaded from a savefile will start with A/V disabled.
 *
 * return 0 on success.
 * return -1 on failure.
 *
 * Audio data callback format (same as the one for toxav_add_av_groupchat()):
 *   `audio_callback(Tox *tox, uint32_t groupnumber, uint32_t peernumber, const int16_t *pcm, unsigned int samples, uint8_t channels, uint32_t sample_rate, void *userdata)`
 *
 * Note that total size of pcm in bytes is equal to `(samples * channels * sizeof(int16_t))`.
 */
int toxav_groupchat_enable_av(Tox *tox, uint32_t groupnumber, audio_data_cb *audio_callback, void *userdata)
{
    // TODO(iphydf): Don't rely on toxcore internals.
    //!TOKSTYLE-
    Messenger *m = *(Messenger **)tox;
    //!TOKSTYLE+
    return groupchat_enable_av(m->log, tox, m->conferences_object, groupnumber, audio_callback, userdata);
}

/* Disable A/V in a groupchat.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int toxav_groupchat_disable_av(Tox *tox, uint32_t groupnumber)
{
    // TODO(iphydf): Don't rely on toxcore internals.
    //!TOKSTYLE-
    Messenger *m = *(Messenger **)tox;
    //!TOKSTYLE+
    return groupchat_disable_av(m->conferences_object, groupnumber);
}

/* Return whether A/V is enabled in the groupchat.
 */
bool toxav_groupchat_av_enabled(Tox *tox, uint32_t groupnumber)
{
    // TODO(iphydf): Don't rely on toxcore internals.
    //!TOKSTYLE-
    Messenger *m = *(Messenger **)tox;
    //!TOKSTYLE+
    return groupchat_av_enabled(m->conferences_object, groupnumber);
}
