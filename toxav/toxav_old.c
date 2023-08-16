/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */

/**
 * This file contains the group chats code for the backwards compatibility.
 */
#include "toxav.h"

#include "../toxcore/tox_struct.h"
#include "groupav.h"

int toxav_add_av_groupchat(Tox *tox, audio_data_cb *audio_callback, void *userdata)
{
    return add_av_groupchat(tox->m->log, tox, tox->m->conferences_object, audio_callback, userdata);
}

int toxav_join_av_groupchat(Tox *tox, uint32_t friendnumber, const uint8_t *data, uint16_t length,
                            audio_data_cb *audio_callback, void *userdata)
{
    return join_av_groupchat(tox->m->log, tox, tox->m->conferences_object, friendnumber, data, length, audio_callback, userdata);
}

int toxav_group_send_audio(Tox *tox, uint32_t groupnumber, const int16_t *pcm, unsigned int samples, uint8_t channels,
                           uint32_t sample_rate)
{
    return group_send_audio(tox->m->conferences_object, groupnumber, pcm, samples, channels, sample_rate);
}

int toxav_groupchat_enable_av(Tox *tox, uint32_t groupnumber, audio_data_cb *audio_callback, void *userdata)
{
    return groupchat_enable_av(tox->m->log, tox, tox->m->conferences_object, groupnumber, audio_callback, userdata);
}

int toxav_groupchat_disable_av(Tox *tox, uint32_t groupnumber)
{
    return groupchat_disable_av(tox->m->conferences_object, groupnumber);
}

/** @brief Return whether A/V is enabled in the groupchat. */
bool toxav_groupchat_av_enabled(Tox *tox, uint32_t groupnumber)
{
    return groupchat_av_enabled(tox->m->conferences_object, groupnumber);
}
