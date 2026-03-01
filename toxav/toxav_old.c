/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */

/**
 * This file contains the group chats code for the backwards compatibility.
 */
#include "toxav.h"

#include "../toxcore/attributes.h"
#include "../toxcore/tox_struct.h"
#include "groupav.h"

int32_t toxav_add_av_groupchat(Tox *_Nonnull tox, toxav_audio_data_cb *_Nullable audio_callback, void *_Nullable userdata)
{
    return add_av_groupchat(tox->m->log, tox, tox->m->conferences_object, (audio_data_cb *)audio_callback, userdata);
}

int32_t toxav_join_av_groupchat(Tox *_Nonnull tox, Tox_Friend_Number friend_number, const uint8_t *_Nonnull data, uint16_t length,
                                toxav_audio_data_cb *_Nullable audio_callback, void *_Nullable userdata)
{
    return join_av_groupchat(tox->m->log, tox, tox->m->conferences_object, friend_number, data, length,
                             (audio_data_cb *)audio_callback, userdata);
}

int32_t toxav_group_send_audio(Tox *_Nonnull tox, Tox_Conference_Number conference_number, const int16_t *_Nonnull pcm, uint32_t samples,
                               uint8_t channels,
                               uint32_t sample_rate)
{
    return group_send_audio(tox->m->conferences_object, conference_number, pcm, samples, channels, sample_rate);
}

int32_t toxav_groupchat_enable_av(Tox *_Nonnull tox, Tox_Conference_Number conference_number, toxav_audio_data_cb *_Nullable audio_callback,
                                  void *_Nullable userdata)
{
    return groupchat_enable_av(tox->m->log, tox, tox->m->conferences_object, conference_number, (audio_data_cb *)audio_callback,
                               userdata);
}

int32_t toxav_groupchat_disable_av(Tox *_Nonnull tox, Tox_Conference_Number conference_number)
{
    return groupchat_disable_av(tox->m->conferences_object, conference_number);
}

/** @brief Return whether A/V is enabled in the groupchat. */
bool toxav_groupchat_av_enabled(Tox *_Nonnull tox, Tox_Conference_Number conference_number)
{
    return groupchat_av_enabled(tox->m->conferences_object, conference_number);
}
