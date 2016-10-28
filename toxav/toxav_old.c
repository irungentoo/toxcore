/* toxav_old.h
 *
 * Copyright (C) 2013-2015 Tox project All Rights Reserved.
 *
 * This file is part of Tox.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox. If not, see <http://www.gnu.org/licenses/>.
 *
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
 *   audio_callback(Tox *tox, int groupnumber, int peernumber, const int16_t *pcm, unsigned int samples, uint8_t channels, unsigned int sample_rate, void *userdata)
 *
 * Note that total size of pcm in bytes is equal to (samples * channels * sizeof(int16_t)).
 */
int toxav_add_av_groupchat(struct Tox *tox, void (*audio_callback)(void *, int, int, const int16_t *, unsigned int,
                           uint8_t, unsigned int, void *), void *userdata)
{
    Messenger *m = (Messenger *)tox;
    return add_av_groupchat(m->log, (Group_Chats *)m->conferences_object,
                            (void (*)(Messenger *, int, int, const int16_t *, unsigned int, uint8_t, unsigned int, void *))audio_callback,
                            userdata);
}

/* Join a AV group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 *
 * Audio data callback format (same as the one for toxav_add_av_groupchat()):
 *   audio_callback(Tox *tox, int groupnumber, int peernumber, const int16_t *pcm, unsigned int samples, uint8_t channels, unsigned int sample_rate, void *userdata)
 *
 * Note that total size of pcm in bytes is equal to (samples * channels * sizeof(int16_t)).
 */
int toxav_join_av_groupchat(struct Tox *tox, int32_t friendnumber, const uint8_t *data, uint16_t length,
                            void (*audio_callback)(void *, int, int, const int16_t *, unsigned int, uint8_t, unsigned int, void *),
                            void *userdata)
{
    Messenger *m = (Messenger *)tox;
    return join_av_groupchat(m->log, (Group_Chats *)m->conferences_object, friendnumber, data, length,
                             (void (*)(Messenger *, int, int, const int16_t *, unsigned int, uint8_t, unsigned int, void *))audio_callback,
                             userdata);
}

/* Send audio to the group chat.
 *
 * return 0 on success.
 * return -1 on failure.
 *
 * Note that total size of pcm in bytes is equal to (samples * channels * sizeof(int16_t)).
 *
 * Valid number of samples are ((sample rate) * (audio length (Valid ones are: 2.5, 5, 10, 20, 40 or 60 ms)) / 1000)
 * Valid number of channels are 1 or 2.
 * Valid sample rates are 8000, 12000, 16000, 24000, or 48000.
 *
 * Recommended values are: samples = 960, channels = 1, sample_rate = 48000
 */
int toxav_group_send_audio(struct Tox *tox, int groupnumber, const int16_t *pcm, unsigned int samples, uint8_t channels,
                           unsigned int sample_rate)
{
    Messenger *m = (Messenger *)tox;
    return group_send_audio((Group_Chats *)m->conferences_object, groupnumber, pcm, samples, channels, sample_rate);
}
