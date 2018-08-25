/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
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
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef C_TOXCORE_TOXAV_GROUPAV_H
#define C_TOXCORE_TOXAV_GROUPAV_H

#include "../toxcore/group.h"
#include "../toxcore/tox.h"

/* Audio encoding/decoding */
#include <opus.h>

#define GROUP_AUDIO_PACKET_ID 192

// TODO(iphydf): Use this better typed one instead of the void-pointer one below.
// typedef void audio_data_cb(Tox *tox, uint32_t groupnumber, uint32_t peernumber, const int16_t *pcm,
//                            uint32_t samples, uint8_t channels, uint32_t sample_rate, void *userdata);
typedef void audio_data_cb(void *tox, uint32_t groupnumber, uint32_t peernumber, const int16_t *pcm,
                           uint32_t samples, uint8_t channels, uint32_t sample_rate, void *userdata);

/* Create a new toxav group.
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_av_groupchat(const Logger *log, Tox *tox, Group_Chats *g_c, audio_data_cb *audio_callback, void *userdata);

/* Join a AV group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 */
int join_av_groupchat(const Logger *log, Tox *tox, Group_Chats *g_c, uint32_t friendnumber, const uint8_t *data,
                      uint16_t length,
                      audio_data_cb *audio_callback, void *userdata);


/* Send audio to the group chat.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int group_send_audio(Group_Chats *g_c, uint32_t groupnumber, const int16_t *pcm, unsigned int samples, uint8_t channels,
                     uint32_t sample_rate);


#endif // C_TOXCORE_TOXAV_GROUPAV_H
