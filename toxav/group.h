/**  groupav.c
 *
 *   Copyright (C) 2014 Tox project All Rights Reserved.
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
 */

/* Audio encoding/decoding */
#include <opus.h>

#include "../toxcore/group.h"

#define GROUP_AUDIO_PACKET_ID 192

/* Create a new toxav group.
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_av_groupchat(Group_Chats *g_c, void (*audio_callback)(Messenger *, int, int, const int16_t *, unsigned int,
                     uint8_t, unsigned int, void *), void *userdata);

/* Join a AV group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 */
int join_av_groupchat(Group_Chats *g_c, int32_t friendnumber, const uint8_t *data, uint16_t length,
                      void (*audio_callback)(Messenger *, int, int, const int16_t *, unsigned int, uint8_t, unsigned int, void *),
                      void *userdata);


/* Send audio to the group chat.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int group_send_audio(Group_Chats *g_c, int groupnumber, const int16_t *pcm, unsigned int samples, uint8_t channels,
                     unsigned int sample_rate);

