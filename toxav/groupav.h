/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
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

/* Create and connect to a new toxav group.
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

/* Enable A/V in a groupchat.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int groupchat_enable_av(const Logger *log, Tox *tox, Group_Chats *g_c, uint32_t groupnumber,
                        audio_data_cb *audio_callback, void *userdata);

/* Disable A/V in a groupchat.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int groupchat_disable_av(Group_Chats *g_c, uint32_t groupnumber);

/* Return whether A/V is enabled in the groupchat.
 */
bool groupchat_av_enabled(Group_Chats *g_c, uint32_t groupnumber);

#endif // C_TOXCORE_TOXAV_GROUPAV_H
