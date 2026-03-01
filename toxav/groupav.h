/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_GROUPAV_H
#define C_TOXCORE_TOXAV_GROUPAV_H

// Audio encoding/decoding
#include <opus.h>

#include "../toxcore/group.h"
#include "../toxcore/tox.h"

#define GROUP_AUDIO_PACKET_ID 192

// TODO(iphydf): Use this better typed one instead of the void-pointer one below.
// typedef void audio_data_cb(Tox *tox, uint32_t conference_number, uint32_t peer_number, const int16_t *pcm,
//                            uint32_t samples, uint8_t channels, uint32_t sample_rate, void *userdata);
typedef void audio_data_cb(void *_Nullable tox, Tox_Conference_Number conference_number, Tox_Conference_Peer_Number peer_number, const int16_t pcm[_Nullable],
                           uint32_t samples, uint8_t channels, uint32_t sample_rate, void *_Nullable userdata);

/** @brief Create and connect to a new toxav group.
 *
 * @return conference number on success.
 * @retval -1 on failure.
 */
int add_av_groupchat(const Logger *_Nonnull log, Tox *_Nonnull tox, Group_Chats *_Nonnull g_c, audio_data_cb *_Nullable audio_callback, void *_Nullable userdata);

/** @brief Join a AV group (you need to have been invited first).
 *
 * @return conference number on success
 * @retval -1 on failure.
 */
int join_av_groupchat(const Logger *_Nonnull log, Tox *_Nonnull tox, Group_Chats *_Nonnull g_c, Tox_Friend_Number friend_number, const uint8_t *_Nonnull data,
                      uint16_t length, audio_data_cb *_Nullable audio_callback, void *_Nullable userdata);

/** @brief Send audio to the conference.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int group_send_audio(const Group_Chats *_Nonnull g_c, Tox_Conference_Number conference_number, const int16_t pcm[_Nonnull], uint32_t samples,
                     uint8_t channels,
                     uint32_t sample_rate);

/** @brief Enable A/V in a conference.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int groupchat_enable_av(const Logger *_Nonnull log, Tox *_Nonnull tox, Group_Chats *_Nonnull g_c, Tox_Conference_Number conference_number,
                        audio_data_cb *_Nullable audio_callback, void *_Nullable userdata);

/** @brief Disable A/V in a conference.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int groupchat_disable_av(const Group_Chats *_Nonnull g_c, Tox_Conference_Number conference_number);

/** Return whether A/V is enabled in the conference. */
bool groupchat_av_enabled(const Group_Chats *_Nonnull g_c, Tox_Conference_Number conference_number);

#endif /* C_TOXCORE_TOXAV_GROUPAV_H */
