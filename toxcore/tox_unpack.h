/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_UNPACK_H
#define C_TOXCORE_TOXCORE_TOX_UNPACK_H

#include <stdbool.h>

#include "attributes.h"
#include "bin_unpack.h"
#include "tox.h"

bool tox_conference_type_unpack(Tox_Conference_Type *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_connection_unpack(Tox_Connection *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_file_control_unpack(Tox_File_Control *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_message_type_unpack(Tox_Message_Type *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_user_status_unpack(Tox_User_Status *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_group_privacy_state_unpack(Tox_Group_Privacy_State *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_group_voice_state_unpack(Tox_Group_Voice_State *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_group_topic_lock_unpack(Tox_Group_Topic_Lock *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_group_join_fail_unpack(Tox_Group_Join_Fail *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_group_mod_event_unpack(Tox_Group_Mod_Event *_Nonnull val, Bin_Unpack *_Nonnull bu);
bool tox_group_exit_type_unpack(Tox_Group_Exit_Type *_Nonnull val, Bin_Unpack *_Nonnull bu);

#endif /* C_TOXCORE_TOXCORE_TOX_UNPACK_H */
