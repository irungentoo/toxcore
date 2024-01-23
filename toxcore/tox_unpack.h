/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_UNPACK_H
#define C_TOXCORE_TOXCORE_TOX_UNPACK_H

#include "attributes.h"
#include "bin_unpack.h"
#include "tox.h"

non_null() bool tox_conference_type_unpack(Tox_Conference_Type *val, Bin_Unpack *bu);
non_null() bool tox_connection_unpack(Tox_Connection *val, Bin_Unpack *bu);
non_null() bool tox_file_control_unpack(Tox_File_Control *val, Bin_Unpack *bu);
non_null() bool tox_message_type_unpack(Tox_Message_Type *val, Bin_Unpack *bu);
non_null() bool tox_user_status_unpack(Tox_User_Status *val, Bin_Unpack *bu);
non_null() bool tox_group_privacy_state_unpack(Tox_Group_Privacy_State *val, Bin_Unpack *bu);
non_null() bool tox_group_voice_state_unpack(Tox_Group_Voice_State *val, Bin_Unpack *bu);
non_null() bool tox_group_topic_lock_unpack(Tox_Group_Topic_Lock *val, Bin_Unpack *bu);
non_null() bool tox_group_join_fail_unpack(Tox_Group_Join_Fail *val, Bin_Unpack *bu);
non_null() bool tox_group_mod_event_unpack(Tox_Group_Mod_Event *val, Bin_Unpack *bu);
non_null() bool tox_group_exit_type_unpack(Tox_Group_Exit_Type *val, Bin_Unpack *bu);

#endif /* C_TOXCORE_TOXCORE_TOX_UNPACK_H */
