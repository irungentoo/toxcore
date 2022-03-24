/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_UNPACK_H
#define C_TOXCORE_TOXCORE_TOX_UNPACK_H

#include "attributes.h"
#include "bin_unpack.h"
#include "tox.h"

non_null() bool tox_unpack_conference_type(Bin_Unpack *bu, Tox_Conference_Type *val);
non_null() bool tox_unpack_connection(Bin_Unpack *bu, Tox_Connection *val);
non_null() bool tox_unpack_file_control(Bin_Unpack *bu, Tox_File_Control *val);
non_null() bool tox_unpack_message_type(Bin_Unpack *bu, Tox_Message_Type *val);
non_null() bool tox_unpack_user_status(Bin_Unpack *bu, Tox_User_Status *val);

#endif  // C_TOXCORE_TOXCORE_TOX_UNPACK_H
