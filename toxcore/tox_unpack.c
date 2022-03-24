/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_unpack.h"

#include <stdint.h>

#include "bin_unpack.h"
#include "ccompat.h"

bool tox_unpack_conference_type(Bin_Unpack *bu, Tox_Conference_Type *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Conference_Type)u32;
    return true;
}

bool tox_unpack_connection(Bin_Unpack *bu, Tox_Connection *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Connection)u32;
    return true;
}

bool tox_unpack_file_control(Bin_Unpack *bu, Tox_File_Control *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_File_Control)u32;
    return true;
}

bool tox_unpack_message_type(Bin_Unpack *bu, Tox_Message_Type *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Message_Type)u32;
    return true;
}

bool tox_unpack_user_status(Bin_Unpack *bu, Tox_User_Status *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_User_Status)u32;
    return true;
}
