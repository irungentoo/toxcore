/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_unpack.h"

#include <msgpack.h>
#include <stdint.h>

#include "bin_unpack.h"
#include "ccompat.h"

bool tox_unpack_conference_type(Tox_Conference_Type *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!bin_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_Conference_Type)u32;
    return true;
}

bool tox_unpack_connection(Tox_Connection *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!bin_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_Connection)u32;
    return true;
}

bool tox_unpack_file_control(Tox_File_Control *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!bin_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_File_Control)u32;
    return true;
}

bool tox_unpack_message_type(Tox_Message_Type *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!bin_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_Message_Type)u32;
    return true;
}

bool tox_unpack_user_status(Tox_User_Status *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!bin_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_User_Status)u32;
    return true;
}
