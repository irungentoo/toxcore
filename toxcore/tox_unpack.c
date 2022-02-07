/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_unpack.h"

#include <msgpack.h>

#include "ccompat.h"

bool tox_unpack_bool(bool *val, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_BOOLEAN) {
        return false;
    }

    *val = obj->via.boolean;
    return true;
}

bool tox_unpack_u16(uint16_t *val, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_POSITIVE_INTEGER || obj->via.u64 > UINT16_MAX) {
        return false;
    }

    *val = (uint16_t)obj->via.u64;
    return true;
}

bool tox_unpack_u32(uint32_t *val, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_POSITIVE_INTEGER || obj->via.u64 > UINT32_MAX) {
        return false;
    }

    *val = (uint32_t)obj->via.u64;
    return true;
}

bool tox_unpack_u64(uint64_t *val, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        return false;
    }

    *val = obj->via.u64;
    return true;
}

bool tox_unpack_bin(uint8_t **data_ptr, size_t *data_length_ptr, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_BIN) {
        return false;
    }

    const uint32_t data_length = obj->via.bin.size;
    uint8_t *const data = (uint8_t *)malloc(data_length);

    if (data == nullptr) {
        return false;
    }

    memcpy(data, obj->via.bin.ptr, data_length);

    *data_ptr = data;
    *data_length_ptr = data_length;
    return true;
}

bool tox_unpack_bin_fixed(uint8_t *data, uint32_t data_length, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_BIN || obj->via.bin.size != data_length) {
        return false;
    }

    memcpy(data, obj->via.bin.ptr, data_length);

    return true;
}

bool tox_unpack_conference_type(Tox_Conference_Type *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!tox_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_Conference_Type)u32;
    return true;
}

bool tox_unpack_connection(Tox_Connection *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!tox_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_Connection)u32;
    return true;
}

bool tox_unpack_file_control(Tox_File_Control *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!tox_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_File_Control)u32;
    return true;
}

bool tox_unpack_message_type(Tox_Message_Type *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!tox_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_Message_Type)u32;
    return true;
}

bool tox_unpack_user_status(Tox_User_Status *val, const msgpack_object *obj)
{
    uint32_t u32;

    if (!tox_unpack_u32(&u32, obj)) {
        return false;
    }

    *val = (Tox_User_Status)u32;
    return true;
}
