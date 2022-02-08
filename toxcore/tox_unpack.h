/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_UNPACK_H
#define C_TOXCORE_TOXCORE_TOX_UNPACK_H

#include <msgpack.h>
#include <stdint.h>

#include "attributes.h"
#include "tox.h"

non_null() bool tox_unpack_bool(bool *val, const msgpack_object *obj);
non_null() bool tox_unpack_u16(uint16_t *val, const msgpack_object *obj);
non_null() bool tox_unpack_u32(uint32_t *val, const msgpack_object *obj);
non_null() bool tox_unpack_u64(uint64_t *val, const msgpack_object *obj);
non_null() bool tox_unpack_bin(uint8_t **data, size_t *data_length, const msgpack_object *obj);
non_null() bool tox_unpack_bin_fixed(uint8_t *data, uint32_t data_length, const msgpack_object *obj);

non_null() bool tox_unpack_conference_type(Tox_Conference_Type *val, const msgpack_object *obj);
non_null() bool tox_unpack_connection(Tox_Connection *val, const msgpack_object *obj);
non_null() bool tox_unpack_file_control(Tox_File_Control *val, const msgpack_object *obj);
non_null() bool tox_unpack_message_type(Tox_Message_Type *val, const msgpack_object *obj);
non_null() bool tox_unpack_user_status(Tox_User_Status *val, const msgpack_object *obj);

#endif  // C_TOXCORE_TOXCORE_TOX_UNPACK_H
