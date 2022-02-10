/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_BIN_UNPACK_H
#define C_TOXCORE_TOXCORE_BIN_UNPACK_H

#include <msgpack.h>
#include <stdint.h>

#include "attributes.h"

non_null() bool bin_unpack_bool(bool *val, const msgpack_object *obj);
non_null() bool bin_unpack_u16(uint16_t *val, const msgpack_object *obj);
non_null() bool bin_unpack_u32(uint32_t *val, const msgpack_object *obj);
non_null() bool bin_unpack_u64(uint64_t *val, const msgpack_object *obj);
non_null() bool bin_unpack_bytes(uint8_t **data, size_t *data_length, const msgpack_object *obj);
non_null() bool bin_unpack_bytes_fixed(uint8_t *data, uint32_t data_length, const msgpack_object *obj);

#endif  // C_TOXCORE_TOXCORE_BIN_UNPACK_H
