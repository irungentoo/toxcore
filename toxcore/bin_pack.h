/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_BIN_PACK_H
#define C_TOXCORE_TOXCORE_BIN_PACK_H

#include <msgpack.h>
#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"

non_null() void bin_pack_array(msgpack_packer *mp, size_t size);
non_null() void bin_pack_bool(msgpack_packer *mp, bool val);
non_null() void bin_pack_u16(msgpack_packer *mp, uint16_t val);
non_null() void bin_pack_u32(msgpack_packer *mp, uint32_t val);
non_null() void bin_pack_u64(msgpack_packer *mp, uint64_t val);
non_null() void bin_pack_bytes(msgpack_packer *mp, const uint8_t *data, size_t length);

#endif // C_TOXCORE_TOXCORE_BIN_PACK_H
