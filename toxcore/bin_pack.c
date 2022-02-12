/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "bin_pack.h"

#include <msgpack.h>

void bin_pack_array(msgpack_packer *mp, size_t size)
{
    msgpack_pack_array(mp, size);
}

void bin_pack_bool(msgpack_packer *mp, bool val)
{
    if (val) {
        msgpack_pack_true(mp);
    } else {
        msgpack_pack_false(mp);
    }
}

void bin_pack_u16(msgpack_packer *mp, uint16_t val)
{
    msgpack_pack_uint16(mp, val);
}

void bin_pack_u32(msgpack_packer *mp, uint32_t val)
{
    msgpack_pack_uint32(mp, val);
}

void bin_pack_u64(msgpack_packer *mp, uint64_t val)
{
    msgpack_pack_uint64(mp, val);
}

void bin_pack_bytes(msgpack_packer *mp, const uint8_t *data, size_t length)
{
    msgpack_pack_bin(mp, length);
    msgpack_pack_bin_body(mp, data, length);
}
