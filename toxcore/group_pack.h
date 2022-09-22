/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * Packer and unpacker functions for saving and loading groups.
 */

#ifndef GROUP_PACK_H
#define GROUP_PACK_H

#include <stdbool.h>

#include "bin_pack.h"
#include "bin_unpack.h"
#include "group_common.h"

/**
 * Packs group data from `chat` into `mp` in binary format. Parallel to the
 * `gc_load_unpack_group` function.
 */
non_null()
void gc_save_pack_group(const GC_Chat *chat, Bin_Pack *bp);

/**
 * Unpacks binary group data from `obj` into `chat`. Parallel to the `gc_save_pack_group`
 * function.
 *
 * Return true if unpacking is successful.
 */
non_null()
bool gc_load_unpack_group(GC_Chat *chat, Bin_Unpack *bu);

#endif // GROUP_PACK_H
