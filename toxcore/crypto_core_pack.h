/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_CRYPTO_CORE_PACK_H
#define C_TOXCORE_TOXCORE_CRYPTO_CORE_PACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "crypto_core.h"

#ifdef __cplusplus
extern "C" {
#endif

bool pack_extended_public_key(const Extended_Public_Key *_Nonnull key, Bin_Pack *_Nonnull bp);
bool pack_extended_secret_key(const Extended_Secret_Key *_Nonnull key, Bin_Pack *_Nonnull bp);
bool unpack_extended_public_key(Extended_Public_Key *_Nonnull key, Bin_Unpack *_Nonnull bu);
bool unpack_extended_secret_key(Extended_Secret_Key *_Nonnull key, Bin_Unpack *_Nonnull bu);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_CRYPTO_CORE_PACK_H */
