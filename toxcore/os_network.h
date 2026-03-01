/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_NETWORK_H
#define C_TOXCORE_TOXCORE_OS_NETWORK_H

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const Network os_network_obj;

const Network *_Nullable os_network(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_NETWORK_H */
