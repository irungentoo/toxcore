/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */
#include "ccompat.h"

static_assert(sizeof(int) >= 4, "toxcore does not support 16-bit platforms");
