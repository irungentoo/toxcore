/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */
#include "rng.h"

void rng_bytes(const Random *rng, uint8_t *bytes, uint32_t length)
{
    rng->funcs->bytes_callback(rng->user_data, bytes, length);
}

uint32_t rng_uniform(const Random *rng, uint32_t upper_bound)
{
    return rng->funcs->uniform_callback(rng->user_data, upper_bound);
}

