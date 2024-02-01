/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2024 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_FUZZING_FUZZ_TOX_H
#define C_TOXCORE_TESTING_FUZZING_FUZZ_TOX_H

#include <memory>

#include "../../toxcore/network.h"

constexpr uint16_t SIZE_IP_PORT = SIZE_IP6 + sizeof(uint16_t);

template <typename T>
using Ptr = std::unique_ptr<T, void (*)(T *)>;

#endif  // C_TOXCORE_TESTING_FUZZING_FUZZ_TOX_H
