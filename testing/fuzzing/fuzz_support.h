/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2021-2022 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H
#define C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <utility>

#include "../../toxcore/tox.h"

struct Fuzz_Data {
    const uint8_t *data;
    std::size_t size;

    Fuzz_Data(const uint8_t *input_data, std::size_t input_size)
        : data(input_data), size(input_size)
    {}

    Fuzz_Data &operator=(const Fuzz_Data &rhs) = delete;
    Fuzz_Data(const Fuzz_Data &rhs) = delete;

    uint8_t consume1()
    {
        const uint8_t val = data[0];
        ++data;
        --size;
        return val;
    }

    const uint8_t *consume(std::size_t count)
    {
        const uint8_t *val = data;
        data += count;
        size -= count;
        return val;
    }
};

/** @brief Consumes 1 byte of the fuzzer input or returns if no data available.
 *
 * This advances the fuzzer input data by 1 byte and consumes that byte in the
 * declaration.
 *
 * @example
 * @code
 * CONSUME1_OR_RETURN(const uint8_t one_byte, input);
 * @endcode
 */
#define CONSUME1_OR_RETURN(DECL, INPUT) \
    if (INPUT.size < 1) {               \
        return;                         \
    }                                   \
    DECL = INPUT.consume1()

/** @brief Consumes SIZE bytes of the fuzzer input or returns if not enough data available.
 *
 * This advances the fuzzer input data by SIZE byte and consumes those bytes in
 * the declaration. If less than SIZE bytes are available in the fuzzer input,
 * this macro returns from the enclosing function.
 *
 * @example
 * @code
 * CONSUME_OR_RETURN(const uint8_t *ten_bytes, input, 10);
 * @endcode
 */
#define CONSUME_OR_RETURN(DECL, INPUT, SIZE) \
    if (INPUT.size < SIZE) {                 \
        return;                              \
    }                                        \
    DECL = INPUT.consume(SIZE)

inline void fuzz_select_target(uint8_t selector, Fuzz_Data &input)
{
    // The selector selected no function, so we do nothing and rely on the
    // fuzzer to come up with a better selector.
}

template <typename Arg, typename... Args>
void fuzz_select_target(uint8_t selector, Fuzz_Data &input, Arg &&fn, Args &&... args)
{
    if (selector == sizeof...(Args)) {
        return fn(input);
    }
    return fuzz_select_target(selector - 1, input, std::forward<Args>(args)...);
}

template <typename... Args>
void fuzz_select_target(const uint8_t *data, std::size_t size, Args &&... args)
{
    Fuzz_Data input{data, size};

    CONSUME1_OR_RETURN(uint8_t selector, input);
    return fuzz_select_target(selector, input, std::forward<Args>(args)...);
}

struct Network;
struct Random;

struct Fuzz_System {
    uint64_t clock;
    Fuzz_Data &data;
    std::unique_ptr<Tox_System> sys;
    std::unique_ptr<Network> ns;
    std::unique_ptr<Random> rng;

    Fuzz_System(Fuzz_Data &input);
    ~Fuzz_System();
};

#endif  // C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H
