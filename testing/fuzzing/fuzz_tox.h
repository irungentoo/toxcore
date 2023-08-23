/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_FUZZING_FUZZ_TOX_H
#define C_TOXCORE_TESTING_FUZZING_FUZZ_TOX_H

#include <cassert>
#include <memory>

#include "../../toxcore/DHT.h"
#include "../../toxcore/logger.h"
#include "../../toxcore/network.h"
#include "fuzz_support.h"

constexpr uint16_t SIZE_IP_PORT = SIZE_IP6 + sizeof(uint16_t);

template <typename T>
using Ptr = std::unique_ptr<T, void (*)(T *)>;

/** @brief Construct any Tox resource using fuzzer input data.
 *
 * Constructs (or fails by returning) a valid object of type T and passes it to
 * a function specified on the rhs of `>>`. Takes care of cleaning up the
 * resource after the specified function returns.
 *
 * Some `with` instances require additional inputs such as the `Fuzz_Data`
 * reference or a logger.
 */
template <typename T>
struct with;

/** @brief Construct a Logger without logging callback.
 */
template <>
struct with<Logger> {
    template <typename F>
    void operator>>(F &&f)
    {
        Ptr<Logger> logger(logger_new(), logger_kill);
        assert(logger != nullptr);
        f(std::move(logger));
    }
};

/** @brief Construct an IP_Port by unpacking fuzzer input with `unpack_ip_port`.
 */
template <>
struct with<IP_Port> {
    Fuzz_Data &input_;

    template <typename F>
    void operator>>(F &&f)
    {
        CONSUME_OR_RETURN(const uint8_t *ipp_packed, input_, SIZE_IP_PORT);
        IP_Port ipp;
        unpack_ip_port(&ipp, ipp_packed, SIZE_IP6, true);

        f(ipp);
    }
};

/** @brief Construct a Networking_Core object using the Network vtable passed.
 *
 * Use `with<Logger>{} >> with<Networking_Core>{input, ns, mem} >> ...` to construct
 * a logger and pass it to the Networking_Core constructor function.
 */
template <>
struct with<Networking_Core> {
    Fuzz_Data &input_;
    const Network *ns_;
    const Memory *mem_;
    Ptr<Logger> logger_{nullptr, logger_kill};

    friend with operator>>(with<Logger> f, with self)
    {
        f >> [&self](Ptr<Logger> logger) { self.logger_ = std::move(logger); };
        return self;
    }

    template <typename F>
    void operator>>(F &&f)
    {
        with<IP_Port>{input_} >> [&f, this](const IP_Port &ipp) {
            Ptr<Networking_Core> net(
                new_networking_ex(logger_.get(), mem_, ns_, &ipp.ip, ipp.port, ipp.port + 100, nullptr),
                kill_networking);
            if (net == nullptr) {
                return;
            }
            f(std::move(net));
        };
    }
};

#endif  // C_TOXCORE_TESTING_FUZZING_FUZZ_TOX_H
