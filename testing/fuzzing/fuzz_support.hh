/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2021-2022 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H
#define C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_private.h"

struct Fuzz_Data {
    static constexpr bool DEBUG = false;
    static constexpr std::size_t TRACE_TRAP = -1;  // 579;

private:
    const uint8_t *data_;
    const uint8_t *base_;
    std::size_t size_;

public:
    Fuzz_Data(const uint8_t *input_data, std::size_t input_size)
        : data_(input_data)
        , base_(input_data)
        , size_(input_size)
    {
    }

    Fuzz_Data &operator=(const Fuzz_Data &rhs) = delete;
    Fuzz_Data(const Fuzz_Data &rhs) = delete;

    struct Consumer {
        const char *func;
        Fuzz_Data &fd;

        operator bool()
        {
            // Special case because memcpy causes UB for bool (which can't be
            // anything other than 0 or 1).
            const bool val = fd.data_[0];
            if (DEBUG) {
                std::printf("consume@%zu(%s): bool %s\n", fd.pos(), func, val ? "true" : "false");
            }
            ++fd.data_;
            --fd.size_;
            return val;
        }

        template <typename T>
        operator T()
        {
            const uint8_t *bytes = fd.consume(func, sizeof(T));
            T val;
            std::memcpy(&val, bytes, sizeof(T));
            return val;
        }
    };

    Consumer consume1(const char *func) { return Consumer{func, *this}; }
    std::size_t size() const { return size_; }
    std::size_t pos() const { return data_ - base_; }
    const uint8_t *data() const { return data_; }
    bool empty() const { return size_ == 0; }

    const uint8_t *consume(const char *func, std::size_t count)
    {
        const uint8_t *val = data_;
        if (DEBUG) {
            if (pos() == TRACE_TRAP) {
                __asm__("int $3");
            }
            if (count == 1) {
                std::printf("consume@%zu(%s): %d (0x%02x)\n", pos(), func, val[0], val[0]);
            } else if (count != 0) {
                std::printf("consume@%zu(%s): %02x..%02x[%zu]\n", pos(), func, val[0],
                    val[count - 1], count);
            }
        }
        data_ += count;
        size_ -= count;
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
 * CONSUME1_OR_RETURN(const uint8_t, one_byte, input);
 * @endcode
 */
#define CONSUME1_OR_RETURN(TYPE, NAME, INPUT) \
    if (INPUT.size() < sizeof(TYPE)) {        \
        return;                               \
    }                                         \
    TYPE NAME = INPUT.consume1(__func__)

/** @brief Consumes 1 byte of the fuzzer input or returns a value if no data
 * available.
 *
 * This advances the fuzzer input data by 1 byte and consumes that byte in the
 * declaration.
 *
 * @example
 * @code
 * CONSUME1_OR_RETURN_VAL(const uint8_t one_byte, input, nullptr);
 * @endcode
 */
#define CONSUME1_OR_RETURN_VAL(TYPE, NAME, INPUT, VAL) \
    if (INPUT.size() < sizeof(TYPE)) {                 \
        return VAL;                                    \
    }                                                  \
    TYPE NAME = INPUT.consume1(__func__)

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
    if (INPUT.size() < SIZE) {               \
        return;                              \
    }                                        \
    DECL = INPUT.consume(__func__, SIZE)

#define CONSUME_OR_RETURN_VAL(DECL, INPUT, SIZE, VAL) \
    if (INPUT.size() < SIZE) {                        \
        return VAL;                                   \
    }                                                 \
    DECL = INPUT.consume(__func__, SIZE)

#define CONSUME_OR_ABORT(DECL, INPUT, SIZE) \
    if (INPUT.size() < SIZE) {              \
        abort();                            \
    }                                       \
    DECL = INPUT.consume(__func__, SIZE)

using Fuzz_Target = void (*)(Fuzz_Data &input);

template <Fuzz_Target... Args>
struct Fuzz_Target_Selector;

template <Fuzz_Target Arg, Fuzz_Target... Args>
struct Fuzz_Target_Selector<Arg, Args...> {
    static void select(uint8_t selector, Fuzz_Data &input)
    {
        if (selector == sizeof...(Args)) {
            return Arg(input);
        }
        return Fuzz_Target_Selector<Args...>::select(selector, input);
    }
};

template <>
struct Fuzz_Target_Selector<> {
    static void select(uint8_t selector, Fuzz_Data &input)
    {
        // The selector selected no function, so we do nothing and rely on the
        // fuzzer to come up with a better selector.
    }
};

template <Fuzz_Target... Args>
void fuzz_select_target(const uint8_t *data, std::size_t size)
{
    Fuzz_Data input{data, size};

    CONSUME1_OR_RETURN(const uint8_t, selector, input);
    return Fuzz_Target_Selector<Args...>::select(selector, input);
}

struct Memory;
struct Network;
struct Random;

struct System {
    /** @brief Deterministic system clock for this instance.
     *
     * Different instances can evolve independently. The time is initialised
     * with a large number, because otherwise many zero-initialised "empty"
     * friends inside toxcore will be "not timed out" for a long time, messing
     * up some logic. Tox moderately depends on the clock being fairly high up
     * (not close to 0).
     *
     * We make it a nice large round number so we can recognise it when debugging.
     */
    uint64_t clock = 1000000000;

    std::unique_ptr<Tox_System> sys;
    std::unique_ptr<Memory> mem;
    std::unique_ptr<Network> ns;
    std::unique_ptr<Random> rng;

    System(std::unique_ptr<Tox_System> sys, std::unique_ptr<Memory> mem,
        std::unique_ptr<Network> ns, std::unique_ptr<Random> rng);
    System(System &&);

    // Not inline because sizeof of the above 2 structs is not known everywhere.
    ~System();

    /**
     * During bootstrap, move the time forward a decent amount, because friend
     * finding and bootstrapping takes significant (around 10 seconds) wall
     * clock time that should be advanced more quickly in the test.
     */
    static constexpr uint8_t BOOTSTRAP_ITERATION_INTERVAL = 200;
    /**
     * Less than BOOTSTRAP_ITERATION_INTERVAL because otherwise we'll spam
     * onion announce packets.
     */
    static constexpr uint8_t MESSAGE_ITERATION_INTERVAL = 20;
    /**
     * Move the clock forward at least 20ms so at least some amount of
     * time passes on each iteration.
     */
    static constexpr uint8_t MIN_ITERATION_INTERVAL = 20;
};

/**
 * A Tox_System implementation that consumes fuzzer input to produce network
 * inputs and random numbers. Once it runs out of fuzzer input, network receive
 * functions return no more data and the random numbers are always zero.
 */
struct Fuzz_System : System {
    Fuzz_Data &data;

    explicit Fuzz_System(Fuzz_Data &input);
};

/**
 * A Tox_System implementation that consumes no fuzzer input but still has a
 * working and deterministic RNG. Network receive functions always fail, send
 * always succeeds.
 */
struct Null_System : System {
    uint64_t seed = 4;  // chosen by fair dice roll. guaranteed to be random.

    Null_System();
};

/**
 * A Tox_System implementation that records all I/O but does not actually
 * perform any real I/O. Everything inside this system is hermetic in-process
 * and fully deterministic.
 *
 * Note: take care not to initialise two systems with the same seed, since
 * that's the only thing distinguishing the system's behaviour. Two toxes
 * initialised with the same seed will be identical (same keys, etc.).
 */
struct Record_System : System {
    static constexpr bool DEBUG = Fuzz_Data::DEBUG;

    /** @brief State shared between all tox instances. */
    struct Global {
        /** @brief Bound UDP ports and their system instance.
         *
         * This implements an in-process network where instances can send
         * packets to other instances by inserting them into the receiver's
         * recvq using the receive function.
         *
         * We need to keep track of ports associated with recv queues because
         * toxcore sends packets to itself sometimes when doing onion routing
         * with only 2 nodes in the network.
         */
        std::unordered_map<uint16_t, Record_System *> bound;
    };

    Global &global_;
    uint64_t seed_;  //!< Current PRNG state.
    const char *name_;  //!< Tox system name ("tox1"/"tox2") for logging.

    std::deque<std::pair<uint16_t, std::vector<uint8_t>>> recvq;
    uint16_t port = 0;  //!< Sending port for this system instance.

    Record_System(Global &global, uint64_t seed, const char *name);
    Record_System(const Record_System &) = delete;
    Record_System operator=(const Record_System &) = delete;

    /** @brief Deposit a network packet in this instance's recvq.
     */
    void receive(uint16_t send_port, const uint8_t *buf, size_t len);

    void push(bool byte)
    {
        if (DEBUG) {
            if (recording_.size() == Fuzz_Data::TRACE_TRAP) {
                __asm__("int $3");
            }
            std::printf(
                "%s: produce@%zu(bool %s)\n", name_, recording_.size(), byte ? "true" : "false");
        }
        recording_.push_back(byte);
    }

    void push(uint8_t byte)
    {
        if (DEBUG) {
            if (recording_.size() == Fuzz_Data::TRACE_TRAP) {
                __asm__("int $3");
            }
            std::printf("%s: produce@%zu(%u (0x%02x))\n", name_, recording_.size(), byte, byte);
        }
        recording_.push_back(byte);
    }

    void push(const uint8_t *bytes, std::size_t size)
    {
        if (DEBUG) {
            if (recording_.size() == Fuzz_Data::TRACE_TRAP) {
                __asm__("int $3");
            }
            std::printf("%s: produce@%zu(%02x..%02x[%zu])\n", name_, recording_.size(), bytes[0],
                bytes[size - 1], size);
        }
        recording_.insert(recording_.end(), bytes, bytes + size);
    }

    template <std::size_t N>
    void push(const char (&bytes)[N])
    {
        push(reinterpret_cast<const uint8_t *>(bytes), N - 1);
    }

    const std::vector<uint8_t> &recording() const { return recording_; }
    std::vector<uint8_t> take_recording() const { return std::move(recording_); }

private:
    std::vector<uint8_t> recording_;
};

/** @brief Enable debug logging.
 *
 * This should not be enabled in fuzzer code while fuzzing, as console I/O slows
 * everything down drastically. It's useful while developing the fuzzer and the
 * protodump program.
 */
extern const bool DEBUG;

inline constexpr char tox_log_level_name(Tox_Log_Level level)
{
    switch (level) {
    case TOX_LOG_LEVEL_TRACE:
        return 'T';
    case TOX_LOG_LEVEL_DEBUG:
        return 'D';
    case TOX_LOG_LEVEL_INFO:
        return 'I';
    case TOX_LOG_LEVEL_WARNING:
        return 'W';
    case TOX_LOG_LEVEL_ERROR:
        return 'E';
    }

    return '?';
}

#endif  // C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H
