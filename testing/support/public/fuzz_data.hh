#ifndef C_TOXCORE_TESTING_SUPPORT_PUBLIC_FUZZ_DATA_H
#define C_TOXCORE_TESTING_SUPPORT_PUBLIC_FUZZ_DATA_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "../../../toxcore/attributes.h"

namespace tox::test {

struct Fuzz_Data {
    static constexpr bool FUZZ_DEBUG = false;
    static constexpr std::size_t TRACE_TRAP = -1;

private:
    const uint8_t *_Nonnull data_;
    const uint8_t *_Nonnull base_;
    std::size_t size_;

public:
    Fuzz_Data(const uint8_t *_Nonnull input_data, std::size_t input_size)
        : data_(input_data)
        , base_(input_data)
        , size_(input_size)
    {
    }

    Fuzz_Data &operator=(const Fuzz_Data &rhs) = delete;
    Fuzz_Data(const Fuzz_Data &rhs) = delete;

    struct Consumer {
        const char *_Nonnull func;
        Fuzz_Data &fd;

        operator bool()
        {
            if (fd.empty())
                return false;
            const bool val = fd.data_[0];
            if (FUZZ_DEBUG) {
                std::printf("consume@%zu(%s): bool %s\n", fd.pos(), func, val ? "true" : "false");
            }
            ++fd.data_;
            --fd.size_;
            return val;
        }

        template <typename T>
        operator T()
        {
            if (sizeof(T) > fd.size())
                return T{};
            const uint8_t *_Nonnull bytes = fd.consume(func, sizeof(T));
            T val;
            std::memcpy(&val, bytes, sizeof(T));
            return val;
        }
    };

    Consumer consume1(const char *_Nonnull func) { return Consumer{func, *this}; }

    template <typename T>
    T consume_integral()
    {
        return consume1("consume_integral");
    }

    template <typename T>
    T consume_integral_in_range(T min, T max)
    {
        if (min >= max)
            return min;
        T val = consume_integral<T>();
        return min + (val % (max - min + 1));
    }

    std::size_t remaining_bytes() const { return size(); }

    std::vector<uint8_t> consume_bytes(std::size_t count)
    {
        if (count == 0 || count > size_)
            return {};
        const uint8_t *_Nullable start = consume("consume_bytes", count);
        if (!start)
            return {};
        return std::vector<uint8_t>(start, start + count);
    }

    std::vector<uint8_t> consume_remaining_bytes()
    {
        if (empty())
            return {};
        std::size_t count = size();
        const uint8_t *_Nonnull start = consume("consume_remaining_bytes", count);
        return std::vector<uint8_t>(start, start + count);
    }

    std::size_t size() const { return size_; }
    std::size_t pos() const { return data_ - base_; }
    const uint8_t *_Nonnull data() const { return data_; }
    bool empty() const { return size_ == 0; }

    const uint8_t *_Nullable consume(const char *_Nonnull func, std::size_t count)
    {
        if (count > size_)
            return nullptr;
        const uint8_t *_Nonnull val = data_;
        if (FUZZ_DEBUG) {
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

#define CONSUME1_OR_RETURN(TYPE, NAME, INPUT) \
    if ((INPUT).size() < sizeof(TYPE)) {      \
        return;                               \
    }                                         \
    TYPE NAME = (INPUT).consume1(__func__)

#define CONSUME1_OR_RETURN_VAL(TYPE, NAME, INPUT, VAL) \
    if ((INPUT).size() < sizeof(TYPE)) {               \
        return (VAL);                                  \
    }                                                  \
    TYPE NAME = (INPUT).consume1(__func__)

#define CONSUME_OR_RETURN(DECL, INPUT, SIZE) \
    if ((INPUT).size() < (SIZE)) {           \
        return;                              \
    }                                        \
    DECL = (INPUT).consume(__func__, (SIZE))

#define CONSUME_OR_RETURN_VAL(DECL, INPUT, SIZE, VAL) \
    if ((INPUT).size() < (SIZE)) {                    \
        return (VAL);                                 \
    }                                                 \
    DECL = (INPUT).consume(__func__, (SIZE))

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
void fuzz_select_target(const uint8_t *_Nonnull data, std::size_t size)
{
    Fuzz_Data input{data, size};

    CONSUME1_OR_RETURN(const uint8_t, selector, input);
    return Fuzz_Target_Selector<Args...>::select(selector, input);
}

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_PUBLIC_FUZZ_DATA_H
