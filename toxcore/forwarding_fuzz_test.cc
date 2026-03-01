#include "forwarding.h"

#include <cassert>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>

#include "../testing/support/public/fuzz_data.hh"
#include "../testing/support/public/fuzz_helpers.hh"
#include "../testing/support/public/simulated_environment.hh"

namespace {

using tox::test::configure_fuzz_memory_source;
using tox::test::Fuzz_Data;
using tox::test::SimulatedEnvironment;

constexpr std::uint16_t SIZE_IP_PORT = SIZE_IP6 + sizeof(std::uint16_t);

template <typename T>
using Ptr = std::unique_ptr<T, void (*)(T *)>;

std::optional<std::tuple<IP_Port, IP_Port, const std::uint8_t *, std::size_t>> prepare(
    Fuzz_Data &input)
{
    CONSUME_OR_RETURN_VAL(const std::uint8_t *ipp_packed, input, SIZE_IP_PORT, std::nullopt);
    IP_Port ipp{};
    unpack_ip_port(&ipp, ipp_packed, SIZE_IP6, true);

    CONSUME_OR_RETURN_VAL(const std::uint8_t *forwarder_packed, input, SIZE_IP_PORT, std::nullopt);
    IP_Port forwarder{};
    unpack_ip_port(&forwarder, forwarder_packed, SIZE_IP6, true);

    // 2 bytes: size of the request
    CONSUME_OR_RETURN_VAL(
        const std::uint8_t *data_size_bytes, input, sizeof(std::uint16_t), std::nullopt);
    std::uint16_t data_size;
    std::memcpy(&data_size, data_size_bytes, sizeof(std::uint16_t));

    // data bytes (max 64K)
    CONSUME_OR_RETURN_VAL(const std::uint8_t *data, input, data_size, std::nullopt);

    return {{ipp, forwarder, data, data_size}};
}

void TestSendForwardRequest(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const std::uint16_t, chain_length, input);
    const std::uint16_t chain_keys_size = chain_length * CRYPTO_PUBLIC_KEY_SIZE;
    CONSUME_OR_RETURN(const std::uint8_t *chain_keys, input, chain_keys_size);

    const auto prep = prepare(input);
    if (!prep.has_value()) {
        return;
    }
    const auto [ipp, forwarder, data, data_size] = prep.value();

    SimulatedEnvironment env{12345};
    auto node = env.create_node(ipp.port);
    configure_fuzz_memory_source(env.fake_memory(), input);

    const Ptr<Logger> logger(logger_new(&node->c_memory), logger_kill);
    if (logger == nullptr) {
        return;
    }

    const Ptr<Networking_Core> net(
        new_networking_ex(logger.get(), &node->c_memory, &node->c_network, &ipp.ip, ipp.port,
            ipp.port + 100, nullptr),
        kill_networking);
    if (net == nullptr) {
        return;
    }

    send_forward_request(net.get(), &forwarder, chain_keys, chain_length, data, data_size);
}

void TestForwardReply(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const std::uint16_t, sendback_length, input);
    CONSUME_OR_RETURN(const std::uint8_t *sendback, input, sendback_length);

    const auto prep = prepare(input);
    if (!prep.has_value()) {
        return;
    }
    const auto [ipp, forwarder, data, data_size] = prep.value();

    SimulatedEnvironment env{12345};
    auto node = env.create_node(ipp.port);
    configure_fuzz_memory_source(env.fake_memory(), input);

    const Ptr<Logger> logger(logger_new(&node->c_memory), logger_kill);
    if (logger == nullptr) {
        return;
    }

    const Ptr<Networking_Core> net(
        new_networking_ex(logger.get(), &node->c_memory, &node->c_network, &ipp.ip, ipp.port,
            ipp.port + 100, nullptr),
        kill_networking);
    if (net == nullptr) {
        return;
    }

    forward_reply(net.get(), &forwarder, sendback, sendback_length, data, data_size);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    tox::test::fuzz_select_target<TestSendForwardRequest, TestForwardReply>(data, size);
    return 0;
}
