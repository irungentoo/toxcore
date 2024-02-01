#include "forwarding.h"

#include <cassert>
#include <cstring>
#include <memory>
#include <optional>

#include "../testing/fuzzing/fuzz_support.hh"
#include "../testing/fuzzing/fuzz_tox.hh"

namespace {

std::optional<std::tuple<IP_Port, IP_Port, const uint8_t *, size_t>> prepare(Fuzz_Data &input)
{
    CONSUME_OR_RETURN_VAL(const uint8_t *ipp_packed, input, SIZE_IP_PORT, std::nullopt);
    IP_Port ipp;
    unpack_ip_port(&ipp, ipp_packed, SIZE_IP6, true);

    CONSUME_OR_RETURN_VAL(const uint8_t *forwarder_packed, input, SIZE_IP_PORT, std::nullopt);
    IP_Port forwarder;
    unpack_ip_port(&forwarder, forwarder_packed, SIZE_IP6, true);

    // 2 bytes: size of the request
    CONSUME_OR_RETURN_VAL(const uint8_t *data_size_bytes, input, sizeof(uint16_t), std::nullopt);
    uint16_t data_size;
    std::memcpy(&data_size, data_size_bytes, sizeof(uint16_t));

    // data bytes (max 64K)
    CONSUME_OR_RETURN_VAL(const uint8_t *data, input, data_size, std::nullopt);

    return {{ipp, forwarder, data, data_size}};
}

void TestSendForwardRequest(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const uint16_t, chain_length, input);
    const uint16_t chain_keys_size = chain_length * CRYPTO_PUBLIC_KEY_SIZE;
    CONSUME_OR_RETURN(const uint8_t *chain_keys, input, chain_keys_size);

    auto prep = prepare(input);
    if (!prep.has_value()) {
        return;
    }
    auto [ipp, forwarder, data, data_size] = prep.value();

    // rest of the fuzz data is input for malloc and network
    Fuzz_System sys(input);

    Ptr<Logger> logger(logger_new(), logger_kill);

    Ptr<Networking_Core> net(new_networking_ex(logger.get(), sys.mem.get(), sys.ns.get(), &ipp.ip,
                                 ipp.port, ipp.port + 100, nullptr),
        kill_networking);
    if (net == nullptr) {
        return;
    }

    send_forward_request(net.get(), &forwarder, chain_keys, chain_length, data, data_size);
}

void TestForwardReply(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const uint16_t, sendback_length, input);
    CONSUME_OR_RETURN(const uint8_t *sendback, input, sendback_length);

    auto prep = prepare(input);
    if (!prep.has_value()) {
        return;
    }
    auto [ipp, forwarder, data, data_size] = prep.value();

    // rest of the fuzz data is input for malloc and network
    Fuzz_System sys(input);

    Ptr<Logger> logger(logger_new(), logger_kill);

    Ptr<Networking_Core> net(new_networking_ex(logger.get(), sys.mem.get(), sys.ns.get(), &ipp.ip,
                                 ipp.port, ipp.port + 100, nullptr),
        kill_networking);
    if (net == nullptr) {
        return;
    }

    forward_reply(net.get(), &forwarder, sendback, sendback_length, data, data_size);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_select_target<TestSendForwardRequest, TestForwardReply>(data, size);
    return 0;
}
