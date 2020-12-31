#include "forwarding.h"

#include <cassert>
#include <memory>

#include "../testing/fuzzing/fuzz_support.h"
#include "../testing/fuzzing/fuzz_tox.h"

namespace {

void TestSendForwardRequest(Fuzz_Data &input)
{
    const Network *ns = system_network();  // TODO(iphydf): fuzz_network
    assert(ns != nullptr);

    with<Logger>{} >> with<Networking_Core>{input, ns} >> [&input](Ptr<Networking_Core> net) {
        with<IP_Port>{input} >> [net = std::move(net), &input](const IP_Port &forwarder) {
            CONSUME1_OR_RETURN(const uint16_t chain_length, input);
            const uint16_t chain_keys_size = chain_length * CRYPTO_PUBLIC_KEY_SIZE;
            CONSUME_OR_RETURN(const uint8_t *chain_keys, input, chain_keys_size);

            send_forward_request(
                net.get(), &forwarder, chain_keys, chain_length, input.data, input.size);
        };
    };
}

void TestForwardReply(Fuzz_Data &input)
{
    const Network *ns = system_network();  // TODO(iphydf): fuzz_network
    assert(ns != nullptr);

    with<Logger>{} >> with<Networking_Core>{input, ns} >> [&input](Ptr<Networking_Core> net) {
        with<IP_Port>{input} >> [net = std::move(net), &input](const IP_Port &forwarder) {
            CONSUME1_OR_RETURN(const uint16_t sendback_length, input);
            CONSUME_OR_RETURN(const uint8_t *sendback, input, sendback_length);

            forward_reply(net.get(), &forwarder, sendback, sendback_length, input.data, input.size);
        };
    };
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_select_target(data, size, TestSendForwardRequest, TestForwardReply);
    return 0;
}
