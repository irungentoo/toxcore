#include "DHT.h"

#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "../testing/support/public/fuzz_data.hh"
#include "../testing/support/public/simulated_environment.hh"

namespace {

using tox::test::Fuzz_Data;
using tox::test::SimulatedEnvironment;

void TestHandleRequest(Fuzz_Data &input)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();

    CONSUME_OR_RETURN(const std::uint8_t *self_public_key, input, CRYPTO_PUBLIC_KEY_SIZE);
    CONSUME_OR_RETURN(const std::uint8_t *self_secret_key, input, CRYPTO_SECRET_KEY_SIZE);

    std::uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t request[MAX_CRYPTO_REQUEST_SIZE];
    std::uint8_t request_id;
    handle_request(&c_mem, self_public_key, self_secret_key, public_key, request, &request_id,
        input.data(), input.size());
}

void TestUnpackNodes(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const bool, tcp_enabled, input);

    const std::uint16_t node_count = 5;
    Node_format nodes[node_count];
    std::uint16_t processed_data_len;
    const int packed_count = unpack_nodes(
        nodes, node_count, &processed_data_len, input.data(), input.size(), tcp_enabled);
    if (packed_count > 0) {
        SimulatedEnvironment env{12345};
        auto c_mem = env.fake_memory().c_memory();
        Logger *logger = logger_new(&c_mem);
        std::vector<std::uint8_t> packed(packed_count * PACKED_NODE_SIZE_IP6);
        const int packed_size
            = pack_nodes(logger, packed.data(), packed.size(), nodes, packed_count);
        LOGGER_ASSERT(logger, packed_size == processed_data_len,
            "packed size (%d) != unpacked size (%d)", packed_size, processed_data_len);
        logger_kill(logger);

        // Check that packed nodes can be unpacked again and result in the
        // original unpacked nodes.
        Node_format nodes2[node_count];
        std::uint16_t processed_data_len2;
        const int packed_count2 = unpack_nodes(
            nodes2, node_count, &processed_data_len2, packed.data(), packed.size(), tcp_enabled);
        (void)packed_count2;
#if 0
        assert(processed_data_len2 == processed_data_len);
        assert(packed_count2 == packed_count);
#endif
        assert(std::memcmp(nodes, nodes2, sizeof(Node_format) * packed_count) == 0);
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    tox::test::fuzz_select_target<TestHandleRequest, TestUnpackNodes>(data, size);
    return 0;
}
