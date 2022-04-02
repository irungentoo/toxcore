#include "DHT.h"

#include <cstdlib>
#include <vector>

#include "../testing/fuzzing/fuzz_support.h"

namespace {

void TestHandleRequest(Fuzz_Data &input)
{
    CONSUME_OR_RETURN(const uint8_t *self_public_key, input, CRYPTO_PUBLIC_KEY_SIZE);
    CONSUME_OR_RETURN(const uint8_t *self_secret_key, input, CRYPTO_SECRET_KEY_SIZE);

    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t request[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t request_id;
    handle_request(
        self_public_key, self_secret_key, public_key, request, &request_id, input.data, input.size);
}

void TestUnpackNodes(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const bool tcp_enabled, input);

    const uint16_t node_count = 5;
    Node_format nodes[node_count];
    uint16_t processed_data_len;
    const int packed_count
        = unpack_nodes(nodes, node_count, &processed_data_len, input.data, input.size, tcp_enabled);
    if (packed_count > 0) {
        Logger *logger = logger_new();
        std::vector<uint8_t> packed(packed_count * PACKED_NODE_SIZE_IP6);
        const int packed_size
            = pack_nodes(logger, packed.data(), packed.size(), nodes, packed_count);
        LOGGER_ASSERT(logger, packed_size == processed_data_len,
            "packed size (%d) != unpacked size (%d)", packed_size, processed_data_len);
        logger_kill(logger);
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_select_target(data, size, TestHandleRequest, TestUnpackNodes);
    return 0;
}
