#include "DHT.h"

#include <cstdlib>
#include <vector>

namespace {

void TestHandleRequest(const uint8_t *input_data, size_t input_size)
{
    const uint8_t *data = input_data;
    size_t size = input_size;

    const uint8_t *self_public_key = data;
    data += CRYPTO_PUBLIC_KEY_SIZE;
    size -= CRYPTO_PUBLIC_KEY_SIZE;

    const uint8_t *self_secret_key = data;
    data += CRYPTO_SECRET_KEY_SIZE;
    size -= CRYPTO_SECRET_KEY_SIZE;

    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t request[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t request_id;
    handle_request(self_public_key, self_secret_key, public_key, request, &request_id, data, size);
}

void TestUnpackNodes(const uint8_t *input_data, size_t input_size)
{
    const uint8_t *data = input_data;
    size_t size = input_size;

    if (size < 1) {
        return;
    }

    const bool tcp_enabled = data[0];
    ++data;
    --size;

    Node_format nodes[5];
    uint16_t processed_data_len;
    const int packed_count = unpack_nodes(nodes, 5, &processed_data_len, data, size, tcp_enabled);
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *input_data, size_t input_size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *input_data, size_t input_size)
{
    const uint8_t *data = input_data;
    size_t size = input_size;

    if (size < 1) {
        return 0;
    }

    const uint8_t func = data[0];
    ++data;
    --size;

    switch (func) {
    case 0:
        TestHandleRequest(data, size);
        return 0;
    case 1:
        TestUnpackNodes(data, size);
        return 0;
    default:
        return 0;
    }
}
