#include "../public/fuzz_helpers.hh"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <vector>

namespace tox::test {

void configure_fuzz_packet_source(FakeUdpSocket &socket, Fuzz_Data &input)
{
    socket.set_packet_source([&input](std::vector<uint8_t> &data, IP_Port &from) -> bool {
        if (input.size() < 2)
            return false;

        const uint8_t *len_bytes = input.consume("recv_len", 2);
        if (!len_bytes)
            return false;

        uint16_t len = (len_bytes[0] << 8) | len_bytes[1];

        if (len == 0xffff) {
            // EWOULDBLOCK simulation. Return false implies "no packet".
            return false;
        }

        std::size_t actual_len = std::min(static_cast<std::size_t>(len), input.size());
        const uint8_t *payload = input.consume("recv_payload", actual_len);

        if (!payload && actual_len > 0)
            return false;

        data.assign(payload, payload + actual_len);

        // Dummy address (legacy Fuzz_System used 127.0.0.2:33446)
        ip_init(&from.ip, false);  // IPv4
        from.ip.ip.v4.uint32 = net_htonl(0x7F000002);  // 127.0.0.2
        from.port = net_htons(33446);

        return true;
    });
}

void configure_fuzz_memory_source(FakeMemory &memory, Fuzz_Data &input)
{
    memory.set_failure_injector([&input](std::size_t size) -> bool {
        if (input.size() < 1) {
            // Legacy behavior: if input runs out, allocation succeeds.
            return false;
        }

        const uint8_t *b = input.consume("malloc_decision", 1);
        bool succeed = (b && *b);
        return !succeed;  // Return true to fail
    });
}

void configure_fuzz_random_source(FakeRandom &random, Fuzz_Data &input)
{
    random.set_entropy_source([&input](uint8_t *_Nonnull out, std::size_t count) {
        // Initialize with zeros in case of underflow
        std::memset(out, 0, count);

        // For small types (keys, nonces), behave like legacy fuzz support
        if (count == 1 || count == 2 || count == 4 || count == 8) {
            if (input.size() >= count) {
                const uint8_t *bytes = input.consume("rnd_bytes", count);
                std::memcpy(out, bytes, count);
            }
            return;
        }

        // For large chunks, repeat available data
        if (count == 24 || count == 32) {
            std::size_t available = std::min(input.size(), static_cast<std::size_t>(2));
            if (available > 0) {
                const uint8_t *chunk = input.consume("rnd_chunk", available);
                if (available == 2) {
                    std::memset(out, chunk[0], count / 2);
                    std::memset(out + count / 2, chunk[1], count / 2);
                } else {
                    std::memset(out, chunk[0], count);
                }
            }
            return;
        }

        // Fallback for other sizes: consume as much as possible
        std::size_t taken = std::min(input.size(), count);
        if (taken > 0) {
            const uint8_t *bytes = input.consume("rnd_generic", taken);
            std::memcpy(out, bytes, taken);
        }
    });
}

}  // namespace tox::test
