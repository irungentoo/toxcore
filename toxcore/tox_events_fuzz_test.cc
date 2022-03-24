#include "tox_events.h"

#include <cstdint>
#include <vector>

namespace {

void TestUnpack(const uint8_t *data, size_t size)
{
    Tox_Events *events = tox_events_load(data, size);
    if (events) {
        std::vector<uint8_t> packed(tox_events_bytes_size(events));
        tox_events_get_bytes(events, packed.data());
    }
    tox_events_free(events);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    TestUnpack(data, size);
    return 0;
}
