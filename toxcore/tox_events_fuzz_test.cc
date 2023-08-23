#include "tox_events.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "../testing/fuzzing/fuzz_support.h"

namespace {

void TestUnpack(Fuzz_Data data)
{
    // 2 bytes: size of the events data
    CONSUME_OR_RETURN(const uint8_t *events_size_bytes, data, sizeof(uint16_t));
    uint16_t events_size;
    std::memcpy(&events_size, events_size_bytes, sizeof(uint16_t));

    // events_size bytes: events data (max 64K)
    CONSUME_OR_RETURN(const uint8_t *events_data, data, events_size);

    if (data.size == 0) {
        // If there's no more input, no malloc failure paths can possibly be
        // tested, so we ignore this input.
        return;
    }

    // rest of the fuzz data is input for malloc
    Fuzz_System sys{data};

    Tox_Events *events = tox_events_load(sys.sys.get(), events_data, events_size);
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
    TestUnpack(Fuzz_Data(data, size));
    return 0;
}
