#include "tox_events.h"

namespace {

void TestUnpack(const uint8_t *data, size_t size) { tox_events_free(tox_events_load(data, size)); }

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    TestUnpack(data, size);
    return 0;
}
