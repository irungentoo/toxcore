#include <cassert>
#include <cstring>
#include <memory>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_private.h"
#include "fuzz_adapter.h"
#include "fuzz_support.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    network_adapter_init(data, size);

    uint64_t clock = 0;
    auto sys = fuzz_system(clock);
    assert(sys->mono_time_callback != nullptr);
    assert(sys->mono_time_user_data != nullptr);

    Tox_Options *opts = tox_options_new(nullptr);
    assert(opts != nullptr);
    tox_options_set_operating_system(opts, sys.get());

    Tox_Err_New error_new;
    Tox *tox = tox_new(opts, &error_new);

    assert(tox != nullptr);
    assert(error_new == TOX_ERR_NEW_OK);

    tox_options_free(opts);

    uint8_t pub_key[TOX_PUBLIC_KEY_SIZE] = {0};

    const bool success = tox_bootstrap(tox, "127.0.0.1", 12345, pub_key, nullptr);
    assert(success);

    /*
     * The iteration count here is a magic value in the literal sense, too small
     * and coverage will be bad, too big and fuzzing will not be efficient.
     * NOTE: This should be fine tuned after gathering some experience.
     */

    for (uint32_t i = 0; i < 50; ++i) {
        tox_iterate(tox, nullptr);
        // Move the clock forward a decent amount so all the time-based checks
        // trigger more quickly.
        clock += 200;
    }

    tox_kill(tox);
    return 0;  // Non-zero return values are reserved for future use.
}
