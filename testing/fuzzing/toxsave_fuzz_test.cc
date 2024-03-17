#include <cassert>
#include <cstdint>
#include <vector>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_private.h"
#include "fuzz_support.hh"

namespace {

void TestSaveDataLoading(Fuzz_Data &input)
{
    Tox_Err_Options_New error_options;

    struct Tox_Options *tox_options = tox_options_new(&error_options);

    assert(tox_options != nullptr);
    assert(error_options == TOX_ERR_OPTIONS_NEW_OK);

    const size_t savedata_size = input.size();
    CONSUME_OR_RETURN(const uint8_t *savedata, input, savedata_size);

    // pass test data to Tox
    tox_options_set_savedata_data(tox_options, savedata, savedata_size);
    tox_options_set_savedata_type(tox_options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    Tox_Options_Testing tox_options_testing;
    Null_System sys;
    tox_options_testing.operating_system = sys.sys.get();

    Tox *tox = tox_new_testing(tox_options, nullptr, &tox_options_testing, nullptr);
    tox_options_free(tox_options);
    if (tox == nullptr) {
        // Tox save was invalid, we're finished here
        return;
    }

    // verify that the file can be saved again
    std::vector<uint8_t> new_savedata(tox_get_savedata_size(tox));
    tox_get_savedata(tox, new_savedata.data());

    tox_kill(tox);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Fuzz_Data input{data, size};
    TestSaveDataLoading(input);
    return 0;  // Non-zero return values are reserved for future use.
}
