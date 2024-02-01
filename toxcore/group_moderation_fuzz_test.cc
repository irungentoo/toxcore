#include "group_moderation.h"

#include "../testing/fuzzing/fuzz_support.hh"
#include "mem_test_util.hh"

namespace {

void TestModListUnpack(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const uint16_t, num_mods, input);
    Test_Memory mem;
    Moderation mods{mem};
    mod_list_unpack(&mods, input.data(), input.size(), num_mods);
    mod_list_cleanup(&mods);
}

void TestSanctionsListUnpack(Fuzz_Data &input)
{
    Mod_Sanction sanctions[10];
    Mod_Sanction_Creds creds;
    uint16_t processed_data_len;
    sanctions_list_unpack(sanctions, &creds, 10, input.data(), input.size(), &processed_data_len);
}

void TestSanctionCredsUnpack(Fuzz_Data &input)
{
    CONSUME_OR_RETURN(const uint8_t *data, input, MOD_SANCTIONS_CREDS_SIZE);
    Mod_Sanction_Creds creds;
    sanctions_creds_unpack(&creds, data);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_select_target<TestModListUnpack, TestSanctionsListUnpack, TestSanctionCredsUnpack>(
        data, size);
    return 0;
}
