#include "group_moderation.h"

#include "../testing/fuzzing/fuzz_support.h"

namespace {

void TestModListUnpack(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const uint16_t num_mods, input);
    Moderation mods{};
    mod_list_unpack(&mods, input.data, input.size, num_mods);
    mod_list_cleanup(&mods);
}

void TestSanctionsListUnpack(Fuzz_Data &input)
{
    Mod_Sanction sanctions[10];
    Mod_Sanction_Creds creds;
    uint16_t processed_data_len;
    sanctions_list_unpack(sanctions, &creds, 10, input.data, input.size, &processed_data_len);
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
    fuzz_select_target(
        data, size, TestModListUnpack, TestSanctionsListUnpack, TestSanctionCredsUnpack);
    return 0;
}
