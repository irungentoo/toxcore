#include "group_moderation.h"

#include <cstddef>

#include "../testing/support/public/fuzz_data.hh"
#include "../testing/support/public/simulated_environment.hh"

namespace {

using tox::test::Fuzz_Data;
using tox::test::SimulatedEnvironment;

void TestModListUnpack(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const std::uint16_t, num_mods, input);
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    mod_list_unpack(&mods, input.data(), input.size(), num_mods);
    mod_list_cleanup(&mods);
}

void TestSanctionsListUnpack(Fuzz_Data &input)
{
    Mod_Sanction sanctions[10];
    Mod_Sanction_Creds creds;
    std::uint16_t processed_data_len;
    sanctions_list_unpack(sanctions, &creds, 10, input.data(), input.size(), &processed_data_len);
}

void TestSanctionCredsUnpack(Fuzz_Data &input)
{
    CONSUME_OR_RETURN(const std::uint8_t *data, input, MOD_SANCTIONS_CREDS_SIZE);
    Mod_Sanction_Creds creds;
    sanctions_creds_unpack(&creds, data);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    tox::test::fuzz_select_target<TestModListUnpack, TestSanctionsListUnpack,
        TestSanctionCredsUnpack>(data, size);
    return 0;
}
