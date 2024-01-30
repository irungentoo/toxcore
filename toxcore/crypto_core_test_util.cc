#include "crypto_core_test_util.hh"

#include <cstring>
#include <iomanip>

#include "crypto_core.h"
#include "test_util.hh"

Random_Funcs const Random_Class::vtable = {
    Method<crypto_random_bytes_cb, Random_Class>::invoke<&Random_Class::random_bytes>,
    Method<crypto_random_uniform_cb, Random_Class>::invoke<&Random_Class::random_uniform>,
};

Random_Class::~Random_Class() = default;

void Test_Random::random_bytes(void *obj, uint8_t *bytes, size_t length)
{
    std::generate(bytes, &bytes[length], std::ref(lcg));
}

uint32_t Test_Random::random_uniform(void *obj, uint32_t upper_bound)
{
    std::uniform_int_distribution<uint32_t> distrib(0, upper_bound);
    return distrib(lcg);
}

PublicKey random_pk(const Random *rng)
{
    PublicKey pk;
    random_bytes(rng, pk.data(), pk.size());
    return pk;
}

std::ostream &operator<<(std::ostream &out, PublicKey const &pk)
{
    out << '"';
    for (uint8_t byte : pk) {
        out << std::setw(2) << std::setfill('0') << std::hex << uint32_t(byte);
    }
    out << '"';
    return out;
}
