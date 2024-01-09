#include "crypto_core_test_util.hh"

#include <cstring>
#include <iomanip>

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

static void test_random_bytes(void *obj, uint8_t *bytes, size_t length)
{
    Test_Random *self = static_cast<Test_Random *>(obj);
    std::generate(bytes, &bytes[length], std::ref(self->lcg));
}

static uint32_t test_random_uniform(void *obj, uint32_t upper_bound)
{
    Test_Random *self = static_cast<Test_Random *>(obj);
    std::uniform_int_distribution<uint32_t> distrib(0, upper_bound);
    return distrib(self->lcg);
}

Random_Funcs const Test_Random::vtable = {
    test_random_bytes,
    test_random_uniform,
};

Test_Random::Test_Random()
    : self{&vtable, this}
{
}

Test_Random::operator Random const *() const { return &self; }
