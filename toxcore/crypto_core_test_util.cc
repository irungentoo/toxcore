#include "crypto_core_test_util.hh"

#include <cstring>
#include <iomanip>
#include <ostream>

#include "crypto_core.h"
#include "test_util.hh"

PublicKey random_pk(const Random *_Nonnull rng)
{
    PublicKey pk;
    random_bytes(rng, pk.data(), pk.size());
    return pk;
}

std::array<std::uint8_t, CRYPTO_SECRET_KEY_SIZE> random_sk(const Random *rng)
{
    std::array<std::uint8_t, CRYPTO_SECRET_KEY_SIZE> sk;
    random_bytes(rng, sk.data(), sk.size());
    return sk;
}

std::ostream &operator<<(std::ostream &out, PublicKey const &pk)
{
    out << '"';
    for (std::uint8_t byte : pk) {
        out << std::setw(2) << std::setfill('0') << std::hex << std::uint32_t(byte);
    }
    out << '"';
    return out;
}
