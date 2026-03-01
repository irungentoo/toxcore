#ifndef C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H

#include <cstdint>
#include <iosfwd>

#include "attributes.h"
#include "crypto_core.h"
#include "mem.h"
#include "net.h"
#include "network.h"
#include "rng.h"
#include "test_util.hh"

template <>
struct Deleter<Networking_Core> : Function_Deleter<Networking_Core, kill_networking> { };

IP_Port random_ip_port(const Random *_Nonnull rng);

class increasing_ip_port {
    std::uint8_t start_;
    const Random *_Nonnull rng_;

public:
    explicit increasing_ip_port(std::uint8_t start, const Random *_Nonnull rng)
        : start_(start)
        , rng_(rng)
    {
    }

    IP_Port operator()();
};

bool operator==(Family a, Family b);

bool operator==(IP4 a, IP4 b);
bool operator==(IP6 a, IP6 b);
bool operator==(IP const &a, IP const &b);
bool operator==(IP_Port const &a, IP_Port const &b);

std::ostream &operator<<(std::ostream &out, IP const &v);
std::ostream &operator<<(std::ostream &out, IP_Port const &v);

#endif  // C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H
