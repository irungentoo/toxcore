#include "DHT_test_util.hh"

#include <cstring>
#include <iomanip>

#include "DHT.h"
#include "crypto_core.h"
#include "crypto_core_test_util.hh"
#include "network.h"
#include "network_test_util.hh"

Node_format random_node_format(const Random *rng)
{
    Node_format node;
    auto const pk = random_pk(rng);
    std::copy(pk.begin(), pk.end(), node.public_key);
    node.ip_port = random_ip_port(rng);
    return node;
}

bool operator==(Node_format const &a, Node_format const &b)
{
    return std::memcmp(a.public_key, b.public_key, sizeof(a.public_key)) == 0
        && a.ip_port == b.ip_port;
}

std::ostream &operator<<(std::ostream &out, Node_format const &v)
{
    return out << "\n    Node_format{\n"
               << "      public_key = " << PublicKey(v.public_key) << ",\n"
               << "      ip_port = " << v.ip_port << " }";
}
