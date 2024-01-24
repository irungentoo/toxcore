#include "../public/network.hh"

#include <iomanip>
#include <ostream>

#include "../../../toxcore/crypto_core.h"
#include "../../../toxcore/rng.h"

namespace tox::test {

NetworkSystem::~NetworkSystem() = default;

IP make_ip(uint32_t ipv4)
{
    IP ip;
    ip_init(&ip, false);
    ip.ip.v4.uint32 = net_htonl(ipv4);
    return ip;
}

IP make_node_ip(uint32_t node_id)
{
    // Use 20.x.y.z range: 20. (id >> 16) . (id >> 8) . (id & 0xFF)
    return make_ip(0x14000000 | (node_id & 0x00FFFFFF));
}

IP_Port random_ip_port(const Random *_Nonnull rng)
{
    IP_Port ip_port;
    ip_init(&ip_port.ip, false);
    ip_port.ip.ip.v4.uint32 = random_u32(rng);
    ip_port.port = net_htons(random_u16(rng));
    return ip_port;
}

IP_Port increasing_ip_port::operator()()
{
    IP_Port ip_port;
    ip_port.ip.family = net_family_ipv4();
    ip_port.ip.ip.v4.uint8[0] = 192;
    ip_port.ip.ip.v4.uint8[1] = 168;
    ip_port.ip.ip.v4.uint8[2] = 0;
    ip_port.ip.ip.v4.uint8[3] = start_;
    ip_port.port = random_u16(rng_);
    ++start_;
    return ip_port;
}

}  // namespace tox::test

bool operator==(Family a, Family b) { return a.value == b.value; }

bool operator==(IP4 a, IP4 b) { return a.uint32 == b.uint32; }

bool operator==(IP6 a, IP6 b) { return a.uint64[0] == b.uint64[0] && a.uint64[1] == b.uint64[1]; }

bool operator==(IP const &a, IP const &b)
{
    if (!(a.family == b.family)) {
        return false;
    }

    if (net_family_is_ipv4(a.family)) {
        return a.ip.v4 == b.ip.v4;
    } else {
        return a.ip.v6 == b.ip.v6;
    }
}

bool operator==(IP_Port const &a, IP_Port const &b) { return a.ip == b.ip && a.port == b.port; }

std::ostream &operator<<(std::ostream &out, IP const &v)
{
    Ip_Ntoa ip_str;
    out << '"' << net_ip_ntoa(&v, &ip_str) << '"';
    return out;
}

std::ostream &operator<<(std::ostream &out, IP_Port const &v)
{
    return out << "IP_Port{\n"
               << "        ip = " << v.ip << ",\n"
               << "        port = " << std::dec << std::setw(0) << v.port << " }";
}
