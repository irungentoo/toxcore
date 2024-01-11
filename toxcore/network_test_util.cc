#include "network_test_util.hh"

#include <iomanip>

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

IP_Port random_ip_port(const Random *rng)
{
    IP_Port ip_port;
    ip_port.ip.family = net_family_ipv4();
    ip_port.ip.ip.v4.uint8[0] = 192;
    ip_port.ip.ip.v4.uint8[1] = 168;
    ip_port.ip.ip.v4.uint8[2] = 0;
    ip_port.ip.ip.v4.uint8[3] = random_u08(rng);
    ip_port.port = random_u16(rng);
    return ip_port;
}

bool operator==(Family const &a, Family const &b) { return a.value == b.value; }

bool operator==(IP4 const &a, IP4 const &b) { return a.uint32 == b.uint32; }

bool operator==(IP6 const &a, IP6 const &b)
{
    return a.uint64[0] == b.uint64[0] && a.uint64[1] == b.uint64[1];
}

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
