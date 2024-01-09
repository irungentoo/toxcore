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
