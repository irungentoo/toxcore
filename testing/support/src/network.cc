#include "../public/network.hh"

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

}  // namespace tox::test
