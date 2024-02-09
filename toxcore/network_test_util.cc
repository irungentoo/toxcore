#include "network_test_util.hh"

#include <iomanip>

#include "crypto_core.h"
#include "network.h"
#include "test_util.hh"

Network_Funcs const Network_Class::vtable = {
    Method<net_close_cb, Network_Class>::invoke<&Network_Class::close>,
    Method<net_accept_cb, Network_Class>::invoke<&Network_Class::accept>,
    Method<net_bind_cb, Network_Class>::invoke<&Network_Class::bind>,
    Method<net_listen_cb, Network_Class>::invoke<&Network_Class::listen>,
    Method<net_recvbuf_cb, Network_Class>::invoke<&Network_Class::recvbuf>,
    Method<net_recv_cb, Network_Class>::invoke<&Network_Class::recv>,
    Method<net_recvfrom_cb, Network_Class>::invoke<&Network_Class::recvfrom>,
    Method<net_send_cb, Network_Class>::invoke<&Network_Class::send>,
    Method<net_sendto_cb, Network_Class>::invoke<&Network_Class::sendto>,
    Method<net_socket_cb, Network_Class>::invoke<&Network_Class::socket>,
    Method<net_socket_nonblock_cb, Network_Class>::invoke<&Network_Class::socket_nonblock>,
    Method<net_getsockopt_cb, Network_Class>::invoke<&Network_Class::getsockopt>,
    Method<net_setsockopt_cb, Network_Class>::invoke<&Network_Class::setsockopt>,
    Method<net_getaddrinfo_cb, Network_Class>::invoke<&Network_Class::getaddrinfo>,
    Method<net_freeaddrinfo_cb, Network_Class>::invoke<&Network_Class::freeaddrinfo>,
};

int Test_Network::close(void *obj, Socket sock) { return net->funcs->close(net->obj, sock); }
Socket Test_Network::accept(void *obj, Socket sock) { return net->funcs->accept(net->obj, sock); }
int Test_Network::bind(void *obj, Socket sock, const Network_Addr *addr)
{
    return net->funcs->bind(net->obj, sock, addr);
}
int Test_Network::listen(void *obj, Socket sock, int backlog)
{
    return net->funcs->listen(net->obj, sock, backlog);
}
int Test_Network::recvbuf(void *obj, Socket sock) { return net->funcs->recvbuf(net->obj, sock); }
int Test_Network::recv(void *obj, Socket sock, uint8_t *buf, size_t len)
{
    return net->funcs->recv(net->obj, sock, buf, len);
}
int Test_Network::recvfrom(void *obj, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr)
{
    return net->funcs->recvfrom(net->obj, sock, buf, len, addr);
}
int Test_Network::send(void *obj, Socket sock, const uint8_t *buf, size_t len)
{
    return net->funcs->send(net->obj, sock, buf, len);
}
int Test_Network::sendto(
    void *obj, Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr)
{
    return net->funcs->sendto(net->obj, sock, buf, len, addr);
}
Socket Test_Network::socket(void *obj, int domain, int type, int proto)
{
    return net->funcs->socket(net->obj, domain, type, proto);
}
int Test_Network::socket_nonblock(void *obj, Socket sock, bool nonblock)
{
    return net->funcs->socket_nonblock(net->obj, sock, nonblock);
}
int Test_Network::getsockopt(
    void *obj, Socket sock, int level, int optname, void *optval, size_t *optlen)
{
    return net->funcs->getsockopt(net->obj, sock, level, optname, optval, optlen);
}
int Test_Network::setsockopt(
    void *obj, Socket sock, int level, int optname, const void *optval, size_t optlen)
{
    return net->funcs->setsockopt(net->obj, sock, level, optname, optval, optlen);
}
int Test_Network::getaddrinfo(void *obj, int family, Network_Addr **addrs)
{
    return net->funcs->getaddrinfo(net->obj, family, addrs);
}
int Test_Network::freeaddrinfo(void *obj, Network_Addr *addrs)
{
    return net->funcs->freeaddrinfo(net->obj, addrs);
}

Network_Class::~Network_Class() = default;

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
