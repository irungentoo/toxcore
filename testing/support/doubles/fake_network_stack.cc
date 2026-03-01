#include "fake_network_stack.hh"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <iostream>

#include "../../../toxcore/mem.h"

namespace tox::test {

static const Network_Funcs kNetworkVtable = {
    .close = [](void *_Nonnull obj,
                 Socket sock) { return static_cast<FakeNetworkStack *>(obj)->close(sock); },
    .accept = [](void *_Nonnull obj,
                  Socket sock) { return static_cast<FakeNetworkStack *>(obj)->accept(sock); },
    .bind =
        [](void *_Nonnull obj, Socket sock, const IP_Port *_Nonnull addr) {
            return static_cast<FakeNetworkStack *>(obj)->bind(sock, addr);
        },
    .listen
    = [](void *_Nonnull obj, Socket sock,
          int backlog) { return static_cast<FakeNetworkStack *>(obj)->listen(sock, backlog); },
    .connect =
        [](void *_Nonnull obj, Socket sock, const IP_Port *_Nonnull addr) {
            return static_cast<FakeNetworkStack *>(obj)->connect(sock, addr);
        },
    .recvbuf = [](void *_Nonnull obj,
                   Socket sock) { return static_cast<FakeNetworkStack *>(obj)->recvbuf(sock); },
    .recv
    = [](void *_Nonnull obj, Socket sock, uint8_t *_Nonnull buf,
          std::size_t len) { return static_cast<FakeNetworkStack *>(obj)->recv(sock, buf, len); },
    .recvfrom =
        [](void *_Nonnull obj, Socket sock, uint8_t *_Nonnull buf, std::size_t len,
            IP_Port *_Nonnull addr) {
            return static_cast<FakeNetworkStack *>(obj)->recvfrom(sock, buf, len, addr);
        },
    .send
    = [](void *_Nonnull obj, Socket sock, const uint8_t *_Nonnull buf,
          std::size_t len) { return static_cast<FakeNetworkStack *>(obj)->send(sock, buf, len); },
    .sendto =
        [](void *_Nonnull obj, Socket sock, const uint8_t *_Nonnull buf, std::size_t len,
            const IP_Port *_Nonnull addr) {
            return static_cast<FakeNetworkStack *>(obj)->sendto(sock, buf, len, addr);
        },
    .socket
    = [](void *_Nonnull obj, int domain, int type,
          int proto) { return static_cast<FakeNetworkStack *>(obj)->socket(domain, type, proto); },
    .socket_nonblock =
        [](void *_Nonnull obj, Socket sock, bool nonblock) {
            return static_cast<FakeNetworkStack *>(obj)->socket_nonblock(sock, nonblock);
        },
    .getsockopt =
        [](void *_Nonnull obj, Socket sock, int level, int optname, void *_Nonnull optval,
            std::size_t *_Nonnull optlen) {
            return static_cast<FakeNetworkStack *>(obj)->getsockopt(
                sock, level, optname, optval, optlen);
        },
    .setsockopt =
        [](void *_Nonnull obj, Socket sock, int level, int optname, const void *_Nonnull optval,
            std::size_t optlen) {
            return static_cast<FakeNetworkStack *>(obj)->setsockopt(
                sock, level, optname, optval, optlen);
        },
    .getaddrinfo =
        [](void *_Nonnull obj, const Memory *_Nonnull mem, const char *_Nonnull address, int family,
            int protocol, IP_Port *_Nullable *_Nonnull addrs) {
            FakeNetworkStack *self = static_cast<FakeNetworkStack *>(obj);
            if (self->universe().is_verbose()) {
                std::cerr << "[FakeNetworkStack] getaddrinfo for " << address << std::endl;
            }
            if (strcmp(address, "127.0.0.1") == 0 || strcmp(address, "localhost") == 0) {
                *addrs = static_cast<IP_Port *>(mem_alloc(mem, sizeof(IP_Port)));
                memset(&(*addrs)->ip, 0, sizeof(IP));
                ip_init(&(*addrs)->ip, false);
                (*addrs)->ip.ip.v4.uint32 = net_htonl(0x7F000001);
                (*addrs)->port = 0;
                return 1;
            }

            IP ip;
            if (addr_parse_ip(address, &ip)) {
                *addrs = static_cast<IP_Port *>(mem_alloc(mem, sizeof(IP_Port)));
                (*addrs)->ip = ip;
                (*addrs)->port = 0;
                if (self->universe().is_verbose()) {
                    std::cerr << "[FakeNetworkStack] resolved " << address << std::endl;
                }
                return 1;
            }
            return 0;
        },
    .freeaddrinfo =
        [](void *_Nonnull obj, const Memory *_Nonnull mem, IP_Port *_Nullable addrs) {
            mem_delete(mem, addrs);
            return 0;
        },
};

FakeNetworkStack::FakeNetworkStack(NetworkUniverse &universe, const IP &node_ip)
    : universe_(universe)
    , node_ip_(node_ip)
{
}

FakeNetworkStack::~FakeNetworkStack() = default;

struct Network FakeNetworkStack::c_network() { return Network{&kNetworkVtable, this}; }

Socket FakeNetworkStack::socket(int domain, int type, int protocol)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int fd = next_fd_++;

    std::unique_ptr<FakeSocket> sock;
    if (type == SOCK_DGRAM) {
        if (universe_.is_verbose()) {
            std::cerr << "[FakeNetworkStack] create UDP socket fd=" << fd << std::endl;
        }
        sock = std::make_unique<FakeUdpSocket>(universe_);
    } else if (type == SOCK_STREAM) {
        if (universe_.is_verbose()) {
            std::cerr << "[FakeNetworkStack] create TCP socket fd=" << fd << std::endl;
        }
        sock = std::make_unique<FakeTcpSocket>(universe_);
    } else {
        // Unknown type
        return net_socket_from_native(-1);
    }

    sockets_[fd] = std::move(sock);
    sockets_[fd]->set_ip(node_ip_);
    return net_socket_from_native(fd);
}

FakeSocket *FakeNetworkStack::get_sock(Socket sock)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sockets_.find(net_socket_to_native(sock));
    if (it != sockets_.end()) {
        return it->second.get();
    }
    return nullptr;
}

int FakeNetworkStack::close(Socket sock)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int fd = net_socket_to_native(sock);
    auto it = sockets_.find(fd);
    if (it == sockets_.end()) {
        errno = EBADF;
        return -1;
    }
    it->second->close();
    sockets_.erase(it);
    return 0;
}

// Delegate all others
int FakeNetworkStack::bind(Socket sock, const IP_Port *addr)
{
    if (auto *s = get_sock(sock)) {
        int ret = s->bind(addr);
        if (universe_.is_verbose() && ret == 0) {
            char ip_str[TOX_INET_ADDRSTRLEN];
            ip_parse_addr(&s->ip_address(), ip_str, sizeof(ip_str));
            std::cerr << "[FakeNetworkStack] bound socket to " << ip_str << ":" << s->local_port()
                      << std::endl;
        }
        return ret;
    }
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::connect(Socket sock, const IP_Port *addr)
{
    if (auto *s = get_sock(sock))
        return s->connect(addr);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::listen(Socket sock, int backlog)
{
    if (auto *s = get_sock(sock))
        return s->listen(backlog);
    errno = EBADF;
    return -1;
}

Socket FakeNetworkStack::accept(Socket sock)
{
    // This requires creating a new FD
    IP_Port addr;
    std::unique_ptr<FakeSocket> new_sock_obj;

    {
        auto *s = get_sock(sock);
        if (!s) {
            errno = EBADF;
            return net_socket_from_native(-1);
        }
        new_sock_obj = s->accept(&addr);
    }

    if (!new_sock_obj) {
        // errno set by accept
        return net_socket_from_native(-1);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    int fd = next_fd_++;
    sockets_[fd] = std::move(new_sock_obj);
    return net_socket_from_native(fd);
}

int FakeNetworkStack::send(Socket sock, const uint8_t *buf, std::size_t len)
{
    if (auto *s = get_sock(sock))
        return s->send(buf, len);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::recv(Socket sock, uint8_t *buf, std::size_t len)
{
    if (auto *s = get_sock(sock))
        return s->recv(buf, len);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::recvbuf(Socket sock)
{
    if (auto *s = get_sock(sock))
        return s->recv_buffer_size();
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::sendto(Socket sock, const uint8_t *buf, std::size_t len, const IP_Port *addr)
{
    if (auto *s = get_sock(sock))
        return s->sendto(buf, len, addr);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::recvfrom(Socket sock, uint8_t *buf, std::size_t len, IP_Port *addr)
{
    if (auto *s = get_sock(sock))
        return s->recvfrom(buf, len, addr);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::socket_nonblock(Socket sock, bool nonblock)
{
    if (auto *s = get_sock(sock))
        return s->socket_nonblock(nonblock);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::getsockopt(
    Socket sock, int level, int optname, void *optval, std::size_t *optlen)
{
    if (auto *s = get_sock(sock))
        return s->getsockopt(level, optname, optval, optlen);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::setsockopt(
    Socket sock, int level, int optname, const void *optval, std::size_t optlen)
{
    if (auto *s = get_sock(sock))
        return s->setsockopt(level, optname, optval, optlen);
    errno = EBADF;
    return -1;
}

FakeUdpSocket *FakeNetworkStack::get_udp_socket(Socket sock)
{
    if (auto *s = get_sock(sock)) {
        if (s->type() == SOCK_DGRAM) {
            return static_cast<FakeUdpSocket *>(s);
        }
    }
    return nullptr;
}

std::vector<FakeUdpSocket *> FakeNetworkStack::get_bound_udp_sockets()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FakeUdpSocket *> result;
    for (const auto &pair : sockets_) {
        FakeSocket *s = pair.second.get();
        if (s->type() == SOCK_DGRAM && s->local_port() != 0) {
            result.push_back(static_cast<FakeUdpSocket *>(s));
        }
    }
    return result;
}

}  // namespace tox::test
