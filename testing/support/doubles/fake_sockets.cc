#include "fake_sockets.hh"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <mutex>
#include <vector>

#include "network_universe.hh"

namespace tox::test {

// --- FakeSocket ---

FakeSocket::FakeSocket(NetworkUniverse &universe, int type)
    : universe_(universe)
    , type_(type)
{
    ip_init(&ip_, false);
    ip_.ip.v4.uint32 = net_htonl(0x7F000001);
}

FakeSocket::~FakeSocket() = default;

int FakeSocket::close()
{
    // Override in subclasses to unbind
    return 0;
}

int FakeSocket::getsockopt(
    int level, int optname, void *_Nonnull optval, std::size_t *_Nonnull optlen)
{
    return 0;
}
int FakeSocket::setsockopt(int level, int optname, const void *_Nonnull optval, std::size_t optlen)
{
    return 0;
}
int FakeSocket::socket_nonblock(bool nonblock)
{
    nonblocking_ = nonblock;
    return 0;
}

// --- FakeUdpSocket ---

FakeUdpSocket::FakeUdpSocket(NetworkUniverse &universe)
    : FakeSocket(universe, SOCK_DGRAM)
{
}

FakeUdpSocket::~FakeUdpSocket() { close_impl(); }

int FakeUdpSocket::close()
{
    std::lock_guard<std::mutex> lock(mutex_);
    close_impl();
    return 0;
}

void FakeUdpSocket::close_impl()
{
    if (local_port_ != 0) {
        universe_.unbind_udp(ip_, local_port_);
        local_port_ = 0;
    }
}

int FakeUdpSocket::bind(const IP_Port *_Nonnull addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (local_port_ != 0)
        return -1;  // Already bound

    uint16_t port = addr->port;
    if (port == 0) {
        port = universe_.find_free_port(ip_);
    } else {
        port = net_ntohs(port);
    }

    if (universe_.bind_udp(ip_, port, this)) {
        local_port_ = port;
        return 0;
    }
    errno = EADDRINUSE;
    return -1;
}

int FakeUdpSocket::connect(const IP_Port *_Nonnull addr)
{
    // UDP connect just sets default dest.
    // Not strictly needed for toxcore UDP but good for completeness.
    return 0;
}

int FakeUdpSocket::listen(int backlog)
{
    errno = EOPNOTSUPP;
    return -1;
}
std::unique_ptr<FakeSocket> FakeUdpSocket::accept(IP_Port *_Nullable addr)
{
    errno = EOPNOTSUPP;
    return nullptr;
}
int FakeUdpSocket::send(const uint8_t *_Nonnull buf, std::size_t len)
{
    errno = EDESTADDRREQ;
    return -1;
}
int FakeUdpSocket::recv(uint8_t *_Nonnull buf, std::size_t len)
{
    errno = EOPNOTSUPP;
    return -1;
}

std::size_t FakeUdpSocket::recv_buffer_size()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return recv_queue_.size();
}

int FakeUdpSocket::sendto(
    const uint8_t *_Nonnull buf, std::size_t len, const IP_Port *_Nonnull addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (local_port_ == 0) {
        // Implicit bind
        uint16_t p = universe_.find_free_port(ip_);
        if (universe_.bind_udp(ip_, p, this)) {
            local_port_ = p;
        } else {
            errno = EADDRINUSE;
            return -1;
        }
    }

    Packet p{};
    // Source
    p.from.ip = ip_;
    p.from.port = net_htons(local_port_);
    p.to = *addr;
    p.data.assign(buf, buf + len);
    p.is_tcp = false;

    universe_.send_packet(p);
    if (universe_.is_verbose()) {
        Ip_Ntoa ip_str;
        net_ip_ntoa(&addr->ip, &ip_str);
        std::cerr << "[FakeUdpSocket] sent " << len << " bytes from port " << local_port_ << " to "
                  << ip_str.buf << ":" << net_ntohs(addr->port) << std::endl;
    }
    return len;
}

int FakeUdpSocket::recvfrom(uint8_t *_Nonnull buf, std::size_t len, IP_Port *_Nonnull addr)
{
    RecvObserver observer_copy;
    std::vector<uint8_t> data_copy;
    IP_Port from_copy;
    std::size_t copy_len = 0;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (recv_queue_.empty() && packet_source_) {
            // NOTE: We call packet_source_ with lock held.
            // Be careful not to call back into socket methods from packet_source_.
            std::vector<uint8_t> data;
            IP_Port from;
            if (packet_source_(data, from)) {
                recv_queue_.push_back({std::move(data), from});
            }
        }

        if (recv_queue_.empty()) {
            errno = EWOULDBLOCK;
            return -1;
        }

        auto &p = recv_queue_.front();
        copy_len = std::min(len, p.data.size());
        std::memcpy(buf, p.data.data(), copy_len);
        *addr = p.from;

        if (recv_observer_) {
            observer_copy = recv_observer_;
            data_copy = p.data;
            from_copy = p.from;
        }

        recv_queue_.pop_front();
    }

    if (observer_copy) {
        observer_copy(data_copy, from_copy);
    }

    if (universe_.is_verbose()) {
        std::cerr << "[FakeUdpSocket] recv " << copy_len << " bytes at port " << local_port_
                  << " from port " << net_ntohs(addr->port) << std::endl;
    }

    return copy_len;
}

void FakeUdpSocket::push_packet(std::vector<uint8_t> data, IP_Port from)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (recv_queue_.size() >= kMaxQueueSize) {
        if (universe_.is_verbose()) {
            std::cerr << "[FakeUdpSocket] queue full, dropping packet" << std::endl;
        }
        return;
    }
    if (universe_.is_verbose()) {
        Ip_Ntoa local_ip_str, from_ip_str;
        net_ip_ntoa(&ip_, &local_ip_str);
        net_ip_ntoa(&from.ip, &from_ip_str);

        std::cerr << "[FakeUdpSocket] push " << data.size() << " bytes into queue for "
                  << local_ip_str.buf << ":" << local_port_ << " from " << from_ip_str.buf << ":"
                  << net_ntohs(from.port) << std::endl;
    }
    recv_queue_.push_back({std::move(data), from});
}

void FakeUdpSocket::set_packet_source(PacketSource source)
{
    std::lock_guard<std::mutex> lock(mutex_);
    packet_source_ = std::move(source);
}

void FakeUdpSocket::set_recv_observer(RecvObserver observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    recv_observer_ = std::move(observer);
}

// --- FakeTcpSocket ---

FakeTcpSocket::FakeTcpSocket(NetworkUniverse &universe)
    : FakeSocket(universe, SOCK_STREAM)
{
    ipport_reset(&remote_addr_);
}

FakeTcpSocket::~FakeTcpSocket() { close_impl(); }

int FakeTcpSocket::close()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == ESTABLISHED || state_ == SYN_SENT || state_ == SYN_RECEIVED
        || state_ == CLOSE_WAIT) {
        // Send RST to peer
        Packet p{};
        p.from.ip = ip_;
        p.from.port = net_htons(local_port_);
        p.to = remote_addr_;
        p.is_tcp = true;
        p.tcp_flags = 0x04;  // RST
        universe_.send_packet(p);
    }
    close_impl();
    return 0;
}

void FakeTcpSocket::close_impl()
{
    if (local_port_ != 0) {
        universe_.unbind_tcp(ip_, local_port_, this);
        local_port_ = 0;
    }
    state_ = CLOSED;
}

int FakeTcpSocket::bind(const IP_Port *_Nonnull addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (local_port_ != 0)
        return -1;

    uint16_t port = addr->port;
    if (port == 0) {
        port = universe_.find_free_port(ip_);
    } else {
        port = net_ntohs(port);
    }

    if (universe_.bind_tcp(ip_, port, this)) {
        local_port_ = port;
        return 0;
    }
    errno = EADDRINUSE;
    return -1;
}

int FakeTcpSocket::listen(int backlog)
{
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = LISTEN;
    backlog_ = backlog;
    return 0;
}

int FakeTcpSocket::connect(const IP_Port *_Nonnull addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (universe_.is_verbose()) {
        Ip_Ntoa ip_str, dest_str;
        net_ip_ntoa(&ip_, &ip_str);
        net_ip_ntoa(&addr->ip, &dest_str);
        std::cerr << "[FakeTcpSocket] connect from " << ip_str.buf << " to " << dest_str.buf << ":"
                  << net_ntohs(addr->port) << std::endl;
    }

    if (local_port_ == 0) {
        // Implicit bind
        uint16_t p = universe_.find_free_port(ip_);
        if (universe_.bind_tcp(ip_, p, this)) {
            local_port_ = p;
            if (universe_.is_verbose()) {
                std::cerr << "[FakeTcpSocket] implicit bind to port " << local_port_ << std::endl;
            }
        } else {
            errno = EADDRINUSE;
            return -1;
        }
    }

    remote_addr_ = *addr;
    state_ = SYN_SENT;

    Packet p{};
    p.from.ip = ip_;
    p.from.port = net_htons(local_port_);
    p.to = *addr;
    p.is_tcp = true;
    p.tcp_flags = 0x02;  // SYN
    p.seq = next_seq_;

    universe_.send_packet(p);
    // Non-blocking connect not fully simulated.
    // Real connect() blocks or returns EINPROGRESS.
    // For simplicity, we assume the test will pump events until connected.
    errno = EINPROGRESS;
    return -1;
}

std::unique_ptr<FakeSocket> FakeTcpSocket::accept(IP_Port *_Nullable addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != LISTEN) {
        errno = EINVAL;
        return nullptr;
    }

    auto it = std::find_if(pending_connections_.begin(), pending_connections_.end(),
        [](const std::unique_ptr<FakeTcpSocket> &s) { return s->state() == ESTABLISHED; });

    if (it == pending_connections_.end()) {
        errno = EWOULDBLOCK;
        return nullptr;
    }

    auto client = std::move(*it);
    pending_connections_.erase(it);

    if (addr) {
        *addr = client->remote_addr();
    }
    return client;
}

int FakeTcpSocket::send(const uint8_t *_Nonnull buf, std::size_t len)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != ESTABLISHED) {
        if (universe_.is_verbose()) {
            std::cerr << "[FakeTcpSocket] send failed: state " << state_ << " port " << local_port_
                      << std::endl;
        }
        if (state_ == SYN_SENT || state_ == SYN_RECEIVED) {
            errno = EWOULDBLOCK;
        } else {
            errno = ENOTCONN;
        }
        return -1;
    }

    // Wrap as TCP packet
    Packet p{};
    // Source
    p.from.ip = ip_;
    p.from.port = net_htons(local_port_);
    p.to = remote_addr_;
    p.data.assign(buf, buf + len);
    p.is_tcp = true;
    p.tcp_flags = 0x10;  // ACK (Data packets usually have ACK)
    p.seq = next_seq_;
    p.ack = last_ack_;

    next_seq_ += len;
    universe_.send_packet(p);
    return len;
}

int FakeTcpSocket::recv(uint8_t *_Nonnull buf, std::size_t len)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (recv_buffer_.empty()) {
        if (state_ == CLOSED || state_ == CLOSE_WAIT)
            return 0;  // EOF
        errno = EWOULDBLOCK;
        return -1;
    }

    std::size_t actual = std::min(len, recv_buffer_.size());
    if (universe_.is_verbose() && actual > 0) {
        char remote_ip_str[TOX_INET_ADDRSTRLEN];
        ip_parse_addr(&remote_addr_.ip, remote_ip_str, sizeof(remote_ip_str));
        std::cerr << "[FakeTcpSocket] Port " << local_port_ << " (Peer: " << remote_ip_str << ":"
                  << net_ntohs(remote_addr_.port) << ") recv requested " << len << " got " << actual
                  << " (remaining " << recv_buffer_.size() - actual << ")" << std::endl;
    }
    for (std::size_t i = 0; i < actual; ++i) {
        buf[i] = recv_buffer_.front();
        recv_buffer_.pop_front();
    }
    return actual;
}

std::size_t FakeTcpSocket::recv_buffer_size()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return recv_buffer_.size();
}

bool FakeTcpSocket::is_readable()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == LISTEN) {
        return std::any_of(pending_connections_.begin(), pending_connections_.end(),
            [](const std::unique_ptr<FakeTcpSocket> &s) { return s->state() == ESTABLISHED; });
    }
    return !recv_buffer_.empty() || state_ == CLOSED || state_ == CLOSE_WAIT;
}

bool FakeTcpSocket::is_writable()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == ESTABLISHED;
}

int FakeTcpSocket::sendto(
    const uint8_t *_Nonnull buf, std::size_t len, const IP_Port *_Nonnull addr)
{
    errno = EOPNOTSUPP;
    return -1;
}
int FakeTcpSocket::recvfrom(uint8_t *_Nonnull buf, std::size_t len, IP_Port *_Nonnull addr)
{
    errno = EOPNOTSUPP;
    return -1;
}

int FakeTcpSocket::getsockopt(
    int level, int optname, void *_Nonnull optval, std::size_t *_Nonnull optlen)
{
    if (universe_.is_verbose()) {
        std::cerr << "[FakeTcpSocket] getsockopt level=" << level << " optname=" << optname
                  << " state=" << state_ << std::endl;
    }
    if (level == SOL_SOCKET && optname == SO_ERROR) {
        int error = 0;
        if (state_ == SYN_SENT || state_ == SYN_RECEIVED) {
            error = EINPROGRESS;
        } else if (state_ == CLOSED) {
            error = ECONNREFUSED;
        }

        if (*optlen >= sizeof(int)) {
            *static_cast<int *>(optval) = error;
            *optlen = sizeof(int);
        }
        if (universe_.is_verbose()) {
            std::cerr << "[FakeTcpSocket] getsockopt SO_ERROR returning error=" << error
                      << std::endl;
        }
        return 0;
    }
    return 0;
}

bool FakeTcpSocket::handle_packet(const Packet &p)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (universe_.is_verbose()) {
        char remote_ip_str[TOX_INET_ADDRSTRLEN];
        ip_parse_addr(&remote_addr_.ip, remote_ip_str, sizeof(remote_ip_str));
        std::cerr << "Handle Packet: Port " << local_port_ << " (Peer: " << remote_ip_str << ":"
                  << net_ntohs(remote_addr_.port) << ") Flags " << TcpFlags{p.tcp_flags}
                  << " State " << state_ << " From " << net_ntohs(p.from.port) << std::endl;
    }

    if (state_ != LISTEN) {
        // Filter packets not from our peer
        bool port_match = net_ntohs(p.from.port) == net_ntohs(remote_addr_.port);
        bool ip_match = ip_equal(&p.from.ip, &remote_addr_.ip)
            || (is_loopback(p.from.ip) && ip_equal(&remote_addr_.ip, &ip_))
            || (is_loopback(remote_addr_.ip) && ip_equal(&p.from.ip, &ip_));

        if (!port_match || !ip_match) {
            return false;
        }

        if (p.tcp_flags & 0x04) {  // RST
            close_impl();
            return true;
        }
    }

    switch (state_) {
    case LISTEN:
        if (p.tcp_flags & 0x02) {  // SYN
            // Check backlog
            std::size_t effective_backlog
                = std::clamp(static_cast<std::size_t>(backlog_), std::size_t{1}, kMaxBacklog);
            if (pending_connections_.size() >= effective_backlog) {
                return false;  // Drop packet
            }

            // Check for duplicate SYN from same peer
            for (const auto &pending : pending_connections_) {
                if (ipport_equal(&p.from, &pending->remote_addr_)) {
                    return true;
                }
            }

            // Create new socket for connection
            auto new_sock = std::make_unique<FakeTcpSocket>(universe_);

            new_sock->state_ = SYN_RECEIVED;
            new_sock->remote_addr_ = p.from;
            new_sock->local_port_ = local_port_;
            new_sock->set_ip(ip_);  // Inherit IP from listening socket
            new_sock->last_ack_ = p.seq + 1;
            new_sock->next_seq_ = 1000;  // Random ISN

            universe_.bind_tcp(ip_, local_port_, new_sock.get());

            // Send SYN-ACK
            Packet resp{};
            resp.from = p.to;
            resp.to = p.from;
            resp.is_tcp = true;
            resp.tcp_flags = 0x12;  // SYN | ACK
            resp.seq = new_sock->next_seq_++;
            resp.ack = new_sock->last_ack_;

            universe_.send_packet(resp);

            // Add to pending, but it's still SYN_RECEIVED
            pending_connections_.push_back(std::move(new_sock));
            return true;
        }
        return false;

    case SYN_SENT:
        if ((p.tcp_flags & 0x12) == 0x12) {  // SYN | ACK
            state_ = ESTABLISHED;
            last_ack_ = p.seq + 1;
            next_seq_++;  // Consumer SYN

            // Send ACK
            Packet ack{};
            ack.from = p.to;
            ack.to = p.from;
            ack.is_tcp = true;
            ack.tcp_flags = 0x10;  // ACK
            ack.seq = next_seq_;
            ack.ack = last_ack_;
            universe_.send_packet(ack);
            // Fall through to handle data if any
        } else if (p.tcp_flags & 0x02) {  // SYN (Simultaneous Open)
            state_ = SYN_RECEIVED;
            last_ack_ = p.seq + 1;

            // Send SYN-ACK
            Packet resp{};
            resp.from = p.to;
            resp.to = p.from;
            resp.is_tcp = true;
            resp.tcp_flags = 0x12;  // SYN | ACK
            resp.seq = next_seq_++;
            resp.ack = last_ack_;
            universe_.send_packet(resp);
            return true;
        } else {
            return false;
        }
        break;

    case SYN_RECEIVED:
        if (p.tcp_flags & 0x10) {  // ACK
            state_ = ESTABLISHED;
            // Fall through to handle data if any
        } else {
            return false;
        }
        break;

    case ESTABLISHED:
        break;

    case CLOSED:
    case CLOSE_WAIT:
    default:
        return false;
    }

    if (state_ == ESTABLISHED) {
        if (p.tcp_flags & 0x01) {  // FIN
            state_ = CLOSE_WAIT;
            // Send ACK
            Packet ack{};
            ack.from = p.to;
            ack.to = p.from;
            ack.is_tcp = true;
            ack.tcp_flags = 0x10;  // ACK
            ack.seq = next_seq_;
            ack.ack = p.seq + 1;  // Consume FIN
            universe_.send_packet(ack);
            return true;
        } else {
            if (!p.data.empty()) {
                if (recv_buffer_.size() + p.data.size() <= kMaxBufferSize) {
                    if (universe_.is_verbose()) {
                        char remote_ip_str[TOX_INET_ADDRSTRLEN];
                        ip_parse_addr(&remote_addr_.ip, remote_ip_str, sizeof(remote_ip_str));
                        std::cerr << "[FakeTcpSocket] Port " << local_port_
                                  << " (Peer: " << remote_ip_str << ":"
                                  << net_ntohs(remote_addr_.port) << ") adding " << p.data.size()
                                  << " bytes to buffer (currently " << recv_buffer_.size() << ")"
                                  << std::endl;
                    }
                    recv_buffer_.insert(recv_buffer_.end(), p.data.begin(), p.data.end());
                    last_ack_ += p.data.size();
                } else {
                    if (universe_.is_verbose()) {
                        std::cerr << "[FakeTcpSocket] Port " << local_port_
                                  << " Buffer full, dropping " << p.data.size() << " bytes"
                                  << std::endl;
                    }
                }
            }
            return true;
        }
    }
    return false;
}

std::unique_ptr<FakeTcpSocket> FakeTcpSocket::create_connected(
    NetworkUniverse &universe, const IP_Port &remote, uint16_t local_port)
{
    auto s = std::make_unique<FakeTcpSocket>(universe);
    s->state_ = ESTABLISHED;
    s->remote_addr_ = remote;
    s->local_port_ = local_port;
    return s;
}

std::ostream &operator<<(std::ostream &os, FakeTcpSocket::State state)
{
    switch (state) {
    case FakeTcpSocket::CLOSED:
        return os << "CLOSED";
    case FakeTcpSocket::LISTEN:
        return os << "LISTEN";
    case FakeTcpSocket::SYN_SENT:
        return os << "SYN_SENT";
    case FakeTcpSocket::SYN_RECEIVED:
        return os << "SYN_RECEIVED";
    case FakeTcpSocket::ESTABLISHED:
        return os << "ESTABLISHED";
    case FakeTcpSocket::CLOSE_WAIT:
        return os << "CLOSE_WAIT";
    }
    return os << "UNKNOWN(" << static_cast<int>(state) << ")";
}

}  // namespace tox::test
