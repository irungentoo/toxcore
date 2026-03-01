#include "network_universe.hh"

#include <cstring>
#include <iostream>

#include "fake_sockets.hh"

namespace tox::test {

std::ostream &operator<<(std::ostream &os, TcpFlags flags)
{
    bool first = true;
    if (flags.value & 0x02) {
        os << (first ? "" : "|") << "SYN";
        first = false;
    }
    if (flags.value & 0x10) {
        os << (first ? "" : "|") << "ACK";
        first = false;
    }
    if (flags.value & 0x01) {
        os << (first ? "" : "|") << "FIN";
        first = false;
    }
    if (flags.value & 0x04) {
        os << (first ? "" : "|") << "RST";
        first = false;
    }
    if (first)
        os << "NONE";
    return os << "(" << static_cast<int>(flags.value) << ")";
}

bool NetworkUniverse::IP_Port_Key::operator<(const IP_Port_Key &other) const
{
    if (port != other.port)
        return port < other.port;
    if (ip.family.value != other.ip.family.value)
        return ip.family.value < other.ip.family.value;

    if (net_family_is_ipv4(ip.family)) {
        return ip.ip.v4.uint32 < other.ip.ip.v4.uint32;
    }

    return std::memcmp(&ip.ip.v6, &other.ip.ip.v6, sizeof(ip.ip.v6)) < 0;
}

NetworkUniverse::NetworkUniverse() { }
NetworkUniverse::~NetworkUniverse() { }

bool NetworkUniverse::bind_udp(IP ip, uint16_t port, FakeUdpSocket *_Nonnull socket)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IP_Port_Key key{ip, port};
    if (udp_bindings_.count(key))
        return false;
    udp_bindings_[key] = socket;
    return true;
}

void NetworkUniverse::unbind_udp(IP ip, uint16_t port)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    udp_bindings_.erase({ip, port});
}

bool NetworkUniverse::bind_tcp(IP ip, uint16_t port, FakeTcpSocket *_Nonnull socket)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    tcp_bindings_.insert({{ip, port}, socket});
    return true;
}

void NetworkUniverse::unbind_tcp(IP ip, uint16_t port, FakeTcpSocket *_Nonnull socket)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto range = tcp_bindings_.equal_range({ip, port});
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second == socket) {
            tcp_bindings_.erase(it);
            break;
        }
    }
}

void NetworkUniverse::send_packet(Packet p)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // Apply filters
    for (const auto &filter : filters_) {
        if (!filter(p))
            return;
    }

    // Notify observers
    for (const auto &observer : observers_) {
        observer(p);
    }

    p.delivery_time += global_latency_ms_;

    p.sequence_number = next_packet_id_++;

    if (verbose_) {
        Ip_Ntoa from_str, to_str;
        net_ip_ntoa(&p.from.ip, &from_str);
        net_ip_ntoa(&p.to.ip, &to_str);
        std::cerr << "[NetworkUniverse] Enqueued packet #" << p.sequence_number << " from "
                  << from_str.buf << ":" << net_ntohs(p.from.port) << " to " << to_str.buf << ":"
                  << net_ntohs(p.to.port);
        if (p.is_tcp) {
            std::cerr << " (TCP Flags=" << TcpFlags{p.tcp_flags} << " Seq=" << p.seq
                      << " Ack=" << p.ack << ")";
        }
        std::cerr << " with size " << p.data.size() << std::endl;
    }
    event_queue_.push(std::move(p));
}

static bool is_ipv4_mapped(const IP &ip)
{
    if (!net_family_is_ipv6(ip.family))
        return false;
    const uint8_t *b = ip.ip.v6.uint8;
    for (int i = 0; i < 10; ++i)
        if (b[i] != 0)
            return false;
    if (b[10] != 0xFF || b[11] != 0xFF)
        return false;
    return true;
}

static IP extract_ipv4(const IP &ip)
{
    IP ip4;
    ip_init(&ip4, false);
    const uint8_t *b = ip.ip.v6.uint8;
    std::memcpy(ip4.ip.v4.uint8, b + 12, 4);
    return ip4;
}

bool is_loopback(const IP &ip)
{
    if (net_family_is_ipv4(ip.family)) {
        return ip.ip.v4.uint32 == net_htonl(0x7F000001);
    }
    if (net_family_is_ipv6(ip.family)) {
        const uint8_t *b = ip.ip.v6.uint8;
        for (int i = 0; i < 15; ++i) {
            if (b[i] != 0) {
                return false;
            }
        }
        return b[15] == 1;
    }
    return false;
}

void NetworkUniverse::process_events(uint64_t current_time_ms)
{
    while (true) {
        Packet p;
        std::vector<FakeTcpSocket *> tcp_targets;
        FakeUdpSocket *udp_target = nullptr;
        bool has_packet = false;

        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (!event_queue_.empty()) {
                const Packet &top = event_queue_.top();
                if (verbose_) {
                    std::cerr << "[NetworkUniverse] Peek packet: time=" << top.delivery_time
                              << " current=" << current_time_ms << " tcp=" << top.is_tcp
                              << std::endl;
                }
            }

            if (!event_queue_.empty() && event_queue_.top().delivery_time <= current_time_ms) {
                p = event_queue_.top();
                event_queue_.pop();
                has_packet = true;

                if (verbose_) {
                    Ip_Ntoa from_str, to_str;
                    net_ip_ntoa(&p.from.ip, &from_str);
                    net_ip_ntoa(&p.to.ip, &to_str);
                    std::cerr << "[NetworkUniverse] Processing packet #" << p.sequence_number
                              << " from " << from_str.buf << ":" << net_ntohs(p.from.port) << " to "
                              << to_str.buf << ":" << net_ntohs(p.to.port)
                              << " (TCP=" << (p.is_tcp ? "true" : "false");
                    if (p.is_tcp) {
                        std::cerr << " Flags=" << TcpFlags{p.tcp_flags} << " Seq=" << p.seq
                                  << " Ack=" << p.ack;
                    }
                    std::cerr << " Size=" << p.data.size() << ")" << std::endl;
                }

                IP target_ip = p.to.ip;

                if (p.is_tcp) {
                    if (is_loopback(target_ip)
                        && tcp_bindings_.count({target_ip, net_ntohs(p.to.port)}) == 0) {
                        if (verbose_) {
                            std::cerr << "[NetworkUniverse] Loopback packet to "
                                      << static_cast<int>(target_ip.ip.v4.uint8[3])
                                      << " redirected to "
                                      << static_cast<int>(p.from.ip.ip.v4.uint8[3]) << std::endl;
                        }
                        target_ip = p.from.ip;
                    }

                    auto range = tcp_bindings_.equal_range({target_ip, net_ntohs(p.to.port)});
                    FakeTcpSocket *listen_match = nullptr;

                    for (auto it = range.first; it != range.second; ++it) {
                        FakeTcpSocket *s = it->second;
                        if (s->state() == FakeTcpSocket::LISTEN) {
                            listen_match = s;
                        } else {
                            const IP_Port &remote = s->remote_addr();
                            if (net_ntohs(p.from.port) == net_ntohs(remote.port)) {
                                if (ip_equal(&p.from.ip, &remote.ip)
                                    || (is_loopback(p.from.ip) && ip_equal(&remote.ip, &target_ip))
                                    || (is_loopback(remote.ip)
                                        && ip_equal(&p.from.ip, &target_ip))) {
                                    tcp_targets.push_back(s);
                                }
                            }
                        }
                    }

                    if (listen_match && (p.tcp_flags & 0x02)) {
                        tcp_targets.push_back(listen_match);
                    }

                    if (verbose_) {
                        std::cerr << "[NetworkUniverse] Routing TCP to "
                                  << static_cast<int>(target_ip.ip.v4.uint8[0]) << "."
                                  << static_cast<int>(target_ip.ip.v4.uint8[3]) << ":"
                                  << net_ntohs(p.to.port)
                                  << ". Targets found: " << tcp_targets.size() << std::endl;
                    }
                    if (tcp_targets.empty()) {
                        if (verbose_) {
                            std::cerr << "[NetworkUniverse] WARNING: No TCP targets for "
                                      << static_cast<int>(target_ip.ip.v4.uint8[0]) << "."
                                      << static_cast<int>(target_ip.ip.v4.uint8[3]) << ":"
                                      << net_ntohs(p.to.port) << std::endl;
                        }
                    }
                } else {
                    if (is_loopback(target_ip)
                        && udp_bindings_.count({target_ip, net_ntohs(p.to.port)}) == 0) {
                        target_ip = p.from.ip;
                    }

                    if (udp_bindings_.count({target_ip, net_ntohs(p.to.port)})) {
                        udp_target = udp_bindings_[{target_ip, net_ntohs(p.to.port)}];
                    } else if (is_ipv4_mapped(target_ip)) {
                        IP ip4 = extract_ipv4(target_ip);
                        if (udp_bindings_.count({ip4, net_ntohs(p.to.port)})) {
                            udp_target = udp_bindings_[{ip4, net_ntohs(p.to.port)}];
                        }
                    }
                }
            }
        }

        if (!has_packet) {
            break;
        }

        if (p.is_tcp) {
            for (auto *it : tcp_targets) {
                if (it->handle_packet(p)) {
                    break;
                }
            }
        } else {
            if (udp_target) {
                udp_target->push_packet(std::move(p.data), p.from);
            }
        }
    }
}

void NetworkUniverse::set_latency(uint64_t ms) { global_latency_ms_ = ms; }

void NetworkUniverse::set_verbose(bool verbose) { verbose_ = verbose; }

bool NetworkUniverse::is_verbose() const { return verbose_; }

void NetworkUniverse::add_filter(PacketFilter filter)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    filters_.push_back(std::move(filter));
}

void NetworkUniverse::add_observer(PacketSink sink)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    observers_.push_back(std::move(sink));
}

uint16_t NetworkUniverse::find_free_port(IP ip, uint16_t start)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (uint16_t port = start; port < 65535; ++port) {
        if (!udp_bindings_.count({ip, port}) && !tcp_bindings_.count({ip, port}))
            return port;
    }
    return 0;
}

}  // namespace tox::test
