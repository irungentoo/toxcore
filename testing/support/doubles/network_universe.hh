#ifndef C_TOXCORE_TESTING_SUPPORT_DOUBLES_NETWORK_UNIVERSE_H
#define C_TOXCORE_TESTING_SUPPORT_DOUBLES_NETWORK_UNIVERSE_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <vector>

#include "../../../toxcore/attributes.h"
#include "../../../toxcore/network.h"

namespace tox::test {

class FakeUdpSocket;
class FakeTcpSocket;

struct TcpFlags {
    uint8_t value;
};
std::ostream &operator<<(std::ostream &os, TcpFlags flags);

struct Packet {
    IP_Port from;
    IP_Port to;
    std::vector<uint8_t> data;
    uint64_t delivery_time;
    uint64_t sequence_number = 0;
    bool is_tcp = false;

    // TCP Simulation Fields
    uint8_t tcp_flags = 0;  // 0x01=FIN, 0x02=SYN, 0x10=ACK
    uint32_t seq = 0;
    uint32_t ack = 0;

    bool operator>(const Packet &other) const
    {
        if (delivery_time != other.delivery_time) {
            return delivery_time > other.delivery_time;
        }
        return sequence_number > other.sequence_number;
    }
};

bool is_loopback(const IP &ip);

/**
 * @brief The God Object for the network simulation.
 * Manages routing, latency, and connectivity.
 */
class NetworkUniverse {
public:
    using PacketFilter = std::function<bool(Packet &)>;
    using PacketSink = std::function<void(const Packet &)>;

    NetworkUniverse();
    ~NetworkUniverse();

    // Registration
    // Returns true if binding succeeded
    bool bind_udp(IP ip, uint16_t port, FakeUdpSocket *_Nonnull socket);
    void unbind_udp(IP ip, uint16_t port);

    bool bind_tcp(IP ip, uint16_t port, FakeTcpSocket *_Nonnull socket);
    void unbind_tcp(IP ip, uint16_t port, FakeTcpSocket *_Nonnull socket);

    // Routing
    void send_packet(Packet p);

    // Simulation
    void process_events(uint64_t current_time_ms);
    void set_latency(uint64_t ms);
    void set_verbose(bool verbose);
    bool is_verbose() const;
    void add_filter(PacketFilter filter);
    void add_observer(PacketSink sink);

    // Helpers
    // Finds a free port starting from 'start'
    uint16_t find_free_port(IP ip, uint16_t start = 33445);

    struct IP_Port_Key {
        IP ip;
        uint16_t port;
        bool operator<(const IP_Port_Key &other) const;
    };

private:
    std::map<IP_Port_Key, FakeUdpSocket *> udp_bindings_;
    std::multimap<IP_Port_Key, FakeTcpSocket *> tcp_bindings_;

    std::priority_queue<Packet, std::vector<Packet>, std::greater<Packet>> event_queue_;
    std::vector<PacketFilter> filters_;
    std::vector<PacketSink> observers_;

    uint64_t global_latency_ms_ = 0;
    uint64_t next_packet_id_ = 0;
    bool verbose_ = false;
    std::recursive_mutex mutex_;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_DOUBLES_NETWORK_UNIVERSE_H
