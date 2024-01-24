#ifndef C_TOXCORE_TESTING_SUPPORT_NETWORK_H
#define C_TOXCORE_TESTING_SUPPORT_NETWORK_H

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <vector>

#include "../../../toxcore/attributes.h"
#include "../../../toxcore/net.h"
#include "../../../toxcore/network.h"
#include "../../../toxcore/rng.h"

namespace tox::test {

/**
 * @brief Abstraction over the network subsystem (sockets).
 */
class NetworkSystem {
public:
    virtual ~NetworkSystem();

    virtual Socket socket(int domain, int type, int protocol) = 0;
    virtual int bind(Socket sock, const IP_Port *_Nonnull addr) = 0;
    virtual int close(Socket sock) = 0;
    virtual int sendto(
        Socket sock, const uint8_t *_Nonnull buf, std::size_t len, const IP_Port *_Nonnull addr)
        = 0;
    virtual int recvfrom(
        Socket sock, uint8_t *_Nonnull buf, std::size_t len, IP_Port *_Nonnull addr)
        = 0;

    // TCP Support
    virtual int listen(Socket sock, int backlog) = 0;
    virtual Socket accept(Socket sock) = 0;
    virtual int connect(Socket sock, const IP_Port *_Nonnull addr) = 0;
    virtual int send(Socket sock, const uint8_t *_Nonnull buf, std::size_t len) = 0;
    virtual int recv(Socket sock, uint8_t *_Nonnull buf, std::size_t len) = 0;
    virtual int recvbuf(Socket sock) = 0;

    // Auxiliary
    virtual int socket_nonblock(Socket sock, bool nonblock) = 0;
    virtual int getsockopt(
        Socket sock, int level, int optname, void *_Nonnull optval, std::size_t *_Nonnull optlen)
        = 0;
    virtual int setsockopt(
        Socket sock, int level, int optname, const void *_Nonnull optval, std::size_t optlen)
        = 0;

    /**
     * @brief Returns C-compatible Network struct.
     */
    virtual struct Network c_network() = 0;
};

/**
 * @brief Helper to create an IPv4 IP struct from a host-byte-order address.
 */
IP make_ip(uint32_t ipv4);

/**
 * @brief Helper to create a unique node IP in the 10.x.y.z range.
 */
IP make_node_ip(uint32_t node_id);

IP_Port random_ip_port(const Random *_Nonnull rng);

class increasing_ip_port {
    std::uint8_t start_;
    const Random *_Nonnull rng_;

public:
    explicit increasing_ip_port(std::uint8_t start, const Random *_Nonnull rng)
        : start_(start)
        , rng_(rng)
    {
    }

    IP_Port operator()();
};

}  // namespace tox::test

bool operator==(Family a, Family b);
bool operator==(IP4 a, IP4 b);
bool operator==(IP6 a, IP6 b);
bool operator==(IP const &a, IP const &b);
bool operator==(IP_Port const &a, IP_Port const &b);

std::ostream &operator<<(std::ostream &out, IP const &v);
std::ostream &operator<<(std::ostream &out, IP_Port const &v);

#endif  // C_TOXCORE_TESTING_SUPPORT_NETWORK_H
