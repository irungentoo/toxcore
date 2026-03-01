#ifndef C_TOXCORE_TESTING_SUPPORT_NETWORK_H
#define C_TOXCORE_TESTING_SUPPORT_NETWORK_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "../../../toxcore/attributes.h"
#include "../../../toxcore/net.h"
#include "../../../toxcore/network.h"

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

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_NETWORK_H
