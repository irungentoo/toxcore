#ifndef C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_NETWORK_STACK_H
#define C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_NETWORK_STACK_H

#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "../../../toxcore/net.h"
#include "../public/network.hh"
#include "fake_sockets.hh"
#include "network_universe.hh"

namespace tox::test {

class FakeNetworkStack : public NetworkSystem {
public:
    explicit FakeNetworkStack(NetworkUniverse &universe, const IP &node_ip);
    ~FakeNetworkStack() override;

    // NetworkSystem Implementation
    Socket socket(int domain, int type, int protocol) override;
    int bind(Socket sock, const IP_Port *_Nonnull addr) override;
    int close(Socket sock) override;
    int sendto(Socket sock, const uint8_t *_Nonnull buf, std::size_t len,
        const IP_Port *_Nonnull addr) override;
    int recvfrom(
        Socket sock, uint8_t *_Nonnull buf, std::size_t len, IP_Port *_Nonnull addr) override;

    int listen(Socket sock, int backlog) override;
    Socket accept(Socket sock) override;
    int connect(Socket sock, const IP_Port *_Nonnull addr) override;
    int send(Socket sock, const uint8_t *_Nonnull buf, std::size_t len) override;
    int recv(Socket sock, uint8_t *_Nonnull buf, std::size_t len) override;
    int recvbuf(Socket sock) override;

    int socket_nonblock(Socket sock, bool nonblock) override;
    int getsockopt(Socket sock, int level, int optname, void *_Nonnull optval,
        std::size_t *_Nonnull optlen) override;
    int setsockopt(Socket sock, int level, int optname, const void *_Nonnull optval,
        std::size_t optlen) override;

    /**
     * @brief Returns C-compatible Network struct.
     */
    struct Network c_network() override;

    // For testing/fuzzing introspection
    FakeSocket *_Nullable get_sock(Socket sock);
    FakeUdpSocket *_Nullable get_udp_socket(Socket sock);
    std::vector<FakeUdpSocket *> get_bound_udp_sockets();

    NetworkUniverse &universe() { return universe_; }

private:
    NetworkUniverse &universe_;
    std::map<int, std::unique_ptr<FakeSocket>> sockets_;
    int next_fd_ = 100;
    IP node_ip_;
    std::mutex mutex_;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_NETWORK_STACK_H
