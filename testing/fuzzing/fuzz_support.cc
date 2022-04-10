/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2021-2022 The TokTok team.
 */

#include "fuzz_support.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstring>
#include <memory>

#include "../../toxcore/crypto_core.h"
#include "../../toxcore/network.h"
#include "../../toxcore/tox_private.h"
#include "func_conversion.h"

// TODO(iphydf): Put this somewhere shared.
struct Network_Addr {
    struct sockaddr_storage addr;
    size_t size;
};

static int recv_common(Fuzz_Data &input, void *buf, size_t buf_len)
{
    if (input.size < 2) {
        return -1;
    }

    const size_t fuzz_len = (input.data[0] << 8) | input.data[1];
    input.data += 2;
    input.size -= 2;

    const size_t res = std::min(buf_len, std::min(fuzz_len, input.size));

    memcpy(buf, input.data, res);
    input.data += res;
    input.size -= res;

    return res;
}

static constexpr Network_Funcs fuzz_network_funcs = {
    /* .close = */ [](void *obj, int sock) { return 0; },
    /* .accept = */ [](void *obj, int sock) { return 2; },
    /* .bind = */ [](void *obj, int sock, const Network_Addr *addr) { return 0; },
    /* .listen = */ [](void *obj, int sock, int backlog) { return 0; },
    /* .recvbuf = */
    ![](Fuzz_System *self, int sock) {
        const size_t count = random_u16(self->rng.get());
        return static_cast<int>(std::min(count, self->data.size));
    },
    /* .recv = */
    ![](Fuzz_System *self, int sock, uint8_t *buf, size_t len) {
        // Receive data from the fuzzer.
        return recv_common(self->data, buf, len);
    },
    /* .recvfrom = */
    ![](Fuzz_System *self, int sock, uint8_t *buf, size_t len, Network_Addr *addr) {
        addr->addr = sockaddr_storage{};
        // Dummy Addr
        addr->addr.ss_family = AF_INET;

        // We want an AF_INET address with dummy values
        sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(&addr->addr);
        addr_in->sin_port = 12356;
        addr_in->sin_addr.s_addr = INADDR_LOOPBACK + 1;
        addr->size = sizeof(struct sockaddr);

        return recv_common(self->data, buf, len);
    },
    /* .send = */
    [](void *obj, int sock, const uint8_t *buf, size_t len) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .sendto = */
    [](void *obj, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .socket = */ [](void *obj, int domain, int type, int proto) { return 1; },
    /* .socket_nonblock = */ [](void *obj, int sock, bool nonblock) { return 0; },
    /* .getsockopt = */
    [](void *obj, int sock, int level, int optname, void *optval, size_t *optlen) {
        memset(optval, 0, *optlen);
        return 0;
    },
    /* .setsockopt = */
    [](void *obj, int sock, int level, int optname, const void *optval, size_t optlen) {
        return 0;
    },
};

static constexpr Random_Funcs fuzz_random_funcs = {
    /* .random_bytes = */
    ![](Fuzz_System *self, uint8_t *bytes, size_t length) {
        // Amount of data is limited
        const size_t bytes_read = std::min(length, self->data.size);
        // Initialize everything to make MSAN and others happy
        std::memset(bytes, 0, length);
        std::memcpy(bytes, self->data.data, bytes_read);
        self->data.data += bytes_read;
        self->data.size -= bytes_read;
    },
    /* .random_uniform = */
    ![](Fuzz_System *self, uint32_t upper_bound) {
        uint32_t randnum = 0;
        if (upper_bound > 0) {
            self->rng->funcs->random_bytes(
                self, reinterpret_cast<uint8_t *>(&randnum), sizeof(randnum));
            randnum %= upper_bound;
        }
        return randnum;
    },
};

Fuzz_System::Fuzz_System(Fuzz_Data &input)
    : clock(0)
    , data(input)
    , sys(std::make_unique<Tox_System>())
    , ns(std::make_unique<Network>(Network{&fuzz_network_funcs, this}))
    , rng(std::make_unique<Random>(Random{&fuzz_random_funcs, this}))
{
    sys->mono_time_callback = ![](Fuzz_System *self) { return self->clock; };
    sys->mono_time_user_data = this;
    sys->ns = ns.get();
    sys->rng = rng.get();
}

Fuzz_System::~Fuzz_System() { }
