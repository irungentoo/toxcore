/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "ev_test_util.hh"

#include <cstddef>

#include "net.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#endif

#ifdef _WIN32
int create_pair(Socket *rs, Socket *ws)
{
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(listener);
        return -1;
    }

    if (listen(listener, 1) != 0) {
        closesocket(listener);
        return -1;
    }

    socklen_t len = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &len) != 0) {
        closesocket(listener);
        return -1;
    }

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        closesocket(listener);
        return -1;
    }

    if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(client);
        closesocket(listener);
        return -1;
    }

    SOCKET server = accept(listener, nullptr, nullptr);
    if (server == INVALID_SOCKET) {
        closesocket(client);
        closesocket(listener);
        return -1;
    }

    closesocket(listener);

    *rs = net_socket_from_native((int)client);
    *ws = net_socket_from_native((int)server);
    return 0;
}

void close_socket(Socket s) { closesocket(net_socket_to_native(s)); }

void close_pair(Socket s1, Socket s2)
{
    closesocket(net_socket_to_native(s1));
    closesocket(net_socket_to_native(s2));
}

int write_socket(Socket s, const void *buf, std::size_t count)
{
    return send(net_socket_to_native(s), (const char *)buf, (int)count, 0);
}
#else
int create_pair(Socket *rs, Socket *ws)
{
    int pipefds[2];
    if (pipe(pipefds) != 0)
        return -1;
    *rs = net_socket_from_native(pipefds[0]);
    *ws = net_socket_from_native(pipefds[1]);
    return 0;
}

void close_socket(Socket s) { close(net_socket_to_native(s)); }

void close_pair(Socket s1, Socket s2)
{
    close(net_socket_to_native(s1));
    close(net_socket_to_native(s2));
}

int write_socket(Socket s, const void *buf, std::size_t count)
{
    return write(net_socket_to_native(s), buf, count);
}
#endif
