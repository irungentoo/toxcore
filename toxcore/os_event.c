/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "os_event.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <winternl.h>
#else
#include <unistd.h>
#endif /* WIN32 */

#ifdef EV_USE_EPOLL
#include <sys/epoll.h>
#elif defined(ESP_PLATFORM)
#include <sys/poll.h>
#elif !defined(_WIN32)
#include <poll.h>
#endif /* EV_USE_EPOLL */

#include "ccompat.h"
#include "logger.h"
#include "mem.h"

#ifdef _WIN32
// Using the undocumented AFD driver directly (IOCTL_AFD_POLL).
// This bypasses the 64-handle limit of WaitForMultipleEvents and the bugs of WSAPoll.
// It provides true Level-Triggered notifications similar to poll/epoll.

#define IOCTL_AFD_POLL 0x00012024

typedef struct AFD_Poll_Handle_Info {
    void *_Nullable handle;
    unsigned long events;
    uint32_t status;
} AFD_Poll_Handle_Info;

typedef struct AFD_Poll_Info {
    int64_t timeout;
    unsigned long number_of_handles;
    unsigned long exclusive;
    AFD_Poll_Handle_Info handles[1];
} AFD_Poll_Info;

typedef enum Afd_Poll {
    AFD_POLL_RECEIVE = 0x0001,
    AFD_POLL_RECEIVE_EXPEDITED = 0x0002,
    AFD_POLL_SEND = 0x0004,
    AFD_POLL_DISCONNECT = 0x0008,
    AFD_POLL_ABORT = 0x0010,
    AFD_POLL_LOCAL_CLOSE = 0x0020,
    AFD_POLL_ACCEPT = 0x0080,
    AFD_POLL_CONNECT_FAIL = 0x0100,
} Afd_Poll;
#endif /* _WIN32 */

typedef struct OS_Ev_Registration {
    Socket sock;
    Ev_Events events;
    void *_Nullable data;
} OS_Ev_Registration;

typedef struct OS_Ev {
    const Memory *_Nonnull mem;
    const Logger *_Nonnull log;
    OS_Ev_Registration **_Nonnull regs;
    uint32_t regs_count;
    uint32_t regs_capacity;

#ifdef EV_USE_EPOLL
    int epoll_fd;
    struct epoll_event *events;
    uint32_t events_capacity;
#elif defined(_WIN32)
    AFD_Poll_Handle_Info *h_events;
    uint32_t h_events_capacity;
    SOCKET helper_sock;
#else
    struct pollfd *pfds;
    uint32_t pfds_count;
#endif /* EV_USE_EPOLL */
} OS_Ev;

static OS_Ev_Registration *_Nullable os_ev_prepare_add(OS_Ev *_Nonnull os_ev, Socket sock, Ev_Events events,
        void *_Nullable data)
{
    for (uint32_t i = 0; i < os_ev->regs_count; ++i) {
        if (net_socket_to_native(os_ev->regs[i]->sock) == net_socket_to_native(sock)) {
            return nullptr;
        }
    }

    if (os_ev->regs_count == os_ev->regs_capacity) {
        const uint32_t new_capacity = os_ev->regs_capacity == 0 ? 8 : os_ev->regs_capacity * 2;
        OS_Ev_Registration **new_regs
            = (OS_Ev_Registration **)mem_vrealloc(os_ev->mem, os_ev->regs, new_capacity, sizeof(OS_Ev_Registration *));

        if (new_regs == nullptr) {
            return nullptr;
        }

        os_ev->regs = new_regs;
        os_ev->regs_capacity = new_capacity;

#ifdef _WIN32
        AFD_Poll_Handle_Info *new_afd = (AFD_Poll_Handle_Info *)mem_vrealloc(
                                            os_ev->mem, os_ev->h_events, new_capacity, sizeof(AFD_Poll_Handle_Info));
        if (new_afd == nullptr) {
            return nullptr;
        }
        os_ev->h_events = new_afd;
        os_ev->h_events_capacity = new_capacity;
#endif /* _WIN32 */
    }

    OS_Ev_Registration *reg = (OS_Ev_Registration *)mem_alloc(os_ev->mem, sizeof(OS_Ev_Registration));
    if (reg == nullptr) {
        return nullptr;
    }
    reg->sock = sock;
    reg->events = events;
    reg->data = data;
    os_ev->regs[os_ev->regs_count] = reg;

    return reg;
}

#ifdef EV_USE_EPOLL

static uint32_t events_to_epoll(Ev_Events events)
{
    uint32_t e = 0;

    if ((events & EV_READ) != 0) {
        e |= EPOLLIN;
    }

    if ((events & EV_WRITE) != 0) {
        e |= EPOLLOUT;
    }

    return e;
}

static Ev_Events epoll_to_events(uint32_t e)
{
    Ev_Events events = 0;

    if ((e & EPOLLIN) != 0) {
        events |= EV_READ;
    }

    if ((e & EPOLLOUT) != 0) {
        events |= EV_WRITE;
    }

    if ((e & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
        events |= EV_ERROR;
    }

    return events;
}

static bool os_ev_add(void *_Nonnull self, Socket sock, Ev_Events events, void *_Nullable data)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    OS_Ev_Registration *reg = os_ev_prepare_add(os_ev, sock, events, data);
    if (reg == nullptr) {
        return false;
    }

    struct epoll_event ep_ev;
    ep_ev.events = events_to_epoll(events);
    ep_ev.data.ptr = reg;

    if (epoll_ctl(os_ev->epoll_fd, EPOLL_CTL_ADD, net_socket_to_native(sock), &ep_ev) == -1) {
        Net_Strerror error_buf;
        LOGGER_ERROR(os_ev->log, "epoll_ctl(ADD) failed: %s", net_strerror(errno, &error_buf));
        mem_delete(os_ev->mem, reg);
        return false;
    }

    LOGGER_DEBUG(os_ev->log, "Added socket %d to epoll (events: %u)", net_socket_to_native(sock), events);

    ++os_ev->regs_count;
    return true;
}

static bool os_ev_mod(void *_Nonnull self, Socket sock, Ev_Events events, void *_Nullable data)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    for (uint32_t i = 0; i < os_ev->regs_count; ++i) {
        if (net_socket_to_native(os_ev->regs[i]->sock) == net_socket_to_native(sock)) {
            OS_Ev_Registration *reg = os_ev->regs[i];
            reg->events = events;
            reg->data = data;

            struct epoll_event ep_ev;
            ep_ev.events = events_to_epoll(events);
            ep_ev.data.ptr = reg;

            if (epoll_ctl(os_ev->epoll_fd, EPOLL_CTL_MOD, net_socket_to_native(sock), &ep_ev) == -1) {
                Net_Strerror error_buf;
                LOGGER_ERROR(os_ev->log, "epoll_ctl(MOD) failed: %s", net_strerror(errno, &error_buf));
                return false;
            }

            LOGGER_DEBUG(os_ev->log, "Modified socket %d in epoll (events: %u)", net_socket_to_native(sock), events);

            return true;
        }
    }

    return false;
}

static bool os_ev_del(void *_Nonnull self, Socket sock)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    for (uint32_t i = 0; i < os_ev->regs_count; ++i) {
        if (net_socket_to_native(os_ev->regs[i]->sock) == net_socket_to_native(sock)) {
            if (epoll_ctl(os_ev->epoll_fd, EPOLL_CTL_DEL, net_socket_to_native(sock), nullptr) == -1) {
                Net_Strerror error_buf;
                LOGGER_ERROR(os_ev->log, "epoll_ctl(DEL) failed: %s", net_strerror(errno, &error_buf));
            }

            LOGGER_DEBUG(os_ev->log, "Removed socket %d from epoll", net_socket_to_native(sock));

            mem_delete(os_ev->mem, os_ev->regs[i]);
            os_ev->regs[i] = os_ev->regs[os_ev->regs_count - 1];
            --os_ev->regs_count;
            return true;
        }
    }

    return false;
}

static int32_t os_ev_run(void *_Nonnull self, Ev_Result *_Nonnull results, uint32_t max_results, int32_t timeout_ms)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    if (os_ev->events_capacity < max_results) {
        struct epoll_event *new_events
            = (struct epoll_event *)mem_vrealloc(os_ev->mem, os_ev->events, max_results, sizeof(struct epoll_event));

        if (new_events == nullptr) {
            return -1;
        }

        os_ev->events = new_events;
        os_ev->events_capacity = max_results;
    }

    const int n = epoll_wait(os_ev->epoll_fd, os_ev->events, (int)max_results, (int)timeout_ms);

    if (n < 0) {
        if (errno == EINTR) {
            return 0;
        }

        Net_Strerror error_buf;
        LOGGER_ERROR(os_ev->log, "epoll_wait failed: %s", net_strerror(errno, &error_buf));
        return -1;
    }

    if (n == 0) {
        return 0;
    }

    uint32_t count = 0;

    for (int i = 0; i < n; ++i) {
        OS_Ev_Registration *reg = (OS_Ev_Registration *)os_ev->events[i].data.ptr;

        if (reg != nullptr) {
            results[count].sock = reg->sock;
            results[count].events = epoll_to_events(os_ev->events[i].events);
            results[count].data = reg->data;
            ++count;
        }
    }

    return (int32_t)count;
}

#elif defined(_WIN32)

static uint32_t events_to_afd(Ev_Events events)
{
    uint32_t e = AFD_POLL_ABORT | AFD_POLL_LOCAL_CLOSE | AFD_POLL_CONNECT_FAIL;  // Always monitor errors

    if (events & EV_READ) {
        e |= AFD_POLL_RECEIVE | AFD_POLL_RECEIVE_EXPEDITED | AFD_POLL_ACCEPT | AFD_POLL_DISCONNECT;
    }

    if (events & EV_WRITE) {
        e |= AFD_POLL_SEND;
    }

    return e;
}

static Ev_Events afd_to_events(uint32_t e)
{
    Ev_Events events = 0;

    if (e & (AFD_POLL_RECEIVE | AFD_POLL_RECEIVE_EXPEDITED | AFD_POLL_ACCEPT | AFD_POLL_DISCONNECT)) {
        events |= EV_READ;
    }

    if (e & AFD_POLL_SEND) {
        events |= EV_WRITE;
    }

    if (e & (AFD_POLL_ABORT | AFD_POLL_LOCAL_CLOSE | AFD_POLL_CONNECT_FAIL)) {
        events |= EV_ERROR;
    }

    return events;
}

static bool os_ev_add(void *_Nonnull self, Socket sock, Ev_Events events, void *_Nullable data)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    OS_Ev_Registration *reg = os_ev_prepare_add(os_ev, sock, events, data);
    if (reg == nullptr) {
        return false;
    }

    AFD_Poll_Handle_Info *afd_handles = os_ev->h_events;
    afd_handles[os_ev->regs_count].handle = (HANDLE)(uintptr_t)net_socket_to_native(sock);
    afd_handles[os_ev->regs_count].events = events_to_afd(events);
    afd_handles[os_ev->regs_count].status = 0;

    LOGGER_DEBUG(os_ev->log, "Added socket %d to AFD (events: %u)", net_socket_to_native(sock), events);

    ++os_ev->regs_count;

    return true;
}

static bool os_ev_mod(void *_Nonnull self, Socket sock, Ev_Events events, void *_Nullable data)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    for (uint32_t i = 0; i < os_ev->regs_count; ++i) {
        if (net_socket_to_native(os_ev->regs[i]->sock) == net_socket_to_native(sock)) {
            os_ev->regs[i]->events = events;
            os_ev->regs[i]->data = data;

            AFD_Poll_Handle_Info *afd_handles = os_ev->h_events;
            afd_handles[i].events = events_to_afd(events);
            afd_handles[i].status = 0;

            LOGGER_DEBUG(os_ev->log, "Modified socket %d in AFD (events: %u)", net_socket_to_native(sock), events);

            return true;
        }
    }

    return false;
}

static bool os_ev_del(void *_Nonnull self, Socket sock)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    for (uint32_t i = 0; i < os_ev->regs_count; ++i) {
        if (net_socket_to_native(os_ev->regs[i]->sock) == net_socket_to_native(sock)) {
            mem_delete(os_ev->mem, os_ev->regs[i]);
            os_ev->regs[i] = os_ev->regs[os_ev->regs_count - 1];

            AFD_Poll_Handle_Info *afd_handles = os_ev->h_events;
            afd_handles[i] = afd_handles[os_ev->regs_count - 1];

            --os_ev->regs_count;

            LOGGER_DEBUG(os_ev->log, "Removed socket %d from AFD", net_socket_to_native(sock));

            return true;
        }
    }

    return false;
}

static int32_t os_ev_run(void *_Nonnull self, Ev_Result *_Nonnull results, uint32_t max_results, int32_t timeout_ms)
{
    OS_Ev *os_ev = (OS_Ev *)self;
    if (os_ev->regs_count == 0) {
        if (timeout_ms > 0) {
            Sleep(timeout_ms);
        }
        return 0;
    }

    const size_t info_size = sizeof(AFD_Poll_Info) + (os_ev->regs_count - 1) * sizeof(AFD_Poll_Handle_Info);
    AFD_Poll_Info *info = (AFD_Poll_Info *)HeapAlloc(GetProcessHeap(), 0, info_size);
    if (info == nullptr) {
        return -1;
    }

    info->timeout = timeout_ms < 0 ? INT64_MAX : (int64_t)timeout_ms * -10000;
    info->number_of_handles = os_ev->regs_count;
    info->exclusive = 0;

    memcpy(info->handles, os_ev->h_events, os_ev->regs_count * sizeof(AFD_Poll_Handle_Info));

    DWORD bytes_ret = 0;

    if (!DeviceIoControl((HANDLE)os_ev->helper_sock, IOCTL_AFD_POLL, info, (DWORD)info_size, info, (DWORD)info_size,
                         &bytes_ret, NULL)) {
        const int err = net_error();
        HeapFree(GetProcessHeap(), 0, info);

        if (err == WAIT_TIMEOUT) {
            return 0;
        }

        Net_Strerror error_buf;
        LOGGER_ERROR(os_ev->log, "AFD_POLL failed: %s", net_strerror(err, &error_buf));
        return -1;
    }

    uint32_t count = 0;
    for (uint32_t i = 0; i < info->number_of_handles && count < max_results; ++i) {
        if (info->handles[i].events != 0) {
            results[count].sock = os_ev->regs[i]->sock;
            results[count].data = os_ev->regs[i]->data;
            results[count].events = afd_to_events(info->handles[i].events);
            ++count;
        }
    }

    HeapFree(GetProcessHeap(), 0, info);
    return (int32_t)count;
}

#else  // POLL

static bool os_ev_add(void *_Nonnull self, Socket sock, Ev_Events events, void *_Nullable data)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    OS_Ev_Registration *reg = os_ev_prepare_add(os_ev, sock, events, data);
    if (reg == nullptr) {
        return false;
    }

    LOGGER_DEBUG(os_ev->log, "Added socket %d to poll (events: %u)", net_socket_to_native(sock), events);

    ++os_ev->regs_count;

    return true;
}

static bool os_ev_mod(void *_Nonnull self, Socket sock, Ev_Events events, void *_Nullable data)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    for (uint32_t i = 0; i < os_ev->regs_count; ++i) {
        if (net_socket_to_native(os_ev->regs[i]->sock) == net_socket_to_native(sock)) {
            os_ev->regs[i]->events = events;
            os_ev->regs[i]->data = data;

            LOGGER_DEBUG(os_ev->log, "Modified socket %d in poll (events: %u)", net_socket_to_native(sock), events);

            return true;
        }
    }

    return false;
}

static bool os_ev_del(void *_Nonnull self, Socket sock)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    for (uint32_t i = 0; i < os_ev->regs_count; ++i) {
        if (net_socket_to_native(os_ev->regs[i]->sock) == net_socket_to_native(sock)) {
            mem_delete(os_ev->mem, os_ev->regs[i]);
            os_ev->regs[i] = os_ev->regs[os_ev->regs_count - 1];
            --os_ev->regs_count;

            LOGGER_DEBUG(os_ev->log, "Removed socket %d from poll", net_socket_to_native(sock));

            return true;
        }
    }

    return false;
}

static int32_t os_ev_run(void *_Nonnull self, Ev_Result *_Nonnull results, uint32_t max_results, int32_t timeout_ms)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    if (os_ev->pfds_count < os_ev->regs_count) {
        struct pollfd *new_pfds
            = (struct pollfd *)mem_vrealloc(os_ev->mem, os_ev->pfds, os_ev->regs_count, sizeof(struct pollfd));

        if (new_pfds == nullptr) {
            return -1;
        }

        os_ev->pfds = new_pfds;
        os_ev->pfds_count = os_ev->regs_count;
    }

    for (uint32_t i = 0; i < os_ev->regs_count; ++i) {
        os_ev->pfds[i].fd = net_socket_to_native(os_ev->regs[i]->sock);
        os_ev->pfds[i].events = 0;

        if ((os_ev->regs[i]->events & EV_READ) != 0) {
            os_ev->pfds[i].events |= POLLIN;
        }

        if ((os_ev->regs[i]->events & EV_WRITE) != 0) {
            os_ev->pfds[i].events |= POLLOUT;
        }

        os_ev->pfds[i].revents = 0;
    }

    const int n = poll(os_ev->pfds, (nfds_t)os_ev->regs_count, (int)timeout_ms);

    if (n < 0) {
        if (errno == EINTR) {
            return 0;
        }

        Net_Strerror error_buf;
        LOGGER_ERROR(os_ev->log, "poll failed: %s", net_strerror(errno, &error_buf));
        return -1;
    }

    if (n == 0) {
        return 0;
    }

    uint32_t count = 0;

    for (uint32_t i = 0; i < os_ev->regs_count && count < max_results; ++i) {
        if (os_ev->pfds[i].revents == 0) {
            continue;
        }

        results[count].sock = os_ev->regs[i]->sock;
        results[count].events = 0;
        results[count].data = os_ev->regs[i]->data;

        if ((os_ev->pfds[i].revents & POLLIN) != 0) {
            results[count].events |= EV_READ;
        }

        if ((os_ev->pfds[i].revents & POLLOUT) != 0) {
            results[count].events |= EV_WRITE;
        }

        if ((os_ev->pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            results[count].events |= EV_ERROR;
        }

        ++count;
    }

    return (int32_t)count;
}

#endif /* EV_USE_EPOLL */

static void os_ev_kill(Ev *_Nullable ev)
{
    if (ev == nullptr) {
        return;
    }

    OS_Ev *os_ev = (OS_Ev *)ev->user_data;
    const Memory *mem = os_ev->mem;

#ifdef EV_USE_EPOLL
    close(os_ev->epoll_fd);
    mem_delete(mem, os_ev->events);
#elif defined(_WIN32)
    closesocket(os_ev->helper_sock);
    mem_delete(mem, os_ev->h_events);
#else
    mem_delete(mem, os_ev->pfds);
#endif /* EV_USE_EPOLL */

    for (uint32_t i = 0; i < os_ev->regs_count; ++i) {
        mem_delete(mem, os_ev->regs[i]);
    }
    mem_delete(mem, os_ev->regs);
    mem_delete(mem, os_ev);
    mem_delete(mem, ev);
}

static const Ev_Funcs os_ev_funcs = {
    os_ev_add,
    os_ev_mod,
    os_ev_del,
    os_ev_run,
    os_ev_kill,
};

Ev *os_event_new(const Memory *mem, const Logger *log)
{
    OS_Ev *os_ev = (OS_Ev *)mem_alloc(mem, sizeof(OS_Ev));

    if (os_ev == nullptr) {
        return nullptr;
    }

    os_ev->mem = mem;
    os_ev->log = log;

#ifdef EV_USE_EPOLL
    os_ev->epoll_fd = epoll_create1(EPOLL_CLOEXEC);

    if (os_ev->epoll_fd == -1) {
        Net_Strerror error_buf;
        LOGGER_ERROR(log, "Failed to create epoll fd: %s", net_strerror(errno, &error_buf));
        mem_delete(mem, os_ev);
        return nullptr;
    }

#elif defined(_WIN32)
    // Create a dummy socket for AFD communication
    os_ev->helper_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (os_ev->helper_sock == INVALID_SOCKET) {
        Net_Strerror error_buf;
        LOGGER_ERROR(log, "Failed to create helper socket: %s", net_strerror(net_error(), &error_buf));
        mem_delete(mem, os_ev);
        return nullptr;
    }
#endif /* EV_USE_EPOLL */

    Ev *ev = (Ev *)mem_alloc(mem, sizeof(Ev));

    if (ev == nullptr) {
#ifdef EV_USE_EPOLL
        close(os_ev->epoll_fd);
#elif defined(_WIN32)
        closesocket(os_ev->helper_sock);
#endif /* EV_USE_EPOLL */
        mem_delete(mem, os_ev);
        return nullptr;
    }

    ev->funcs = &os_ev_funcs;
    ev->user_data = os_ev;

    LOGGER_DEBUG(log, "Created new os_event loop");

    return ev;
}
