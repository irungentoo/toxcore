#define _GNU_SOURCE

#include "mallocfail.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

static int (*libc_ioctl)(int fd, unsigned long request, ...);
static int (*libc_bind)(int sockfd, const struct sockaddr *addr,
        socklen_t addrlen);
static int (*libc_getsockopt)(int sockfd, int level, int optname,
        void *optval, socklen_t *optlen);
static int (*libc_setsockopt)(int sockfd, int level, int optname,
        const void *optval, socklen_t optlen);
static ssize_t (*libc_recv)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*libc_recvfrom)(int sockfd, void *buf, size_t len, int flags,
        struct sockaddr *src_addr, socklen_t *addrlen);
static ssize_t (*libc_send)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t(*libc_sendto)(int sockfd, const void *buf, size_t len, int flags,
        const struct sockaddr *dest_addr, socklen_t addrlen);
static int (*libc_socket)(int domain, int type, int protocol);
static int (*libc_listen)(int sockfd, int backlog);

__attribute__((__constructor__))
static void init(void)
{
    libc_ioctl = dlsym(RTLD_NEXT, "ioctl");
    libc_bind = dlsym(RTLD_NEXT, "bind");
    libc_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    libc_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    libc_recv = dlsym(RTLD_NEXT, "recv");
    libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    libc_send = dlsym(RTLD_NEXT, "send");
    libc_sendto = dlsym(RTLD_NEXT, "sendto");
    libc_socket = dlsym(RTLD_NEXT, "socket");
    libc_listen = dlsym(RTLD_NEXT, "listen");
}

int ioctl(int fd, unsigned long request, ...)
{
    if (should_malloc_fail()) {
        errno = ENOMEM;
        return -1;
    }

    va_list ap;
    va_start(ap, request);
    const int ret = libc_ioctl(fd, SIOCGIFCONF, va_arg(ap, void *));
    va_end(ap);
    return ret;
}

int bind(int sockfd, const struct sockaddr *addr,
        socklen_t addrlen)
{
    // Unlike all others, if bind should fail once, it should fail always, because in toxcore we try
    // many ports before giving up. If this only fails once, we'll never reach the code path where
    // we give up.
    static int should_fail = -1;
    if (should_fail == -1) {
        should_fail = should_malloc_fail();
    }
    if (should_fail) {
        errno = ENOMEM;
        return -1;
    }
    return libc_bind(sockfd, addr, addrlen);
}

int getsockopt(int sockfd, int level, int optname,
        void *optval, socklen_t *optlen)
{
    if (should_malloc_fail()) {
        errno = ENOMEM;
        return -1;
    }
    return libc_getsockopt(sockfd, level, optname, optval, optlen);
}

int setsockopt(int sockfd, int level, int optname,
        const void *optval, socklen_t optlen)
{
    if (should_malloc_fail()) {
        errno = ENOMEM;
        return -1;
    }
    return libc_setsockopt(sockfd, level, optname, optval, optlen);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    if (should_malloc_fail()) {
        errno = ENOMEM;
        return -1;
    }
    return libc_recv(sockfd, buf, len, flags);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
        struct sockaddr *src_addr, socklen_t *addrlen)
{
    if (should_malloc_fail()) {
        errno = ENOMEM;
        return -1;
    }
    return libc_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    if (should_malloc_fail()) {
        errno = ENOMEM;
        return -1;
    }
    return libc_send(sockfd, buf, len, flags);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
        const struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (should_malloc_fail()) {
        errno = ENOMEM;
        return -1;
    }
    return libc_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

int socket(int domain, int type, int protocol)
{
    if (should_malloc_fail()) {
        errno = ENOMEM;
        return -1;
    }
    return libc_socket(domain, type, protocol);
}

int listen(int sockfd, int backlog)
{
    if (should_malloc_fail()) {
        errno = ENOMEM;
        return -1;
    }
    return libc_listen(sockfd, backlog);
}
