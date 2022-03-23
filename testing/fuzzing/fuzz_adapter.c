#include "fuzz_adapter.h"

struct fuzz_buf {
    /* Monotonic counter for time replacement */
    uint64_t counter;
    /* Fuzz data buffer */
    const uint8_t *cur;
    const uint8_t *end;
};

static struct fuzz_buf data;

#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>


void network_adapter_init(const uint8_t *buf, size_t length)
{
    data.counter = 0;
    data.cur = buf;
    data.end = buf + length;
}

ssize_t fuzz_sendto(int sockfd, const void *buf, size_t len,
                    int flags, const struct sockaddr *addr,
                    socklen_t addrlen)
{
    return len;
}

ssize_t fuzz_send(int sockfd, const void *buf, size_t len, int flags)
{
    return len;
}

static ssize_t recv_common(void *buf, size_t buf_len)
{
    if (data.cur + 2 >= data.end) {
        return -1;
    }

    uint16_t fuzz_len = (data.cur[0] << 8) | data.cur[1];
    data.cur += 2;

    size_t available = data.end - data.cur;

    size_t res = fuzz_len > available ? available : fuzz_len;
    res = buf_len > res ? res : buf_len;

    memcpy(buf, data.cur, res);
    data.cur += res;

    return res;
}

ssize_t fuzz_recvfrom(int sockfd, void *buf, size_t len,
                      int flags, struct sockaddr *src_addr,
                      socklen_t *addr_len)
{
    if (src_addr && addr_len && (sizeof(struct sockaddr) <= *addr_len)) {
        *src_addr  = (struct sockaddr) {
            0
        };
        // Dummy Addr
        src_addr->sa_family = AF_INET;

        // We want an AF_INET address with dummy values
        struct sockaddr_in *addr_in = (struct sockaddr_in *)(void *)src_addr;
        addr_in->sin_port = 12356;
        addr_in->sin_addr.s_addr = INADDR_LOOPBACK + 1;
        *addr_len = sizeof(struct sockaddr);
    }

    return recv_common(buf, len);
}

ssize_t fuzz_recv(int sockfd, void *buf, size_t len, int flags)
{
    return recv_common(buf, len);
}

void fuzz_random_bytes(uint8_t *rnd, size_t length)
{
    // Amount of data is limited
    size_t available = data.end - data.cur;
    size_t bytes_read = length > available ? available : length;
    // Initialize everything to make MSAN and others happy
    memset(rnd, 0, length);
    memcpy(rnd, data.cur, bytes_read);
    data.cur += bytes_read;
}

uint64_t fuzz_get_count(void)
{
    return data.counter++;
}
